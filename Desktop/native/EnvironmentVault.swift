import Cocoa

struct EnvironmentCredential: Codable {
    let id: String
    let name: String
    let env_name: String
    let secret: String

    func validate() throws {
        let blocked: Set<String> = [
            "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "OLDPWD", "TMPDIR", "TMP", "TEMP",
            "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "IFS", "CDPATH", "GLOBIGNORE",
            "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "NODE_OPTIONS",
            "RUBYOPT", "PERL5OPT", "PERL5LIB", "ZDOTDIR", "PROMPT_COMMAND", "PS4", "CODEX_HOME",
            "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_SSH", "GIT_SSH_COMMAND",
            "GIT_ASKPASS", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE",
        ]
        let upper = env_name.uppercased()
        guard id.utf8.count == 32,
              id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              !name.isEmpty, name.count <= 80,
              env_name.range(of: "^[A-Za-z_][A-Za-z0-9_]{0,63}$", options: .regularExpression) != nil,
              !blocked.contains(upper),
              !["LD_", "DYLD_", "BASH_FUNC_", "GIT_CONFIG_", "ADR_"].contains(where: upper.hasPrefix),
              !secret.isEmpty, secret.utf8.count <= 16384, !secret.contains("\0"),
              secret != env_name, secret != name else {
            throw ADRNativeError.rejected("invalid_environment_credential")
        }
    }
}

// Multiline values are pasted only into the native process. No browser field,
// clipboard polling, file import, or raw-secret IPC endpoint is involved.
@MainActor final class EnvironmentSecretInput: NSView {
    let field = NSSecureTextField(frame: NSRect(x: 0, y: 52, width: 430, height: 28))
    private let status = NSTextField(labelWithString: "")
    private var multiline: String?
    override init(frame: NSRect) {
        super.init(frame: frame)
        field.placeholderString = "Password, token, or key"
        field.setAccessibilityLabel("Credential value")
        addSubview(field)
        let paste = NSButton(title: "Paste multiline value", target: self, action: #selector(pasteMultiline))
        paste.frame = NSRect(x: 0, y: 12, width: 170, height: 28)
        paste.bezelStyle = .rounded; addSubview(paste)
        status.frame = NSRect(x: 180, y: 16, width: 250, height: 20)
        status.font = NSFont.systemFont(ofSize: 11); addSubview(status)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
    @objc private func pasteMultiline() {
        guard let text = NSPasteboard.general.string(forType: .string),
              !text.isEmpty, text.utf8.count <= 16384, !text.contains("\0") else {
            status.stringValue = "Paste a text value up to 16 KiB."; return
        }
        multiline = text
        field.stringValue = ""; field.isEnabled = false
        status.stringValue = "Value ready (\(text.count) characters)"
    }
    var value: String { multiline ?? field.stringValue }
    func clear() { multiline = nil; field.stringValue = "" }
}

extension Vault {
    func storeEnvironment(_ profile: EnvironmentCredential) throws {
        try profile.validate()
        try storeData(id: profile.id, data: JSONEncoder().encode(profile))
    }

    func loadEnvironment(_ id: String) throws -> EnvironmentCredential {
        let data = try credentialData(id)
        do {
            let profile = try JSONDecoder().decode(EnvironmentCredential.self, from: data)
            guard profile.id == id else { throw LocalVaultFailure.corrupt }
            try profile.validate()
            return profile
        } catch { throw ADRNativeError.rejected("local_vault_corrupt") }
    }

    @MainActor func promptEnvironment(arguments: [String: Any]) throws -> [String: Any] {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Save \(arguments["name"] as? String ?? "credential")"
        alert.informativeText = """
        Agents connected through the ADR plugin can use $\(arguments["env_name"] as? String ?? "VARIABLE") automatically in local commands.

        Paste the value here, not into the agent chat. ADR stores it in this profile's encrypted local vault and supplies it to local programs when needed. No Keychain unlock is required. For JSON or a multiline key, use “Paste multiline value”.

        The decryption key is stored locally too. This does not protect against other programs running as you.
        """
        alert.addButton(withTitle: "Save to local vault"); alert.addButton(withTitle: "Cancel")
        let input = EnvironmentSecretInput(frame: NSRect(x: 0, y: 0, width: 430, height: 90))
        alert.accessoryView = input
        alert.window.initialFirstResponder = input.field
        let deadline = Date().addingTimeInterval(110)
        DispatchQueue.main.asyncAfter(deadline: .now() + 110) { [weak alert] in
            if alert?.window.isVisible == true { NSApp.abortModal() }
        }
        defer { input.clear() }
        guard alert.runModal() == .alertFirstButtonReturn else { throw ADRNativeError.rejected("cancelled") }
        guard Date() < deadline else { throw ADRNativeError.rejected("request_expired") }
        let profile = EnvironmentCredential(
            id: arguments["id"] as? String ?? "", name: arguments["name"] as? String ?? "",
            env_name: arguments["env_name"] as? String ?? "", secret: input.value
        )
        try storeEnvironment(profile)
        return ["id": profile.id, "stored": true, "storage": "local_encrypted", "storage_state": "available"]
    }

    func executeEnvironment(arguments: [String: Any], expectedEpoch: UInt64? = nil) throws -> [String: Any] {
        guard let ids = arguments["ids"] as? [String], (1...64).contains(ids.count),
              Set(ids).count == ids.count,
              let command = arguments["command"] as? String, !command.isEmpty,
              command.utf8.count <= 16384, !command.contains("\0"),
              let cwd = arguments["cwd"] as? String, cwd.hasPrefix("/"), !cwd.contains("\0"),
              let seconds = arguments["timeout_seconds"] as? Int, (1...60).contains(seconds) else {
            throw ADRNativeError.rejected("invalid_environment_command")
        }
        do { try ids.forEach(LocalVault.validateID) }
        catch { throw ADRNativeError.rejected("invalid_environment_command") }

        // Older direct native/synthetic callers may omit these fields: protect
        // the selected environment entries, and no additional service entries.
        // A present null, mixed-type array, duplicate or invalid ID is NOT an
        // omitted field. Validate *every* array before loading or spawning.
        func protectionIDs(_ key: String, default fallback: [String]) throws -> [String] {
            guard let value = arguments[key] else { return fallback }
            guard let values = value as? [String], values.count <= 64, Set(values).count == values.count else {
                throw ADRNativeError.rejected("invalid_environment_protection")
            }
            do { try values.forEach(LocalVault.validateID) }
            catch { throw ADRNativeError.rejected("invalid_environment_protection") }
            return values
        }
        let environmentIDs = try protectionIDs("protection_environment_ids", default: ids)
        let serviceIDs = try protectionIDs("protection_service_ids", default: [])
        guard Set(ids + environmentIDs).isDisjoint(with: serviceIDs) else {
            throw ADRNativeError.rejected("invalid_environment_protection")
        }
        let profiles = try ids.map(loadEnvironment)
        guard Set(profiles.map(\.env_name)).count == profiles.count,
              profiles.reduce(0, { $0 + $1.secret.utf8.count + $1.env_name.utf8.count + 2 }) <= 128 * 1024,
              !profiles.contains(where: {
                  VaultProcess.containsCredential(command, secret: $0.secret, aliases: profiles.map(\.env_name))
              }) else {
            throw ADRNativeError.rejected("use_credential_reference")
        }
        var outputVariants = Set<String>()
        let selected = Set(ids)
        for id in environmentIDs where !selected.contains(id) {
            outputVariants.formUnion(VaultProcess.variants(try loadEnvironment(id).secret))
        }
        for id in serviceIDs {
            outputVariants.formUnion(try loadService(id).outputProtectionVariants)
        }
        return try VaultProcess.run(
            command: command, cwd: cwd, credentials: profiles, timeout: TimeInterval(seconds),
            expectedEpoch: expectedEpoch, protectionVariants: outputVariants
        )
    }

    func environmentSelfTest() throws {
        let value = "synthetic-credential-never-used-on-network"
        let profile = EnvironmentCredential(
            id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            name: "Synthetic environment", env_name: "SYNTHETIC_PASSWORD", secret: value
        )
        try storeEnvironment(profile)
        defer { try? remove(profile.id) }
        let check = try checkText("A pasted value: " + value, environmentIDs: [profile.id], serviceIDs: [])
        guard check["matched"] as? Bool == true else { throw ADRNativeError.rejected("environment_match_test") }
        let history = try checkText(
            "{\"tool_result\":\"\(value)\"}", environmentIDs: [profile.id], serviceIDs: [],
            protectOutput: true
        )
        guard history["matched"] as? Bool == true else { throw ADRNativeError.rejected("history_match_test") }
        let shortProfile = EnvironmentCredential(
            id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            name: "Synthetic short", env_name: "SYNTHETIC_SHORT", secret: "zq!"
        )
        try storeEnvironment(shortProfile)
        defer { try? remove(shortProfile.id) }
        let shortOutput = try checkText(
            "{\"tool_result\":\"zq!\"}", environmentIDs: [shortProfile.id], serviceIDs: [],
            protectOutput: true
        )
        guard shortOutput["matched"] as? Bool == true else {
            throw ADRNativeError.rejected("short_output_match_test")
        }
        guard !VaultProcess.containsCredential("printf ready; use $MY_PASSWORD", secret: "in", aliases: ["MY_PASSWORD"]),
              VaultProcess.containsCredential("password is in", secret: "in", aliases: ["MY_PASSWORD"]),
              !VaultProcess.containsCredential("Use $MY_PASSWORD", secret: "PASSWORD", aliases: ["MY_PASSWORD"]) else {
            throw ADRNativeError.rejected("environment_reference_test")
        }
        let result = try executeEnvironment(arguments: [
            "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 3,
            "command": "printf '%s' \"$SYNTHETIC_PASSWORD\"; printf '%s' \"$SYNTHETIC_PASSWORD\" >&2",
        ])
        guard result["stdout"] as? String == "[ADR credential hidden]",
              result["stderr"] as? String == "[ADR credential hidden]",
              result["exit_code"] as? Int == 0 else { throw ADRNativeError.rejected("environment_output_test") }
        let child = try executeEnvironment(arguments: [
            "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 3,
            "command": "/bin/sh -c 'test -n \"$SYNTHETIC_PASSWORD\" && printf child-inherited'",
        ])
        guard child["stdout"] as? String == "child-inherited" else {
            throw ADRNativeError.rejected("environment_child_test")
        }
        let timed = try executeEnvironment(arguments: [
            "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 1,
            "command": "sleep 10",
        ])
        guard timed["timed_out"] as? Bool == true else {
            throw ADRNativeError.rejected("environment_timeout_test")
        }
        let oversized = try executeEnvironment(arguments: [
            "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 3,
            "command": "/usr/bin/yes x | /usr/bin/head -c 70000",
        ])
        guard oversized["output_withheld"] as? Bool == true,
              oversized["stdout"] as? String == "" else {
            throw ADRNativeError.rejected("environment_size_test")
        }
        let encoded = try executeEnvironment(arguments: [
            "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 3,
            "command": "printf '%s' \"$SYNTHETIC_PASSWORD\" | /usr/bin/base64",
        ])
        guard let encodedOutput = encoded["stdout"] as? String,
              !encodedOutput.contains(Data(value.utf8).base64EncodedString()) else {
            throw ADRNativeError.rejected("environment_encoding_test")
        }
        let oldEpoch = VaultProcess.epoch()
        VaultProcess.cancelAll()
        do {
            _ = try executeEnvironment(arguments: [
                "ids": [profile.id], "cwd": NSTemporaryDirectory(), "timeout_seconds": 1,
                "command": "printf must-not-run",
            ], expectedEpoch: oldEpoch)
            throw ADRNativeError.rejected("environment_cancel_test")
        } catch ADRNativeError.rejected("execution_cancelled") {}
    }
}
