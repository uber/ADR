import Cocoa
import Security

struct CredentialProfile: Codable {
    let id: String
    let name: String
    let origin: String
    let auth_type: String
    let header_name: String
    let username: String
    let allowed_paths: [String]
    let secret: String

    func validate() throws {
        guard id.utf8.count == 32,
              id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              !name.isEmpty, name.count <= 80, !secret.isEmpty, secret.utf8.count <= 16384,
              !secret.contains("\0"), ["bearer", "api_key", "basic"].contains(auth_type),
              (1...32).contains(allowed_paths.count) else { throw ADRNativeError.rejected("invalid_credential") }
        _ = try ServiceBoundary.origin(origin)
        for path in allowed_paths {
            guard !path.contains("?") else { throw ADRNativeError.rejected("invalid_path_scope") }
            _ = try ServiceBoundary.target(path, allowed: ["/"])
        }
        let blocked = Set([
            "host", "cookie", "content-length", "transfer-encoding", "connection",
            "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer",
            "accept", "accept-encoding", "user-agent", "expect",
        ])
        guard header_name.range(of: "^[A-Za-z][A-Za-z0-9-]{0,63}$", options: .regularExpression) != nil,
              !blocked.contains(header_name.lowercased()) else { throw ADRNativeError.rejected("invalid_header") }
        if auth_type != "basic", secret.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) {
            throw ADRNativeError.rejected("invalid_credential")
        }
        if auth_type == "basic", username.isEmpty || username.contains(":")
            || username.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) {
            throw ADRNativeError.rejected("invalid_username")
        }
    }

    var authorization: String {
        if auth_type == "basic" { return "Basic " + Data("\(username):\(secret)".utf8).base64EncodedString() }
        if auth_type == "bearer" { return "Bearer \(secret)" }
        return secret
    }

    /// Native-only protection context, never an injection permission or an IPC
    /// value. Basic auth encodes username:password, not just the saved password.
    var outputProtectionVariants: Set<String> {
        var result = VaultProcess.variants(secret)
        result.formUnion(VaultProcess.variants(authorization))
        if auth_type == "basic" {
            result.formUnion(VaultProcess.variants("\(username):\(secret)"))
        }
        return result
    }

    func safeResult(_ packet: HTTPPacket, protectionVariants: Set<String> = []) throws -> [String: Any] {
        guard let text = String(data: packet.body, encoding: .utf8) else {
            throw ADRNativeError.rejected("non_text_response")
        }
        let variants = outputProtectionVariants.union(protectionVariants).filter { !$0.isEmpty }
        func reflected(_ value: Any, depth: Int = 0) -> Bool {
            if depth > 64 { return true }
            if let string = value as? String { return variants.contains { string.contains($0) } }
            if let values = value as? [Any] { return values.contains { reflected($0, depth: depth + 1) } }
            if let values = value as? [String: Any] {
                return values.contains { reflected($0.key, depth: depth + 1) || reflected($0.value, depth: depth + 1) }
            }
            return false
        }
        let parsed = (try? JSONSerialization.jsonObject(with: packet.body, options: [.fragmentsAllowed])) ?? text
        guard !reflected(text), !reflected(parsed),
              !reflected(packet.headers["content-type"] ?? "") else {
            throw ADRNativeError.rejected("credential_echo_blocked")
        }
        return [
            "status": packet.status, "content_type": packet.headers["content-type"] ?? "text/plain",
            "body": parsed,
        ]
    }
}

/// Deliberately read-only. Migration cannot update or delete legacy originals.
/// Tests inject synthetic data; no test needs a real or temporary Keychain.
protocol LegacyCredentialSource: Sendable {
    func read(id: String) throws -> Data
}

struct KeychainLegacyCredentialSource: LegacyCredentialSource {
    func read(id: String) throws -> Data {
        do { try LocalVault.validateID(id) }
        catch { throw ADRNativeError.rejected("invalid_credential_id") }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "org.adr.desktop.credentials",
            kSecAttrAccount as String: id,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        // This is the only Keychain operation, called ONLY by explicit migration.
        // macOS may ask for one-time access here; routine usage never asks.
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw ADRNativeError.rejected("legacy_keychain_missing") }
        if status == errSecUserCanceled { throw ADRNativeError.rejected("legacy_keychain_cancelled") }
        if status == errSecInteractionNotAllowed { throw ADRNativeError.rejected("legacy_keychain_locked") }
        guard status == errSecSuccess, let data = result as? Data else {
            throw ADRNativeError.rejected("legacy_keychain_unavailable")
        }
        guard !data.isEmpty, data.count <= LocalVault.maximumPlaintextBytes else {
            throw ADRNativeError.rejected("legacy_credential_invalid")
        }
        return data
    }
}

/// Wall-clock expiry is supplied by the core. Monotonic time also caps lifetime
/// if the wall clock moves backwards.
private struct VaultMigrationTime: Sendable {
    let wall: TimeInterval
    let uptime: TimeInterval

    static var now: VaultMigrationTime {
        VaultMigrationTime(wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime)
    }
}

struct VaultMigrationIdentity: Sendable {
    fileprivate let token: UUID
}

private enum VaultMigrationFailure: String, Error {
    case invalidExpiry = "invalid_vault_migration_expiry"
    case busy = "vault_migration_busy"
    case expired = "vault_migration_expired"
    case cancelled = "vault_migration_cancelled"
    case invalidated = "vault_migration_invalidated"
}

// Immutable storage handles; LocalVault serializes short filesystem operations.
// The separate migration lock protects only in-memory identity/lifetime state.
// It is NEVER held around a legacy read, filesystem wait, or filesystem I/O.
final class Vault: @unchecked Sendable {
    private let local: LocalVault
    private let legacy: any LegacyCredentialSource
    private let migrationLock = NSLock()
    private struct PendingMigration {
        let identity: VaultMigrationIdentity
        let ids: [String]
        let deadline: VaultMigrationTime
        var running = false
        var cancelled = false
        var invalidatedIDs: Set<String> = []
    }
    private var pendingMigration: PendingMigration?
    private var migrationGeneration = UUID()
    private var deletingIDs: [String: Int] = [:]
    // IDs are never reused by normal core creation. Retain deletion tombstones
    // for this host lifetime so an old value dialog cannot publish after removal.
    private var removedIDs: Set<String> = []

    init(
        profileDirectory: URL? = LocalVault.defaultProfileDirectory,
        legacySource: any LegacyCredentialSource = KeychainLegacyCredentialSource()
    ) {
        local = LocalVault(profileDirectory: profileDirectory)
        legacy = legacySource
    }

    func store(_ profile: CredentialProfile) throws {
        try profile.validate()
        try storeData(id: profile.id, data: JSONEncoder().encode(profile))
    }

    func storeData(id: String, data: Data) throws {
        guard credentialKind(data, id: id) != nil else {
            throw ADRNativeError.rejected("invalid_credential")
        }
        do {
            try nativeStorage {
                try local.save(id: id, data: data) {
                    self.migrationLock.lock(); defer { self.migrationLock.unlock() }
                    guard !self.removedIDs.contains(id) else {
                        throw LocalVaultFailure.removed
                    }
                }
            }
        } catch ADRNativeError.rejected("local_vault_exists") {
            _ = try credentialData(id) // Also authenticate the stored schema.
            throw ADRNativeError.rejected("local_vault_exists")
        }
    }

    /// Native-only validated service profile; never expose it through IPC.
    func loadService(_ id: String) throws -> CredentialProfile {
        let data = try credentialData(id)
        do {
            let profile = try JSONDecoder().decode(CredentialProfile.self, from: data)
            guard profile.id == id else { throw LocalVaultFailure.corrupt }
            try profile.validate()
            return profile
        } catch { throw ADRNativeError.rejected("local_vault_corrupt") }
    }

    /// Native-only bytes. There must never be an IPC operation for this method.
    /// Missing local data requires explicit migration/re-entry, NOT a Keychain
    /// fallback. Corrupt/unsafe local files also fail closed.
    func credentialData(_ id: String) throws -> Data {
        let data = try nativeStorage { try local.load(id: id) }
        guard credentialKind(data, id: id) != nil else {
            throw ADRNativeError.rejected("local_vault_corrupt")
        }
        return data
    }

    private func nativeStorage<T>(_ action: () throws -> T) throws -> T {
        do { return try action() }
        catch let error as LocalVaultFailure { throw ADRNativeError.rejected(error.rawValue) }
        catch let error as VaultMigrationFailure { throw ADRNativeError.rejected(error.rawValue) }
        catch { throw ADRNativeError.rejected("local_vault_unavailable") }
    }

    private func validateIDs(_ ids: [String]) throws {
        guard ids.count <= 128, Set(ids).count == ids.count else {
            throw ADRNativeError.rejected("invalid_vault_ids")
        }
        // Validate the complete request before doing any work or echoing IDs.
        try nativeStorage { try ids.forEach(LocalVault.validateID) }
    }

    /// Validate decrypted data entirely in the host. Neither decoder errors nor
    /// user-provided metadata/value strings escape via status/migration results.
    private func credentialKind(_ data: Data, id: String) -> String? {
        guard !data.isEmpty, data.count <= LocalVault.maximumPlaintextBytes,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["id"] as? String == id else { return nil }
        do {
            if value["env_name"] != nil, value["auth_type"] == nil {
                let profile = try JSONDecoder().decode(EnvironmentCredential.self, from: data)
                guard profile.id == id else { return nil }
                try profile.validate()
                return "environment"
            }
            if value["auth_type"] != nil, value["env_name"] == nil {
                let profile = try JSONDecoder().decode(CredentialProfile.self, from: data)
                guard profile.id == id else { return nil }
                try profile.validate()
                return "service"
            }
        } catch {}
        return nil
    }

    /// A read-only check of *requested* IDs, with authentication/validation
    /// inside the native host. Does not enumerate credentials, inspect Keychain,
    /// create files, return paths, or include names, values, or value hashes.
    func storageStatus(arguments: [String: Any]) throws -> [String: Any] {
        guard let ids = arguments["ids"] as? [String] else {
            throw ADRNativeError.rejected("invalid_vault_ids")
        }
        return try storageStatus(ids: ids)
    }

    func storageStatus(ids: [String]) throws -> [String: Any] {
        try validateIDs(ids)
        let entries: [[String: Any]] = ids.map { id in
            do {
                let data = try credentialData(id)
                guard let kind = credentialKind(data, id: id) else {
                    throw ADRNativeError.rejected("local_vault_corrupt")
                }
                return ["id": id, "storage": "local_encrypted", "state": "available", "kind": kind]
            } catch {
                let code = safeStorageCode(error)
                let state = code == "local_vault_missing" ? "missing"
                    : ["local_vault_corrupt", "local_vault_too_large"].contains(code) ? "corrupt" : "unavailable"
                return ["id": id, "storage": "local_encrypted", "state": state, "reason_code": code]
            }
        }
        return [
            "backend": "local_encrypted", "format_version": 1, "entries": entries,
            "legacy_status": "not_checked", "legacy_access": "explicit_migration_only",
        ]
    }

    /// Reserve identity on receipt, BEFORE dispatching a worker. The native
    /// single-flight gate is not the HTTP wait: expiry/cancellation invalidates
    /// work but cannot release the gate while a legacy read is still alive.
    func beginLegacyMigration(
        arguments: [String: Any], expectedEpoch: UUID? = nil
    ) throws -> VaultMigrationIdentity {
        guard let ids = arguments["ids"] as? [String] else {
            throw ADRNativeError.rejected("invalid_vault_ids")
        }
        return try beginLegacyMigration(ids: ids, expiresAt: arguments["expires_at"], expectedEpoch: expectedEpoch)
    }

    func beginLegacyMigration(
        ids: [String], expiresAt: Any?, expectedEpoch: UUID? = nil
    ) throws -> VaultMigrationIdentity {
        try validateIDs(ids)
        return try nativeStorage {
            guard let number = expiresAt as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue.isFinite else { throw VaultMigrationFailure.invalidExpiry }
            let now = VaultMigrationTime.now
            let remaining = min(110, number.doubleValue - now.wall)
            guard remaining > 0 else { throw VaultMigrationFailure.expired }
            migrationLock.lock(); defer { migrationLock.unlock() }
            if let expectedEpoch, expectedEpoch != migrationGeneration {
                throw VaultMigrationFailure.cancelled
            }
            guard pendingMigration == nil, !ids.contains(where: { deletingIDs[$0] != nil }) else {
                throw VaultMigrationFailure.busy
            }
            let identity = VaultMigrationIdentity(token: UUID())
            pendingMigration = PendingMigration(
                identity: identity, ids: ids,
                deadline: VaultMigrationTime(wall: now.wall + remaining, uptime: now.uptime + remaining)
            )
            return identity
        }
    }

    /// Invalidate queued/running work without waiting for a system authorization
    /// dialog or the main queue. An old core's delayed death callback must not
    /// cancel a replacement core. Only worker completion clears the busy gate.
    func cancelLegacyMigrations(expectedEpoch: UUID? = nil) {
        migrationLock.lock(); defer { migrationLock.unlock() }
        if let expectedEpoch, expectedEpoch != migrationGeneration { return }
        migrationGeneration = UUID()
        pendingMigration?.cancelled = true
    }

    func legacyMigrationEpoch() -> UUID {
        migrationLock.lock(); defer { migrationLock.unlock() }
        return migrationGeneration
    }

    private func checkMigration(_ identity: VaultMigrationIdentity, id: String? = nil) throws {
        migrationLock.lock(); defer { migrationLock.unlock() }
        guard let pending = pendingMigration, pending.identity.token == identity.token, !pending.cancelled else {
            throw VaultMigrationFailure.cancelled
        }
        if let id, pending.invalidatedIDs.contains(id) || deletingIDs[id] != nil {
            throw VaultMigrationFailure.invalidated
        }
        let now = VaultMigrationTime.now
        guard now.wall < pending.deadline.wall, now.uptime < pending.deadline.uptime else {
            throw VaultMigrationFailure.expired
        }
    }

    /// Bounded convenience for direct native callers (including old synthetic
    /// tests). IPC must use beginLegacyMigration(arguments:) before dispatch.
    func migrateLegacy(ids: [String]) throws -> [String: Any] {
        let identity = try beginLegacyMigration(ids: ids, expiresAt: Date().timeIntervalSince1970 + 110)
        return try migrateLegacy(identity: identity)
    }

    /// Explicit owner-initiated copying only. No whole-operation replay and at
    /// most one legacy read per ID in this job. Already committed results survive
    /// a later failure, expiry, cancellation or deletion of another entry.
    func migrateLegacy(identity: VaultMigrationIdentity) throws -> [String: Any] {
        let ids: [String] = try nativeStorage {
            migrationLock.lock(); defer { migrationLock.unlock() }
            guard let pending = pendingMigration, pending.identity.token == identity.token else {
                throw VaultMigrationFailure.cancelled
            }
            guard !pending.running else { throw VaultMigrationFailure.busy }
            pendingMigration?.running = true
            return pending.ids
        }
        defer {
            migrationLock.lock()
            if pendingMigration?.identity.token == identity.token { pendingMigration = nil }
            migrationLock.unlock()
        }
        try nativeStorage { try checkMigration(identity) }
        let results: [[String: Any]] = ids.map { id in
            do {
                try checkMigration(identity, id: id)
                do {
                    let data = try credentialData(id)
                    try checkMigration(identity, id: id)
                    guard let kind = credentialKind(data, id: id) else {
                        throw ADRNativeError.rejected("local_vault_corrupt")
                    }
                    return ["id": id, "status": "already_local", "storage": "local_encrypted", "kind": kind]
                } catch ADRNativeError.rejected("local_vault_missing") {
                    // Only this exact missing condition permits a legacy read.
                }
                try checkMigration(identity, id: id)
                // No filesystem or lifetime lock is held during this possibly
                // interactive read. Recheck even if the adapter returns failure.
                let read = Result { try legacy.read(id: id) }
                try checkMigration(identity, id: id)
                let data = try read.get()
                guard let kind = credentialKind(data, id: id) else {
                    throw ADRNativeError.rejected("legacy_credential_invalid")
                }
                do {
                    try nativeStorage {
                        try local.save(id: id, data: data) { try checkMigration(identity, id: id) }
                    }
                } catch ADRNativeError.rejected("local_vault_exists") {
                    // Another operation won during the potentially interactive
                    // Keychain read. Keep its local value; never overwrite it.
                    try checkMigration(identity, id: id)
                    guard let localKind = credentialKind(try credentialData(id), id: id) else {
                        throw ADRNativeError.rejected("local_vault_corrupt")
                    }
                    return ["id": id, "status": "already_local", "storage": "local_encrypted", "kind": localKind]
                }
                // Acknowledge only an authenticated readback of this exact copy.
                guard try credentialData(id) == data else {
                    throw ADRNativeError.rejected("local_vault_corrupt")
                }
                return ["id": id, "status": "migrated", "storage": "local_encrypted", "kind": kind]
            } catch {
                return ["id": id, "status": "failed", "reason_code": safeMigrationCode(error)]
            }
        }
        return ["backend": "local_encrypted", "keychain_originals_retained": true, "results": results]
    }

    private func safeStorageCode(_ error: Error) -> String {
        let code = (error as? ADRNativeError)?.code ?? ""
        return LocalVaultFailure(rawValue: code)?.rawValue ?? "local_vault_unavailable"
    }

    private func safeMigrationCode(_ error: Error) -> String {
        let code = (error as? ADRNativeError)?.code ?? (error as? VaultMigrationFailure)?.rawValue ?? ""
        if let failure = VaultMigrationFailure(rawValue: code) { return failure.rawValue }
        if [
            "legacy_keychain_missing", "legacy_keychain_cancelled", "legacy_keychain_locked",
            "legacy_keychain_unavailable", "legacy_credential_invalid",
        ].contains(code) { return code }
        return safeStorageCode(error)
    }

    func checkText(arguments: [String: Any]) throws -> [String: Any] {
        guard let text = arguments["text"] as? String,
              let environmentIDs = arguments["environment_ids"] as? [String],
              let serviceIDs = arguments["service_ids"] as? [String] else {
            throw ADRNativeError.rejected("invalid_text_check")
        }
        let purpose: String
        if let value = arguments["purpose"] {
            guard let string = value as? String, ["prompt", "output"].contains(string) else {
                throw ADRNativeError.rejected("invalid_text_check")
            }
            purpose = string
        } else { purpose = "prompt" }
        return try checkText(text, environmentIDs: environmentIDs, serviceIDs: serviceIDs, protectOutput: purpose == "output")
    }

    func checkText(
        _ text: String, environmentIDs: [String], serviceIDs: [String], protectOutput: Bool = false
    ) throws -> [String: Any] {
        guard text.utf8.count <= 256 * 1024, environmentIDs.count <= 64, serviceIDs.count <= 64,
              Set(environmentIDs).count == environmentIDs.count, Set(serviceIDs).count == serviceIDs.count,
              Set(environmentIDs).isDisjoint(with: serviceIDs) else {
            throw ADRNativeError.rejected("invalid_text_check")
        }
        do { try (environmentIDs + serviceIDs).forEach(LocalVault.validateID) }
        catch { throw ADRNativeError.rejected("invalid_text_check") }
        var aliases: [String] = []
        var matched = false
        let environments = try environmentIDs.map(loadEnvironment)
        let names = environments.map(\.env_name)
        func contains(_ secret: String) -> Bool {
            // Prompt matching permits aliases and avoids short-password false
            // positives. Returned tool/history text must not expose even a short
            // saved value, including inside a serialized JSON string.
            if protectOutput {
                return VaultProcess.variants(secret).contains { !$0.isEmpty && text.contains($0) }
            }
            return VaultProcess.containsCredential(text, secret: secret, aliases: names)
        }
        for profile in environments {
            if contains(profile.secret) {
                matched = true; aliases.append(profile.env_name)
            }
        }
        for id in serviceIDs {
            let profile = try loadService(id)
            if protectOutput
                ? profile.outputProtectionVariants.contains(where: { !$0.isEmpty && text.contains($0) })
                : contains(profile.secret) {
                matched = true
            }
        }
        return ["checked": true, "matched": matched, "aliases": aliases]
    }

    func remove(_ id: String) throws {
        try nativeStorage { try LocalVault.validateID(id) }
        migrationLock.lock()
        removedIDs.insert(id)
        deletingIDs[id, default: 0] += 1
        if pendingMigration?.ids.contains(id) == true { pendingMigration?.invalidatedIDs.insert(id) }
        migrationLock.unlock()
        defer {
            migrationLock.lock()
            if let count = deletingIDs[id], count > 1 { deletingIDs[id] = count - 1 }
            else { deletingIDs.removeValue(forKey: id) }
            migrationLock.unlock()
        }
        // Invalidation is recorded even when the local copy is absent. If a
        // publication already passed its final validity check, it still holds
        // the exclusive filesystem lock: deletion follows it under that lock.
        // Otherwise the old job cannot publish after this deletion succeeds.
        try nativeStorage { try local.remove(id: id) }
    }

    func perform(
        id: String, path: String, deadline: Date,
        protectionEnvironmentIDs: [String] = [], protectionServiceIDs: [String] = []
    ) throws -> [String: Any] {
        guard protectionEnvironmentIDs.count <= 64, protectionServiceIDs.count <= 64,
              Set(protectionEnvironmentIDs).isDisjoint(with: protectionServiceIDs) else {
            throw ADRNativeError.rejected("invalid_environment_protection")
        }
        try validateIDs(protectionEnvironmentIDs + protectionServiceIDs)
        var protection = Set<String>()
        for identifier in protectionEnvironmentIDs {
            protection.formUnion(VaultProcess.variants(try loadEnvironment(identifier).secret))
        }
        for identifier in protectionServiceIDs {
            protection.formUnion(try loadService(identifier).outputProtectionVariants)
        }
        let profile = try loadService(id)
        let (_, host) = try ServiceBoundary.origin(profile.origin)
        let target = try ServiceBoundary.target(path, allowed: profile.allowed_paths)
        let header = profile.auth_type == "api_key" ? profile.header_name : "Authorization"
        let packet = try PinnedHTTPS().get(
            host: host, path: target, header: header, value: profile.authorization, deadline: deadline
        )
        return try profile.safeResult(packet, protectionVariants: protection)
    }

    @MainActor func promptStore(arguments: [String: Any]) throws -> [String: Any] {
        let deadline = Date().addingTimeInterval(110)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        let kind = arguments["auth_type"] as? String ?? "bearer"
        let valueLabel = kind == "basic" ? "Password" : kind == "api_key" ? "API key" : "Token"
        alert.messageText = "Save \(arguments["name"] as? String ?? "credential")"
        alert.informativeText = """
        Paste your existing \(valueLabel.lowercased()) for:
        \(arguments["origin"] as? String ?? "the selected service")

        ADR saves it in this profile's encrypted local vault, without a Keychain unlock. Agents you allow can ask ADR to make API read requests without receiving this value.

        The decryption key is stored locally too. This does not protect against other programs running as you.
        """
        alert.addButton(withTitle: "Save to local vault")
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 28))
        field.placeholderString = valueLabel
        field.setAccessibilityLabel(valueLabel)
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { throw ADRNativeError.rejected("cancelled") }
        defer { field.stringValue = "" }
        guard Date() < deadline else { throw ADRNativeError.rejected("request_expired") }
        var value = arguments
        value["secret"] = field.stringValue
        let data = try JSONSerialization.data(withJSONObject: value)
        let profile = try JSONDecoder().decode(CredentialProfile.self, from: data)
        try store(profile)
        return ["id": profile.id, "stored": true, "storage": "local_encrypted", "storage_state": "available"]
    }

    // Compatibility entry point; the parent should relabel the old CLI flag.
    // All fixtures are now synthetic disk files and an in-memory legacy source.
    static func selfTest() throws {
        try LocalVaultSelfTests.run()
    }
}
