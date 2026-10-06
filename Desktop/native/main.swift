import Cocoa
import CFNetwork
import Security
import ServiceManagement

signal(SIGPIPE, SIG_IGN)

enum ToolApprovalClock {
    static func deadline(expiresAt: Any?, now: Date = Date()) -> Date? {
        let expires: Double
        if let value = expiresAt {
            guard let number = value as? Double, number.isFinite else { return nil }
            expires = number
        } else {
            expires = now.timeIntervalSince1970 + 100
        }
        let remaining = min(100, expires - now.timeIntervalSince1970)
        guard remaining > 0 else { return nil }
        return now.addingTimeInterval(remaining)
    }
}

final class LocalSessionDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class LineFramer: @unchecked Sendable {
    private var buffer = Data()
    private let lock = NSLock()
    func append(_ data: Data) -> [Data] {
        lock.lock(); defer { lock.unlock() }
        buffer.append(data)
        if buffer.count > 2 * 1024 * 1024 { buffer.removeAll(); return [] }
        var lines: [Data] = []
        while let end = buffer.firstIndex(of: 10) {
            lines.append(Data(buffer[..<end]))
            buffer.removeSubrange(...end)
        }
        return lines
    }
}

@MainActor final class ADRApplication: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var statusLine = NSMenuItem(title: "Starting local workspace…", action: nil, keyEquivalent: "")
    private var captureItem = NSMenuItem(title: "Start capture", action: #selector(toggleCapture), keyEquivalent: "")
    private var process: Process?
    private var input: Pipe?
    private var output: Pipe?
    private var timer: Timer?
    private var ownerToken = ""
    private var port = 0
    private var recording = false
    private var quitting = false
    private var generation = UUID()
    private let vault = Vault()
    private var migrationEpoch: UUID?
    private let delegate = LocalSessionDelegate()
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 4
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: false,
            kCFNetworkProxiesHTTPSEnable as String: false,
            kCFNetworkProxiesSOCKSEnable as String: false,
            kCFNetworkProxiesProxyAutoConfigEnable as String: false,
            kCFNetworkProxiesProxyAutoDiscoveryEnable as String: false,
        ]
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "ADR")
        statusItem.button?.image?.isTemplate = true
        statusItem.button?.title = " ADR"
        statusItem.button?.toolTip = "ADR Desktop — local agent insights and protection"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "ADR Desktop", action: nil, keyEquivalent: ""))
        menu.addItem(statusLine)
        menu.addItem(.separator())
        let open = NSMenuItem(title: "Open ADR Insights", action: #selector(openInsights), keyEquivalent: "o")
        open.target = self; menu.addItem(open)
        captureItem.target = self; menu.addItem(captureItem)
        let credentials = NSMenuItem(title: "Credential vault…", action: #selector(openCredentials), keyEquivalent: "")
        credentials.target = self; menu.addItem(credentials)
        let protection = NSMenuItem(title: "File protection…", action: #selector(openProtection), keyEquivalent: "")
        protection.target = self; menu.addItem(protection)
        menu.addItem(.separator())
        let restart = NSMenuItem(title: "Restart local service", action: #selector(restartService), keyEquivalent: "")
        restart.target = self; menu.addItem(restart)
        let quit = NSMenuItem(title: "Quit ADR", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit)
        statusItem.menu = menu
        launchCore()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openInsights(); return true
    }

    private func launchCore() {
        guard process?.isRunning != true else { return }
        guard let resources = Bundle.main.resourceURL else { return }
        let executable = resources.appendingPathComponent("core/ADRCore")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            statusLine.title = "Core missing — rebuild the application"; return
        }
        generation = UUID()
        let vault = self.vault
        vault.cancelLegacyMigrations()
        let epoch = vault.legacyMigrationEpoch()
        migrationEpoch = epoch
        let instance = generation
        let child = Process()
        let stdin = Pipe(), stdout = Pipe()
        child.executableURL = executable
        child.arguments = ["serve", "--native-bridge"]
        if let testProfile = ProcessInfo.processInfo.environment["ADR_DESKTOP_STATE_DIR"], !testProfile.isEmpty {
            child.arguments?.append(contentsOf: ["--state-dir", testProfile])
        }
        child.standardInput = stdin
        child.standardOutput = stdout
        child.standardError = FileHandle.nullDevice
        child.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
        let framer = LineFramer()
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            for line in framer.append(data) {
                Task { @MainActor in
                    guard let value = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { return }
                    self?.receive(value, generation: instance)
                }
            }
        }
        child.terminationHandler = { [weak self] _ in
            // Keychain approval may finish while the main queue is occupied.
            // Cancel natively now; an old process cannot cancel a new epoch.
            vault.cancelLegacyMigrations(expectedEpoch: epoch)
            Task { @MainActor in
                guard let self, self.generation == instance, !self.quitting else { return }
                // Invalidate main-queue messages as well as already dispatched
                // workers. A dead core must not start a new stale migration.
                self.generation = UUID()
                self.migrationEpoch = nil
                VaultProcess.cancelAll()
                self.ownerToken = ""; self.port = 0
                self.statusLine.title = "Service stopped — restart from this menu"
                self.statusItem.button?.title = " ADR !"
            }
        }
        process = child; input = stdin; output = stdout
        statusLine.title = "Starting local workspace…"
        do { try child.run() }
        catch { statusLine.title = "Could not start the local service" }
    }

    private func receive(_ message: [String: Any], generation: UUID) {
        guard generation == self.generation, !quitting, process?.isRunning == true else { return }
        if message["type"] as? String == "ready" {
            guard let port = message["port"] as? Int, (1024...65535).contains(port),
                  let token = message["owner_token"] as? String, token.count >= 40 else { return }
            self.port = port; ownerToken = token
            statusLine.title = "Running locally · capture paused"
            statusItem.button?.title = " ADR"
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
                self?.refreshStatus()
                if !UserDefaults.standard.bool(forKey: "hasOpenedWorkspace") {
                    self?.openInsights()
                    UserDefaults.standard.set(true, forKey: "hasOpenedWorkspace")
                }
            }
            return
        }
        guard message["type"] as? String == "native_request",
              let identifier = message["id"] as? String,
              let operation = message["operation"] as? String,
              let arguments = message["arguments"] as? [String: Any] else { return }
        func reply(_ result: Result<[String: Any], Error>) {
            var response: [String: Any] = ["type": "native_response", "id": identifier]
            switch result {
            case .success(let value): response["ok"] = true; response["result"] = value
            case .failure(let error):
                response["ok"] = false
                response["error"] = (error as? ADRNativeError)?.code ?? "native_operation_failed"
            }
            send(response, generation: generation)
        }
        switch operation {
        case "approve_vault_migration":
            let deadline = Date().addingTimeInterval(100)
            let count = min(128, max(0, arguments["count"] as? Int ?? 0))
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Move \(count) older credential entries to the local vault?"
            alert.informativeText = """
            ADR will copy the selected existing values from Keychain into encrypted local files. This one-time read may need a macOS Keychain approval.

            Future use will not require Keychain unlocks. Original Keychain entries stay intact. The local encryption key is stored in your private ADR profile, so this does not isolate values from other code running as your OS user.
            """
            alert.addButton(withTitle: "Cancel")
            alert.addButton(withTitle: "Move to local vault")
            DispatchQueue.main.asyncAfter(deadline: .now() + 100) { [weak alert] in
                if alert?.window.isVisible == true { NSApp.abortModal() }
            }
            let result = alert.runModal()
            reply(.success(["allowed": result == .alertSecondButtonReturn && Date() < deadline]))
        case "approve_integration":
            let deadline = Date().addingTimeInterval(100)
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Connect ADR to \(arguments["harness"] as? String ?? "this agent")?"
            alert.informativeText = """
            This installs one ADR plugin for protection and conversation search.

            The agent can search and read captured conversations across all agents and projects on this device. History may contain sensitive information.

            \(arguments["credentials"] as? Bool == true
              ? "Local commands can use all saved credentials, including ones you add later, without per-key or per-project setup. ADR filters command output before returning it to the model. Your file rules still apply."
              : "This history-only connection does not grant vault credential use.")

            This does not grant permission to change ADR policies. Restart agents afterward and review any native plugin trust prompts.
            """
            alert.addButton(withTitle: "Cancel")
            alert.addButton(withTitle: "Connect ADR")
            DispatchQueue.main.asyncAfter(deadline: .now() + 100) { [weak alert] in
                if alert?.window.isVisible == true { NSApp.abortModal() }
            }
            let result = alert.runModal()
            reply(.success(["allowed": result == .alertSecondButtonReturn && Date() < deadline]))
        case "approve_tool":
            // Time in the core's queue counts toward the same deadline. A
            // request that expired before reaching the main thread must not
            // open a stale approval dialog.
            guard let deadline = ToolApprovalClock.deadline(expiresAt: arguments["expires_at"]) else {
                reply(.success(["allowed": false, "reason_code": "approval_expired"])); return
            }
            let remaining = max(0, deadline.timeIntervalSinceNow)
            guard let operation = arguments["operation"] as? String,
                  operation.utf8.count <= 16384 else {
                reply(.success(["allowed": false])); return
            }
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Allow this agent action once?"
            alert.informativeText = "\(arguments["harness"] as? String ?? "Agent") · \(arguments["tool"] as? String ?? "Tool")\nReview the complete operation below. This does not change your saved rules."
            alert.addButton(withTitle: "Deny")
            alert.addButton(withTitle: "Allow once")
            let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 500, height: 220))
            scroll.hasVerticalScroller = true
            let text = NSTextView(frame: scroll.bounds)
            text.isEditable = false; text.isSelectable = true
            text.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            text.string = operation
            text.isVerticallyResizable = true
            text.textContainer?.widthTracksTextView = true
            text.textContainer?.containerSize = NSSize(width: 500, height: CGFloat.greatestFiniteMagnitude)
            text.autoresizingMask = [.width]
            scroll.documentView = text; alert.accessoryView = scroll
            DispatchQueue.main.asyncAfter(deadline: .now() + remaining) { [weak alert] in
                if alert?.window.isVisible == true { NSApp.abortModal() }
            }
            let result = alert.runModal()
            let expired = Date() >= deadline
            let allowed = result == .alertSecondButtonReturn && !expired
            reply(.success([
                "allowed": allowed,
                "reason_code": expired ? "approval_expired" : allowed ? "approved" : "approval_denied",
            ]))
        case "vault_prompt_store":
            do { reply(.success(try vault.promptStore(arguments: arguments))) }
            catch { reply(.failure(error)) }
        case "environment_prompt_store":
            do { reply(.success(try vault.promptEnvironment(arguments: arguments))) }
            catch { reply(.failure(error)) }
        case "vault_storage_status":
            let vault = self.vault
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try vault.storageStatus(arguments: arguments) }
                Task { @MainActor in reply(result) }
            }
        case "vault_migrate_legacy":
            let vault = self.vault
            do {
                guard let epoch = migrationEpoch else {
                    throw ADRNativeError.rejected("vault_migration_cancelled")
                }
                // Reserve the native lifetime/gate now, not after queueing.
                // Restart/death/shutdown can then invalidate this exact job.
                let identity = try vault.beginLegacyMigration(arguments: arguments, expectedEpoch: epoch)
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = Result { try vault.migrateLegacy(identity: identity) }
                    Task { @MainActor in reply(result) }
                }
            } catch { reply(.failure(error)) }
        case "vault_check_text":
            let vault = self.vault
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try vault.checkText(arguments: arguments) }
                Task { @MainActor in reply(result) }
            }
        case "environment_execute":
            let vault = self.vault
            let epoch = VaultProcess.epoch()
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try vault.executeEnvironment(arguments: arguments, expectedEpoch: epoch) }
                Task { @MainActor in reply(result) }
            }
        case "vault_delete":
            guard let id = arguments["id"] as? String else {
                reply(.failure(ADRNativeError.rejected("invalid_credential_id"))); return
            }
            let vault = self.vault
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result {
                    try vault.remove(id)
                    return ["removed": true] as [String: Any]
                }
                Task { @MainActor in reply(result) }
            }
        case "vault_perform":
            let id = arguments["id"] as? String ?? "", path = arguments["path"] as? String ?? ""
            guard let environmentIDs = arguments["protection_environment_ids"] as? [String],
                  let serviceIDs = arguments["protection_service_ids"] as? [String] else {
                reply(.failure(ADRNativeError.rejected("invalid_environment_protection"))); return
            }
            let deadline = Date().addingTimeInterval(20)
            let vault = self.vault
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result {
                    try vault.perform(
                        id: id, path: path, deadline: deadline,
                        protectionEnvironmentIDs: environmentIDs, protectionServiceIDs: serviceIDs
                    )
                }
                Task { @MainActor in reply(result) }
            }
        case "choose_path":
            NSApp.activate(ignoringOtherApps: true)
            let panel = NSOpenPanel()
            panel.canChooseDirectories = true; panel.canChooseFiles = true
            panel.allowsMultipleSelection = false
            panel.message = "Choose a path for ADR. Selecting it does not change its contents."
            if panel.runModal() == .OK, let url = panel.url {
                let directory = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
                reply(.success(["path": url.path, "kind": directory ? "directory" : "file"]))
            } else { reply(.failure(ADRNativeError.rejected("cancelled"))) }
        case "file_access_identity":
            reply(.success(ADRFileAccess.identity(
                coreExecutable: Bundle.main.resourceURL?.appendingPathComponent("core/ADRCore")
            )))
        case "open_access_settings":
            do {
                reply(.success(try ADRFileAccess.openSettings(
                    target: arguments["target"] as? String ?? ""
                )))
            } catch { reply(.failure(ADRNativeError.rejected("unsupported_access_settings"))) }
        case "login_status":
            reply(.success(loginStatus()))
        case "review_idle_status":
            let idle = CGEventSource.secondsSinceLastEventType(
                .combinedSessionState, eventType: CGEventType(rawValue: UInt32.max)!
            )
            reply(.success(["idle_seconds": idle.isFinite ? max(0, idle) : 0]))
        case "set_login":
            let enabled = arguments["enabled"] as? Bool ?? false
            Task { @MainActor in
                do {
                    if enabled { try SMAppService.mainApp.register() }
                    else { try await SMAppService.mainApp.unregister() }
                    reply(.success(loginStatus()))
                } catch { reply(.failure(ADRNativeError.rejected("login_item_change_failed"))) }
            }
        default:
            reply(.failure(ADRNativeError.rejected("unsupported_native_operation")))
        }
    }

    private func send(_ value: [String: Any], generation: UUID) {
        guard generation == self.generation, let handle = input?.fileHandleForWriting else { return }
        guard var data = try? JSONSerialization.data(withJSONObject: value), data.count < 2 * 1024 * 1024 else {
            if let id = value["id"] as? String {
                send(["type": "native_response", "id": id, "ok": false, "error": "response_too_large"], generation: generation)
            }
            return
        }
        data.append(10)
        try? handle.write(contentsOf: data)
    }

    private func loginStatus() -> [String: Any] {
        let status = SMAppService.mainApp.status
        return ["available": true, "enabled": status == .enabled, "requires_approval": status == .requiresApproval]
    }

    private func local(_ path: String, method: String = "GET", completion: @escaping ([String: Any]?) -> Void) {
        guard port != 0, !ownerToken.isEmpty, let url = URL(string: "http://127.0.0.1:\(port)\(path)") else {
            completion(nil); return
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(ownerToken)", forHTTPHeaderField: "Authorization")
        if method != "GET" {
            request.httpBody = Data("{}".utf8)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        session.dataTask(with: request) { data, response, _ in
            let valid = (response as? HTTPURLResponse)?.statusCode == 200
            let value = valid ? data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } : nil
            DispatchQueue.main.async { completion(value) }
        }.resume()
    }

    @objc private func openInsights() { openPage("/") }
    @objc private func openCredentials() { openPage("/credentials") }
    @objc private func openProtection() { openPage("/protection") }

    private func openPage(_ path: String) {
        local("/api/control/open", method: "POST") { [weak self] value in
            guard let self, let text = value?["url"] as? String, var url = URLComponents(string: text),
                  url.scheme == "http", url.host == "127.0.0.1", url.port == self.port else { return }
            url.path = path
            if let target = url.url { NSWorkspace.shared.open(target) }
        }
    }

    @objc private func toggleCapture() {
        local("/api/collector/\(recording ? "pause" : "start")", method: "POST") { [weak self] _ in
            self?.refreshStatus()
        }
    }

    private func refreshStatus() {
        local("/api/status") { [weak self] value in
            guard let self else { return }
            guard let value else {
                if self.process?.isRunning == true { self.statusLine.title = "Local service is reconnecting…" }
                return
            }
            let collector = value["collector"] as? [String: Any] ?? [:]
            self.recording = collector["recording"] as? Bool ?? false
            let pending = value["pending"] as? Int ?? 0
            let phase = collector["phase"] as? String ?? "idle"
            self.captureItem.title = self.recording ? "Pause capture" : "Start capture"
            self.statusItem.button?.title = pending > 0 ? " ADR \(pending)" : " ADR"
            self.statusLine.title = pending > 0 ? "\(pending) credential request(s) need approval" :
                phase == "error" || phase == "partial" ? "Running · collection needs attention" :
                "Running locally · \(self.recording ? "capture on" : "capture paused")"
        }
    }

    @objc private func restartService() {
        stopCore()
        ownerToken = ""; port = 0; process = nil
        launchCore()
    }

    private func stopCore() {
        generation = UUID()
        migrationEpoch = nil
        vault.cancelLegacyMigrations()
        VaultProcess.cancelAll()
        output?.fileHandleForReading.readabilityHandler = nil
        try? input?.fileHandleForWriting.close()
        if let child = process, child.isRunning {
            child.terminate()
            let deadline = Date().addingTimeInterval(4)
            while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        }
    }

    @objc private func quitApp() {
        quitting = true
        timer?.invalidate()
        stopCore()
        NSApp.terminate(nil)
    }

    func applicationWillTerminate(_ notification: Notification) {
        quitting = true; stopCore()
    }
}

if CommandLine.arguments.contains("--self-test") {
    do {
        try NativeSelfTests.run()
        print("ADR native security tests passed")
        exit(0)
    } catch {
        fputs("ADR native security test failed\n", stderr)
        exit(1)
    }
}
if CommandLine.arguments.contains("--vault-self-test") || CommandLine.arguments.contains("--keychain-self-test") {
    do {
        try Vault.selfTest()
        print("ADR isolated local-vault security tests passed")
        exit(0)
    } catch {
        fputs("ADR local-vault synthetic self-test failed\n", stderr)
        exit(1)
    }
}
MainActor.assumeIsolated {
    let application = NSApplication.shared
    let controller = ADRApplication()
    application.delegate = controller
    withExtendedLifetime(controller) { application.run() }
}
