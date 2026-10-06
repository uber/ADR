import Foundation
import Darwin

/// A bounded, noninteractive native child. Only filtered output crosses IPC.
enum VaultProcess {
    private static let processLock = NSLock()
    private static var active: Set<pid_t> = []
    private static var generation: UInt64 = 0

    static func epoch() -> UInt64 {
        processLock.lock(); defer { processLock.unlock() }
        return generation
    }

    static func cancelAll() {
        processLock.lock(); defer { processLock.unlock() }
        generation &+= 1
        // Leaders stay unreaped until removed from active, so no PID here can
        // refer to an unrelated process which reused a completed child's PID.
        for pid in active { kill(-pid, SIGKILL) }
    }

    static func variants(_ secret: String) -> Set<String> {
        let base64 = Data(secret.utf8).base64EncodedString()
        let base64URL = base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        var result: Set<String> = [
            secret, base64, base64URL,
            base64.replacingOccurrences(of: "=", with: ""),
            base64URL.replacingOccurrences(of: "=", with: ""),
        ]
        if let encoded = secret.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
            result.insert(encoded)
        }
        // Query-allowed characters leave delimiters such as '+' unescaped.
        // Also cover a value encoded as a URL component or a form field.
        let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        if let encoded = secret.addingPercentEncoding(withAllowedCharacters: unreserved) {
            result.insert(encoded)
            result.insert(encoded.replacingOccurrences(of: "%20", with: "+"))
        }
        if let encoded = try? JSONSerialization.data(withJSONObject: secret, options: .fragmentsAllowed),
           let text = String(data: encoded, encoding: .utf8), text.count > 2 {
            result.insert(String(text.dropFirst().dropLast()))
        }
        return result
    }

    static func containsCredential(_ text: String, secret: String, aliases: [String]) -> Bool {
        if secret.utf8.count < 6 {
            // Short passwords still work. Do not make ordinary words/code
            // unusable merely because they contain one or two matching letters.
            if text.trimmingCharacters(in: .whitespacesAndNewlines) == secret { return true }
            let labels = (aliases + ["password", "passwd", "pwd", "token", "secret"])
                .map { NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "|")
            let value = NSRegularExpression.escapedPattern(for: secret)
            let pattern = "(?i)\\b(?:\(labels))[\"']?\\s*(?:[:=]|\\bis\\b)\\s*[\"']?\(value)(?:$|[\"'\\s,;])"
            return (try? NSRegularExpression(pattern: pattern))?.firstMatch(
                in: text, range: NSRange(text.startIndex..., in: text)
            ) != nil
        }
        let input = text as NSString
        // A variable reference is not a pasted value, even if a short secret
        // happens to be a substring of its public alias.
        let references = aliases.flatMap { name -> [NSRange] in
            let escaped = NSRegularExpression.escapedPattern(for: name)
            let pattern = "\\$(?:\(escaped)\\b|\\{\(escaped)(?=[:}]))"
                + "|(?:os\\.environ\\[|os\\.getenv\\(|process\\.env\\[)\\s*[\"']\(escaped)[\"']"
                + "|process\\.env\\.\(escaped)\\b"
            return ((try? NSRegularExpression(pattern: pattern))?.matches(
                in: text, range: NSRange(location: 0, length: input.length)
            ) ?? []).map(\.range)
        }
        for variant in variants(secret) where !variant.isEmpty {
            var search = NSRange(location: 0, length: input.length)
            while search.length > 0 {
                let match = input.range(of: variant, range: search)
                if match.location == NSNotFound { break }
                if !references.contains(where: {
                    $0.location <= match.location && NSMaxRange($0) >= NSMaxRange(match)
                }) { return true }
                let next = match.location + max(1, match.length)
                search = NSRange(location: next, length: input.length - next)
            }
        }
        return false
    }

    static func run(
        command: String, cwd: String, credentials: [EnvironmentCredential], timeout: TimeInterval,
        expectedEpoch: UInt64? = nil, protectionVariants: Set<String> = []
    ) throws -> [String: Any] {
        var output: [Int32] = [0, 0], error: [Int32] = [0, 0]
        guard pipe(&output) == 0 else { throw ADRNativeError.rejected("execution_pipe_failed") }
        guard pipe(&error) == 0 else {
            close(output[0]); close(output[1]); throw ADRNativeError.rejected("execution_pipe_failed")
        }
        defer { output.forEach { close($0) }; error.forEach { close($0) } }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw ADRNativeError.rejected("execution_setup_failed")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw ADRNativeError.rejected("execution_setup_failed")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        let flags = Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, error[1], STDERR_FILENO) == 0,
              posix_spawn_file_actions_addchdir_np(&actions, cwd) == 0 else {
            throw ADRNativeError.rejected("execution_setup_failed")
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var environment = [
            "HOME": home, "USER": NSUserName(), "LOGNAME": NSUserName(),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin:\(home)/.local/bin",
            "LANG": "en_US.UTF-8", "TMPDIR": NSTemporaryDirectory(),
        ]
        for profile in credentials { environment[profile.env_name] = profile.secret }
        let arguments: [String] = ["/bin/bash", "--noprofile", "--norc", "-c", command]
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map {
            $0.withCString { strdup($0) }
        } + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = environment.sorted(by: { $0.key < $1.key }).map {
            "\($0.key)=\($0.value)".withCString { strdup($0) }
        } + [nil]
        defer {
            argv.compactMap { $0 }.forEach { free($0) }
            envp.compactMap { $0 }.forEach { free($0) }
        }
        guard argv.dropLast().allSatisfy({ $0 != nil }), envp.dropLast().allSatisfy({ $0 != nil }) else {
            throw ADRNativeError.rejected("execution_allocation_failed")
        }
        var pid: pid_t = 0
        processLock.lock()
        if let expectedEpoch, expectedEpoch != generation {
            processLock.unlock()
            throw ADRNativeError.rejected("execution_cancelled")
        }
        let spawned = posix_spawn(&pid, "/bin/bash", &actions, &attributes, &argv, &envp)
        if spawned == 0 && pid > 0 { active.insert(pid) }
        processLock.unlock()
        guard spawned == 0, pid > 0 else {
            throw ADRNativeError.rejected("execution_start_failed")
        }
        close(output[1]); output[1] = -1
        close(error[1]); error[1] = -1
        for fd in [output[0], error[0]] { _ = fcntl(fd, F_SETFL, O_NONBLOCK) }
        var buffers = [Data(), Data()], ended = [false, false]
        var status: Int32 = 0
        var exited = false, timedOut = false, oversized = false
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !exited || !ended.allSatisfy({ $0 }) {
            if ProcessInfo.processInfo.systemUptime >= deadline { timedOut = true; break }
            var polls = [pollfd(fd: output[0], events: Int16(POLLIN | POLLHUP), revents: 0),
                         pollfd(fd: error[0], events: Int16(POLLIN | POLLHUP), revents: 0)]
            _ = poll(&polls, 2, 20)
            for index in 0...1 where !ended[index] && polls[index].revents != 0 {
                var bytes = [UInt8](repeating: 0, count: 8192)
                let count = read(polls[index].fd, &bytes, bytes.count)
                if count > 0 {
                    buffers[index].append(contentsOf: bytes.prefix(count))
                    if buffers[0].count + buffers[1].count > 65536 { oversized = true }
                } else if count == 0 { ended[index] = true }
                else if errno != EAGAIN && errno != EINTR { ended[index] = true; oversized = true }
            }
            if oversized { break }
            if !exited {
                var info = siginfo_t()
                // Observe exit without reaping. That keeps PID ownership
                // intact while output pipes or background children remain.
                if waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 {
                    exited = info.si_pid == pid
                }
            }
        }
        processLock.lock()
        active.remove(pid)
        // Stop remaining members even after a successful foreground command.
        // Detached daemons are outside this cooperative execution boundary.
        kill(-pid, SIGKILL)
        processLock.unlock()
        _ = waitpid(pid, &status, 0)
        if timedOut || oversized {
            // Never return a truncated secret prefix at the output-size boundary.
            return [
                "exit_code": timedOut ? 124 : 125, "stdout": "", "stderr": "",
                "timed_out": timedOut, "output_withheld": true,
                "message": timedOut ? "Command timed out; output withheld." : "Output limit exceeded; output withheld.",
            ]
        }
        guard let stdout = String(data: buffers[0], encoding: .utf8),
              let stderr = String(data: buffers[1], encoding: .utf8) else {
            return ["exit_code": 125, "stdout": "", "stderr": "", "output_withheld": true,
                    "message": "Non-text output was withheld."]
        }
        // Protection-only values never enter envp. Selected injection values
        // always remain protected, including with an explicitly empty list.
        var variants = protectionVariants
        for profile in credentials {
            variants.formUnion(Self.variants(profile.secret))
        }
        variants.remove("")
        func filtered(_ text: String) -> String {
            variants.filter { !$0.isEmpty }.sorted { $0.count > $1.count }.reduce(text) {
                $0.replacingOccurrences(of: $1, with: "[ADR credential hidden]")
            }
        }
        let safeOut = filtered(stdout), safeErr = filtered(stderr)
        let code = status & 0x7f == 0 ? Int((status >> 8) & 0xff) : 128 + Int(status & 0x7f)
        if variants.contains(where: { safeOut.contains($0) || safeErr.contains($0) }) {
            return ["exit_code": code, "stdout": "", "stderr": "", "output_withheld": true,
                    "message": "Credential-bearing output was withheld."]
        }
        return ["exit_code": code, "stdout": safeOut, "stderr": safeErr,
                "redacted": safeOut != stdout || safeErr != stderr, "output_withheld": false]
    }
}
