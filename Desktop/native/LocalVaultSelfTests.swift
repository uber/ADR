import Darwin
import Foundation

/// No production profile, credential, Keychain API, UI prompt, or network access.
/// All filesystem mutations remain inside a freshly created synthetic fixture.
enum LocalVaultSelfTests {
    private final class SyntheticLegacy: LegacyCredentialSource, @unchecked Sendable {
        let originals: [String: Data]
        private let failures: [String: String]
        private let lock = NSLock()
        private var calls: [String] = []

        init(_ originals: [String: Data] = [:], failures: [String: String] = [:]) {
            self.originals = originals
            self.failures = failures
        }

        func read(id: String) throws -> Data {
            lock.lock(); defer { lock.unlock() }
            calls.append(id)
            if let failure = failures[id] { throw ADRNativeError.rejected(failure) }
            guard let data = originals[id] else { throw ADRNativeError.rejected("legacy_keychain_missing") }
            return data
        }

        var readIDs: [String] {
            lock.lock(); defer { lock.unlock() }
            return calls
        }
    }

    private final class DelayedLegacy: LegacyCredentialSource, @unchecked Sendable {
        let source: SyntheticLegacy
        let delayedID: String
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let returning = DispatchSemaphore(value: 0)

        init(_ source: SyntheticLegacy, delayedID: String) {
            self.source = source
            self.delayedID = delayedID
        }

        func read(id: String) throws -> Data {
            let result = Result { try source.read(id: id) }
            if id == delayedID {
                entered.signal()
                guard release.wait(timeout: .now() + 10) == .success else {
                    throw ADRNativeError.rejected("synthetic_legacy_wait_timed_out")
                }
                returning.signal()
            }
            return try result.get()
        }
    }

    /// A bounded join, not a retry. Completion publishes the result before any
    /// reader can inspect it. Fixtures always join workers before cleanup.
    private final class Work<Value>: @unchecked Sendable {
        private let group = DispatchGroup()
        private var result: Result<Value, Error>?

        init(_ action: @escaping @Sendable () throws -> Value) {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                self.result = Result { try action() }
                self.group.leave()
            }
        }

        func finished(within seconds: TimeInterval) -> Bool {
            group.wait(timeout: .now() + seconds) == .success
        }

        func get(timeout: TimeInterval = 5) throws -> Value {
            guard finished(within: timeout), let result else {
                throw ADRNativeError.rejected("local_vault_test_worker_timeout")
            }
            return try result.get()
        }
    }

    static func run() throws {
        let tests: [(String, () throws -> Void)] = [
            ("round-trip, confidentiality, metadata, reopen, deletion", roundTrip),
            ("profile isolation and authenticated record binding", isolation),
            ("corruption, bounds, schema and ID validation", corruption),
            ("key loss and invalid keys never regenerate", keyLoss),
            ("owner-only modes and extended ACL rejection", permissions),
            ("profile, ancestor and vault-directory symlinks", directorySymlinks),
            ("key, record and lock symlinks; hardlinks; special files", unsafeFiles),
            ("concurrent shared load/status/text and atomic publication without retries", concurrency),
            ("short-writer waits and bounded held-lock failures", lockWaiting),
            ("partial migration, retained originals and idempotent retry", migration),
            ("migration destination failure preserves every original", failedMigration),
            ("strict IPC arrays, expiry types and queued migration identity", requestValidation),
            ("late legacy success after expiry, deletion and cancellation", migrationLifetime),
            ("migration expiry while waiting and final publication validity", migrationPublication),
            ("unchanged native environment injection and output filtering", environmentExecution),
            ("protection-only credentials, authorization encodings and fail-closed execution", environmentProtection),
        ]
        for (name, test) in tests {
            do { try test() }
            catch {
                // Only static labels/codes; never print an error's description.
                fputs("ADR synthetic local vault FAILED: \(name) (\(errorCode(error)))\n", stderr)
                throw error
            }
            print("ADR synthetic local vault passed: \(name)")
        }
    }

    private static func fixture(_ action: (URL) throws -> Void) throws {
        // macOS /var and /tmp themselves are symlinks. Use POSIX realpath for
        // *only this synthetic base*: Foundation can shorten /private/var back
        // to /var even in a "resolved" URL.
        guard let resolved = realpath(FileManager.default.temporaryDirectory.path, nil) else {
            throw ADRNativeError.rejected("local_vault_test_temporary_path")
        }
        defer { free(resolved) }
        let root = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
            .appendingPathComponent("adr-local-vault-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try action(root)
    }

    private static func id(_ value: Int) -> String { String(format: "%032x", value) }

    private static func environment(_ value: Int) -> EnvironmentCredential {
        EnvironmentCredential(
            id: id(value), name: "Synthetic entry \(value)", env_name: "SYNTHETIC_VALUE_\(value)",
            secret: "synthetic-local-vault-secret-\(value)-never-used-on-network\nsecond-line"
        )
    }

    private static func service(_ value: Int) -> CredentialProfile {
        CredentialProfile(
            id: id(value), name: "Synthetic service \(value)", origin: "https://example.com",
            auth_type: "bearer", header_name: "Authorization", username: "", allowed_paths: ["/"],
            secret: "synthetic-service-secret-\(value)-never-used-on-network"
        )
    }

    private static func directory(_ root: URL) -> URL {
        root.appendingPathComponent(LocalVault.directoryName, isDirectory: true)
    }

    private static func record(_ root: URL, _ id: String) -> URL {
        directory(root).appendingPathComponent(id + LocalVault.recordSuffix)
    }

    private static func require(_ condition: Bool, line: UInt = #line) throws {
        guard condition else { throw ADRNativeError.rejected("local_vault_test_assertion_line_\(line)") }
    }

    private static func waitPast(_ wallTime: TimeInterval) throws {
        let limit = ProcessInfo.processInfo.systemUptime + 4
        while Date().timeIntervalSince1970 <= wallTime {
            try require(ProcessInfo.processInfo.systemUptime < limit)
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    private static func errorCode(_ error: Error) -> String {
        (error as? ADRNativeError)?.code ?? (error as? LocalVaultFailure)?.rawValue ?? "unexpected_error"
    }

    private static func expect(_ code: String, line: UInt = #line, _ action: () throws -> Void) throws {
        do { try action() }
        catch {
            guard errorCode(error) == code else {
                throw ADRNativeError.rejected("local_vault_test_line_\(line)_wrong_error_" + errorCode(error))
            }
            return
        }
        throw ADRNativeError.rejected("local_vault_test_line_\(line)_expected_" + code)
    }

    private static func rows(_ value: [String: Any], _ key: String = "entries") throws -> [[String: Any]] {
        guard let result = value[key] as? [[String: Any]] else {
            throw ADRNativeError.rejected("local_vault_test_metadata_shape")
        }
        return result
    }

    private static func mode(_ url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw ADRNativeError.rejected("local_vault_test_stat") }
        try require(info.st_uid == geteuid())
        return info.st_mode & 0o7777
    }

    private static func writeFixture(_ bytes: Data, _ url: URL) throws {
        try bytes.write(to: url, options: .atomic)
        guard chmod(url.path, 0o600) == 0 else { throw ADRNativeError.rejected("local_vault_test_chmod") }
    }

    private static func roundTrip() throws {
        try fixture { root in
            let first = environment(1), second = service(2), legacy = SyntheticLegacy()
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try expect("local_vault_missing") { _ = try vault.credentialData(first.id) }
            let empty = try rows(vault.storageStatus(ids: [first.id]))
            try require(empty[0]["state"] as? String == "missing")
            try require(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
            try vault.storeEnvironment(first)
            try vault.store(second)
            try require(try vault.loadEnvironment(first.id).secret == first.secret)
            let loadedService = try JSONDecoder().decode(
                CredentialProfile.self, from: vault.credentialData(second.id)
            )
            try require(loadedService.secret == second.secret)
            let keyURL = directory(root).appendingPathComponent(LocalVault.keyName)
            let key = try Data(contentsOf: keyURL)
            try require(key.count == 32)
            try require(try mode(root) == 0o700 && mode(directory(root)) == 0o700)
            for file in try FileManager.default.contentsOfDirectory(
                at: directory(root), includingPropertiesForKeys: nil
            ) {
                try require(try mode(file) == 0o600)
                let raw = try Data(contentsOf: file)
                for hidden in [first.secret, first.name, first.env_name, second.secret, second.name] {
                    try require(raw.range(of: Data(hidden.utf8)) == nil)
                }
            }
            let original = try Data(contentsOf: record(root, first.id))
            try expect("local_vault_exists") { try vault.storeEnvironment(first) }
            try require(try Data(contentsOf: record(root, first.id)) == original)
            let reopened = Vault(profileDirectory: root, legacySource: legacy)
            try require(try reopened.loadEnvironment(first.id).secret == first.secret)
            try require(try Data(contentsOf: keyURL) == key)
            let status = try reopened.storageStatus(ids: [first.id, second.id, id(3)])
            let entries = try rows(status)
            try require(entries.map { $0["state"] as? String } == ["available", "available", "missing"])
            try require(entries[0]["kind"] as? String == "environment")
            try require(entries[1]["kind"] as? String == "service")
            try require(status["legacy_status"] as? String == "not_checked")
            let metadata = try JSONSerialization.data(withJSONObject: status)
            for hidden in [first.secret, first.name, first.env_name, second.secret, root.path] {
                for variant in VaultProcess.variants(hidden) {
                    try require(metadata.range(of: Data(variant.utf8)) == nil)
                }
            }
            try reopened.remove(first.id)
            try reopened.remove(first.id)
            try expect("credential_removed_during_save") { try reopened.storeEnvironment(first) }
            try expect("local_vault_missing") { _ = try vault.loadEnvironment(first.id) }
            try require(try Data(contentsOf: keyURL) == key)
            try require(try JSONDecoder().decode(
                CredentialProfile.self, from: vault.credentialData(second.id)
            ).secret == second.secret)
            try require(legacy.readIDs.isEmpty)
            let echo = HTTPPacket(
                status: 200, headers: ["content-type": "application/json"],
                body: try JSONSerialization.data(withJSONObject: ["other": first.secret])
            )
            try expect("credential_echo_blocked") {
                _ = try second.safeResult(echo, protectionVariants: VaultProcess.variants(first.secret))
            }
            try require(try FileManager.default.contentsOfDirectory(atPath: directory(root).path)
                .allSatisfy { !$0.hasPrefix(".tmp-") })
        }
    }

    private static func isolation() throws {
        try fixture { root in
            let other = root.appendingPathComponent("other-profile", isDirectory: true)
            try FileManager.default.createDirectory(
                at: other, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
            )
            let value = environment(1), legacy = SyntheticLegacy()
            let first = Vault(profileDirectory: root, legacySource: legacy)
            let second = Vault(profileDirectory: other, legacySource: legacy)
            try first.storeEnvironment(value)
            try expect("local_vault_missing") { _ = try second.loadEnvironment(value.id) }
            try second.storeEnvironment(value)
            let raw = try Data(contentsOf: record(root, value.id))
            try require(try raw != Data(contentsOf: record(other, value.id)))
            try require(try Data(contentsOf: directory(root).appendingPathComponent(LocalVault.keyName))
                != Data(contentsOf: directory(other).appendingPathComponent(LocalVault.keyName)))
            // Ciphertext cannot be moved to another ID, even with the same key.
            try writeFixture(raw, record(root, id(2)))
            try expect("local_vault_corrupt") { _ = try first.credentialData(id(2)) }
            // Nor does ciphertext alone work in an independently keyed profile.
            try writeFixture(raw, record(other, value.id))
            try expect("local_vault_corrupt") { _ = try second.loadEnvironment(value.id) }
            try require(try first.loadEnvironment(value.id).secret == value.secret)
            try require(legacy.readIDs.isEmpty)
        }
    }

    private static func corruption() throws {
        try fixture { root in
            let value = environment(1)
            let legacy = SyntheticLegacy([value.id: try JSONEncoder().encode(value)])
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            let local = LocalVault(profileDirectory: root)
            try vault.storeEnvironment(value)
            let url = record(root, value.id), original = try Data(contentsOf: record(root, value.id))
            for offset in [0, 8, original.count - 1] {
                var damaged = original
                damaged[offset] ^= 0xff
                try writeFixture(damaged, url)
                try expect("local_vault_corrupt") { _ = try vault.loadEnvironment(value.id) }
                try expect("local_vault_corrupt") { try vault.storeEnvironment(value) }
                let result = try rows(vault.migrateLegacy(ids: [value.id]), "results")
                try require(result[0]["reason_code"] as? String == "local_vault_corrupt")
                try require(try Data(contentsOf: url) == damaged)
                try require(legacy.readIDs.isEmpty)
            }
            try writeFixture(Data(original.prefix(10)), url)
            try expect("local_vault_corrupt") { _ = try vault.credentialData(value.id) }
            try writeFixture(Data(repeating: 0, count: LocalVault.maximumRecordBytes + 1), url)
            try expect("local_vault_too_large") { _ = try vault.credentialData(value.id) }
            try require(try rows(vault.storageStatus(ids: [value.id]))[0]["state"] as? String == "corrupt")
            try expect("local_vault_too_large") {
                try local.save(id: id(2), data: Data(repeating: 1, count: LocalVault.maximumPlaintextBytes + 1))
            }
            try local.save(id: id(2), data: Data(repeating: 1, count: LocalVault.maximumPlaintextBytes))
            try require(try local.load(id: id(2)).count == LocalVault.maximumPlaintextBytes)
            try expect("local_vault_corrupt") { _ = try vault.credentialData(id(2)) }
            try expect("local_vault_corrupt") { try vault.storeEnvironment(environment(2)) }
            try local.save(id: id(3), data: JSONEncoder().encode(environment(4)))
            try expect("local_vault_corrupt") { _ = try vault.loadEnvironment(id(3)) }
            for invalid in ["", "../key.v1", id(1) + "\n", String(repeating: "a", count: 33), id(1) + "\0"] {
                try expect("invalid_credential_id") { _ = try local.load(id: invalid) }
                try expect("invalid_credential_id") { try local.save(id: invalid, data: Data([1])) }
                try expect("invalid_credential_id") { try local.remove(id: invalid) }
                try expect("invalid_credential_id") { _ = try vault.migrateLegacy(ids: [invalid]) }
            }
            try expect("invalid_vault_ids") { _ = try vault.migrateLegacy(ids: [id(1), id(1)]) }
            try expect("invalid_vault_ids") { _ = try vault.storageStatus(ids: (1...129).map(id)) }
            try require(legacy.readIDs.isEmpty)
            // Explicit local deletion remains possible for a corrupt record.
            try vault.remove(value.id)
            try expect("local_vault_missing") { _ = try vault.credentialData(value.id) }
        }
    }

    private static func keyLoss() throws {
        try fixture { root in
            let local = LocalVault(profileDirectory: root), value = environment(1)
            let encoded = try JSONEncoder().encode(value)
            try local.save(id: value.id, data: encoded)
            let keyURL = directory(root).appendingPathComponent(LocalVault.keyName)
            let key = try Data(contentsOf: keyURL), original = try Data(contentsOf: record(root, value.id))
            try FileManager.default.removeItem(at: keyURL)
            try expect("local_vault_key_missing") { _ = try local.load(id: value.id) }
            try expect("local_vault_key_missing") { try local.save(id: id(2), data: Data([1])) }
            try require(!FileManager.default.fileExists(atPath: keyURL.path))
            try require(try Data(contentsOf: record(root, value.id)) == original)
            for bytes in [Data(), Data(repeating: 1, count: 31), Data(repeating: 1, count: 33)] {
                try writeFixture(bytes, keyURL)
                try expect("local_vault_key_invalid") { _ = try local.load(id: value.id) }
                try expect("local_vault_key_invalid") { try local.save(id: id(2), data: Data([1])) }
                try require(try Data(contentsOf: keyURL) == bytes)
            }
            try writeFixture(Data(repeating: 0, count: 32), keyURL)
            try expect("local_vault_corrupt") { _ = try local.load(id: value.id) }
            try writeFixture(key, keyURL)
            try require(try local.load(id: value.id) == encoded)
            try FileManager.default.removeItem(at: keyURL)
            try local.remove(id: value.id)
            // Unknown files or interrupted writes also prevent key replacement.
            try writeFixture(Data([1]), directory(root).appendingPathComponent(".tmp-interrupted"))
            try expect("local_vault_key_missing") { try local.save(id: id(2), data: Data([1])) }
            try require(!FileManager.default.fileExists(atPath: keyURL.path))
        }
    }

    private static func permissions() throws {
        try fixture { root in
            let local = LocalVault(profileDirectory: root)
            try local.save(id: id(1), data: Data([1]))
            let key = directory(root).appendingPathComponent(LocalVault.keyName)
            let targets: [(URL, mode_t)] = [
                (root, 0o700), (directory(root), 0o700), (key, 0o600),
                (record(root, id(1)), 0o600), (directory(root).appendingPathComponent(LocalVault.lockName), 0o600),
            ]
            for (target, originalMode) in targets {
                try require(chmod(target.path, originalMode | 0o040) == 0)
                try expect("local_vault_permissions") { _ = try local.load(id: id(1)) }
                try expect("local_vault_permissions") { try local.save(id: id(1), data: Data([1])) }
                try require(chmod(target.path, originalMode) == 0)
            }
            // ACLs must not bypass otherwise-private POSIX mode bits.
            try chmodFixture(["+a", "everyone allow read", key.path])
            try require(try mode(key) == 0o600)
            try expect("local_vault_permissions") { _ = try local.load(id: id(1)) }
            try chmodFixture(["-N", key.path])
            try require(try local.load(id: id(1)) == Data([1]))
        }
    }

    private static func chmodFixture(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        try require(process.terminationStatus == 0)
    }

    private static func directorySymlinks() throws {
        try expect("local_vault_unsafe_path") {
            try LocalVault(profileDirectory: nil).save(id: id(1), data: Data([1]))
        }
        try expect("local_vault_unsafe_path") {
            _ = try LocalVault(profileDirectory: URL(string: "https://example.com/not-a-profile")).load(id: id(1))
        }
        try fixture { root in
            let real = root.appendingPathComponent("real", isDirectory: true)
            let child = real.appendingPathComponent("child", isDirectory: true)
            try FileManager.default.createDirectory(
                at: child, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
            let alias = root.appendingPathComponent("alias", isDirectory: true)
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
            for profile in [alias, alias.appendingPathComponent("child", isDirectory: true)] {
                let local = LocalVault(profileDirectory: profile)
                try expect("local_vault_unsafe_path") { try local.save(id: id(1), data: Data([1])) }
                try expect("local_vault_unsafe_path") { _ = try local.load(id: id(1)) }
                try expect("local_vault_unsafe_path") { try local.remove(id: id(1)) }
            }
            try FileManager.default.createSymbolicLink(at: directory(root), withDestinationURL: child)
            let local = LocalVault(profileDirectory: root)
            try expect("local_vault_unsafe_path") { try local.save(id: id(1), data: Data([1])) }
            try expect("local_vault_unsafe_path") { _ = try local.load(id: id(1)) }
            try require(try FileManager.default.contentsOfDirectory(atPath: child.path).isEmpty)
        }
    }

    private static func unsafeFiles() throws {
        try fixture { root in
            let local = LocalVault(profileDirectory: root)
            try local.save(id: id(1), data: Data([1]))
            let outside = root.appendingPathComponent("synthetic-target")
            let untouched = Data("synthetic-target-must-not-be-read-or-modified".utf8)
            try writeFixture(untouched, outside)
            let key = directory(root).appendingPathComponent(LocalVault.keyName)
            let lock = directory(root).appendingPathComponent(LocalVault.lockName)
            for target in [key, record(root, id(1)), lock] {
                let original = try Data(contentsOf: target)
                try FileManager.default.removeItem(at: target)
                try FileManager.default.createSymbolicLink(at: target, withDestinationURL: outside)
                try expect("local_vault_unsafe_path") { _ = try local.load(id: id(1)) }
                try expect("local_vault_unsafe_path") { try local.save(id: id(1), data: Data([2])) }
                if target != key {
                    try expect("local_vault_unsafe_path") { try local.remove(id: id(1)) }
                }
                try require(try Data(contentsOf: outside) == untouched)
                try FileManager.default.removeItem(at: target)
                try writeFixture(original, target)
            }
            let target = record(root, id(2))
            try require(link(outside.path, target.path) == 0)
            try expect("local_vault_unsafe_path") { _ = try local.load(id: id(2)) }
            try expect("local_vault_unsafe_path") { try local.remove(id: id(2)) }
            try FileManager.default.removeItem(at: target)
            try require(mkfifo(target.path, 0o600) == 0)
            try expect("local_vault_unsafe_path") { _ = try local.load(id: id(2)) }
            try expect("local_vault_unsafe_path") { try local.save(id: id(2), data: Data([1])) }
            try FileManager.default.removeItem(at: target)
            try FileManager.default.createDirectory(
                at: target, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
            )
            try expect("local_vault_unsafe_path") { _ = try local.load(id: id(2)) }
            try FileManager.default.removeItem(at: target)
            try FileManager.default.removeItem(at: lock)
            try require(mkfifo(lock.path, 0o600) == 0)
            try expect("local_vault_unsafe_path") { _ = try local.load(id: id(1)) }
            try require(try Data(contentsOf: outside) == untouched)
        }
    }

    private static func concurrency() throws {
        try fixture { root in
            let local = LocalVault(profileDirectory: root), first = environment(1), second = service(2)
            let legacy = SyntheticLegacy()
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try vault.storeEnvironment(first)
            try vault.store(second)
            let descriptor = open(directory(root).appendingPathComponent(LocalVault.lockName).path, O_RDWR | O_NOFOLLOW)
            try require(descriptor >= 0)
            defer { close(descriptor) }
            // An independently held reader must not block any immutable read.
            // Keep it held for the entire batch: exclusive-read code fails this
            // test deterministically, even on a single-core scheduler.
            try require(flock(descriptor, LOCK_SH | LOCK_NB) == 0)
            let failuresLock = NSLock()
            var failed = false
            DispatchQueue.concurrentPerform(iterations: 12) { index in
                let reopened = Vault(profileDirectory: root, legacySource: legacy)
                do {
                    for _ in 0..<8 {
                        switch index % 3 {
                        case 0: try require(try reopened.loadEnvironment(first.id).secret == first.secret)
                        case 1:
                            let status = try rows(reopened.storageStatus(ids: [first.id, second.id]))
                            try require(status.allSatisfy { $0["state"] as? String == "available" })
                        default:
                            let result = try reopened.checkText(
                                first.secret + second.secret, environmentIDs: [first.id],
                                serviceIDs: [second.id], protectOutput: true
                            )
                            try require(result["matched"] as? Bool == true)
                        }
                    }
                } catch { failuresLock.lock(); failed = true; failuresLock.unlock() }
            }
            try require(!failed)
            try require(flock(descriptor, LOCK_UN) == 0)
            DispatchQueue.concurrentPerform(iterations: 8) { index in
                let reopened = LocalVault(profileDirectory: root)
                do { try reopened.save(id: id(index + 10), data: Data([UInt8(index)])) }
                catch { failuresLock.lock(); failed = true; failuresLock.unlock() }
            }
            try require(!failed)
            for index in 0..<8 {
                try require(try local.load(id: id(index + 10)) == Data([UInt8(index)]))
            }
            try require(try FileManager.default.contentsOfDirectory(atPath: directory(root).path)
                .allSatisfy { !$0.hasPrefix(".tmp-") })
            try require(legacy.readIDs.isEmpty)
        }
    }

    private static func lockWaiting() throws {
        try fixture { root in
            let local = LocalVault(profileDirectory: root), first = environment(1)
            let vault = Vault(profileDirectory: root, legacySource: SyntheticLegacy())
            try vault.storeEnvironment(first)
            let descriptor = open(directory(root).appendingPathComponent(LocalVault.lockName).path, O_RDWR | O_NOFOLLOW)
            try require(descriptor >= 0)
            defer { close(descriptor) }
            try require(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
            let started = DispatchSemaphore(value: 0)
            let reader = Work {
                started.signal()
                try require(try vault.loadEnvironment(first.id).secret == first.secret)
                try require(try rows(vault.storageStatus(ids: [first.id]))[0]["state"] as? String == "available")
                try require(try vault.checkText(
                    first.secret, environmentIDs: [first.id], serviceIDs: []
                )["matched"] as? Bool == true)
            }
            defer { flock(descriptor, LOCK_UN); _ = try? reader.get() }
            try require(started.wait(timeout: .now() + 2) == .success)
            try require(!reader.finished(within: 0.05))
            try require(flock(descriptor, LOCK_UN) == 0)
            try reader.get()

            try require(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
            let start = ProcessInfo.processInfo.systemUptime
            try expect("local_vault_busy") { _ = try local.load(id: first.id) }
            let elapsed = ProcessInfo.processInfo.systemUptime - start
            try require(elapsed >= 0.45 && elapsed < 2)
            try expect("local_vault_busy") { try local.save(id: id(2), data: Data([1])) }
            try expect("local_vault_busy") { try local.remove(id: first.id) }
            let status = try rows(vault.storageStatus(ids: [first.id]))
            try require(status[0]["state"] as? String == "unavailable")
            try require(status[0]["reason_code"] as? String == "local_vault_busy")
            try expect("local_vault_busy") {
                _ = try vault.checkText("ordinary text", environmentIDs: [first.id], serviceIDs: [])
            }
            try require(flock(descriptor, LOCK_UN) == 0)
            try require(try vault.loadEnvironment(first.id).secret == first.secret)
            try expect("local_vault_missing") { _ = try local.load(id: id(2)) }
        }
    }

    private static func migration() throws {
        try fixture { root in
            let first = environment(1), second = service(2), denied = environment(3)
            let originals = [
                first.id: try JSONEncoder().encode(first), second.id: try JSONEncoder().encode(second),
                denied.id: try JSONEncoder().encode(denied), id(5): Data("invalid-synthetic-json".utf8),
                id(6): try JSONEncoder().encode(environment(7)), // mismatched ID
            ]
            let legacy = SyntheticLegacy(originals, failures: [denied.id: "legacy_keychain_cancelled"])
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try require(try rows(vault.storageStatus(ids: [first.id]))[0]["state"] as? String == "missing")
            try require(legacy.readIDs.isEmpty)
            let result = try vault.migrateLegacy(ids: (1...6).map(id))
            let entries = try rows(result, "results")
            try require(entries.map { $0["status"] as? String }
                == ["migrated", "migrated", "failed", "failed", "failed", "failed"])
            try require(entries[2]["reason_code"] as? String == "legacy_keychain_cancelled")
            try require(entries[3]["reason_code"] as? String == "legacy_keychain_missing")
            try require(entries[4]["reason_code"] as? String == "legacy_credential_invalid")
            try require(entries[5]["reason_code"] as? String == "legacy_credential_invalid")
            try require(result["keychain_originals_retained"] as? Bool == true)
            try require(legacy.originals == originals)
            try require(try vault.loadEnvironment(first.id).secret == first.secret)
            let count = legacy.readIDs.count
            let again = try rows(vault.migrateLegacy(ids: [first.id, second.id]), "results")
            try require(again.allSatisfy { $0["status"] as? String == "already_local" })
            try require(legacy.readIDs.count == count)
            let metadata = try JSONSerialization.data(withJSONObject: result)
            for hidden in [first.secret, first.name, first.env_name, second.secret, root.path] {
                for variant in VaultProcess.variants(hidden) {
                    try require(metadata.range(of: Data(variant.utf8)) == nil)
                }
            }
            try vault.remove(first.id)
            try expect("local_vault_missing") { _ = try vault.loadEnvironment(first.id) }
            try require(legacy.readIDs.count == count)
            // Retained originals permit explicit recovery; deletion never
            // automatically resurrects a Keychain entry.
            try require(try rows(vault.migrateLegacy(ids: [first.id]), "results")[0]["status"] as? String == "migrated")
            try require(legacy.originals == originals)
            // Even a misbehaving legacy adapter's error string is not trusted
            // as an IPC diagnostic (including JSON-escaped multiline values).
            let unsafeError = SyntheticLegacy(failures: [id(8): first.secret])
            let safeFailure = try Vault(profileDirectory: root, legacySource: unsafeError)
                .migrateLegacy(ids: [id(8)])
            try require(try rows(safeFailure, "results")[0]["reason_code"] as? String == "local_vault_unavailable")
            let failureBytes = try JSONSerialization.data(withJSONObject: safeFailure)
            for variant in VaultProcess.variants(first.secret) {
                try require(failureBytes.range(of: Data(variant.utf8)) == nil)
            }
        }
    }

    private static func failedMigration() throws {
        try fixture { root in
            let first = environment(1), second = environment(2)
            let originals = [first.id: try JSONEncoder().encode(first), second.id: try JSONEncoder().encode(second)]
            let legacy = SyntheticLegacy(originals)
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try vault.storeEnvironment(first)
            let file = record(root, first.id), raw = try Data(contentsOf: record(root, first.id))
            let keyURL = directory(root).appendingPathComponent(LocalVault.keyName)
            let key = try Data(contentsOf: keyURL)
            try FileManager.default.removeItem(at: keyURL)
            let result = try rows(vault.migrateLegacy(ids: [first.id, second.id]), "results")
            try require(result.allSatisfy { $0["status"] as? String == "failed" })
            try require(result.allSatisfy { $0["reason_code"] as? String == "local_vault_key_missing" })
            try require(legacy.readIDs == [second.id]) // never fallback for an existing record
            try require(legacy.originals == originals)
            try require(try Data(contentsOf: file) == raw)
            try require(!FileManager.default.fileExists(atPath: record(root, second.id).path))
            try require(!FileManager.default.fileExists(atPath: keyURL.path))
            try writeFixture(key, keyURL)
            let retried = try rows(vault.migrateLegacy(ids: [first.id, second.id]), "results")
            try require(retried.map { $0["status"] as? String } == ["already_local", "migrated"])
            try require(legacy.originals == originals)
            try require(try Data(contentsOf: file) == raw)
            try require(try vault.loadEnvironment(second.id).secret == second.secret)
        }
    }

    private static func requestValidation() throws {
        try fixture { root in
            let legacy = SyntheticLegacy()
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            let future = Date().timeIntervalSince1970 + 60
            let malformed: [Any] = [NSNull(), true, 7, id(1), [id(1), 7] as [Any]]
            for value in malformed {
                try expect("invalid_vault_ids") { _ = try vault.storageStatus(arguments: ["ids": value]) }
                try expect("invalid_vault_ids") {
                    _ = try vault.beginLegacyMigration(arguments: ["ids": value, "expires_at": future])
                }
                for key in ["environment_ids", "service_ids"] {
                    var arguments: [String: Any] = ["text": "ordinary", "environment_ids": [], "service_ids": []]
                    arguments[key] = value
                    try expect("invalid_text_check") { _ = try vault.checkText(arguments: arguments) }
                }
            }
            try expect("invalid_vault_ids") { _ = try vault.storageStatus(arguments: [:]) }
            try expect("invalid_vault_ids") {
                _ = try vault.beginLegacyMigration(arguments: ["expires_at": future])
            }
            for ids in [[id(1), id(1)], (1...129).map(id)] {
                try expect("invalid_vault_ids") { _ = try vault.storageStatus(arguments: ["ids": ids]) }
                try expect("invalid_vault_ids") {
                    _ = try vault.beginLegacyMigration(arguments: ["ids": ids, "expires_at": future])
                }
            }
            for invalid in ["", "../key.v1", String(repeating: "A", count: 32), id(1) + "\n", id(1) + "\0"] {
                try expect("invalid_credential_id") {
                    _ = try vault.storageStatus(arguments: ["ids": [id(1), invalid]])
                }
                try expect("invalid_credential_id") {
                    _ = try vault.beginLegacyMigration(arguments: ["ids": [id(1), invalid], "expires_at": future])
                }
            }
            let invalidExpiry: [Any] = [NSNull(), true, "123", [future], Double.nan, Double.infinity, -Double.infinity]
            for value in invalidExpiry {
                try expect("invalid_vault_migration_expiry") {
                    _ = try vault.beginLegacyMigration(arguments: ["ids": [id(1)], "expires_at": value])
                }
            }
            try expect("invalid_vault_migration_expiry") {
                _ = try vault.beginLegacyMigration(arguments: ["ids": [id(1)]])
            }
            try expect("vault_migration_expired") {
                _ = try vault.beginLegacyMigration(arguments: ["ids": [id(1)], "expires_at": 0])
            }
            for ids in [[id(1), id(1)], (1...65).map(id), [id(1), "bad-id"]] {
                for key in ["environment_ids", "service_ids"] {
                    var arguments: [String: Any] = ["text": "ordinary", "environment_ids": [], "service_ids": []]
                    arguments[key] = ids
                    try expect("invalid_text_check") { _ = try vault.checkText(arguments: arguments) }
                }
            }
            for key in ["text", "environment_ids", "service_ids"] {
                var arguments: [String: Any] = ["text": "", "environment_ids": [], "service_ids": []]
                arguments.removeValue(forKey: key)
                try expect("invalid_text_check") { _ = try vault.checkText(arguments: arguments) }
            }
            for purpose in [NSNull(), 1, "unknown"] as [Any] {
                try expect("invalid_text_check") {
                    _ = try vault.checkText(arguments: [
                        "text": "", "environment_ids": [], "service_ids": [], "purpose": purpose,
                    ])
                }
            }
            try expect("invalid_text_check") {
                _ = try vault.checkText("", environmentIDs: [id(1)], serviceIDs: [id(1)])
            }
            try expect("invalid_text_check") {
                _ = try vault.checkText(String(repeating: "x", count: 256 * 1024 + 1), environmentIDs: [], serviceIDs: [])
            }
            try require(try vault.checkText(arguments: [
                "text": "", "environment_ids": [], "service_ids": [],
            ])["matched"] as? Bool == false)

            let oldEpoch = vault.legacyMigrationEpoch()
            vault.cancelLegacyMigrations()
            let currentEpoch = vault.legacyMigrationEpoch()
            try expect("vault_migration_cancelled") {
                _ = try vault.beginLegacyMigration(
                    arguments: ["ids": [id(1)], "expires_at": future], expectedEpoch: oldEpoch
                )
            }
            let current = try vault.beginLegacyMigration(
                arguments: ["ids": [String](), "expires_at": future], expectedEpoch: currentEpoch
            )
            vault.cancelLegacyMigrations(expectedEpoch: oldEpoch) // stale core death is a no-op
            try require(try rows(vault.migrateLegacy(identity: current), "results").isEmpty)

            let queued = try vault.beginLegacyMigration(arguments: ["ids": [id(1)], "expires_at": future])
            vault.cancelLegacyMigrations()
            try expect("vault_migration_busy") {
                _ = try vault.beginLegacyMigration(ids: [], expiresAt: future)
            }
            try expect("vault_migration_cancelled") { _ = try vault.migrateLegacy(identity: queued) }
            try expect("vault_migration_cancelled") { _ = try vault.migrateLegacy(identity: queued) }

            let deleted = try vault.beginLegacyMigration(ids: [id(1)], expiresAt: future)
            try vault.remove(id(1))
            let deletedResult = try rows(vault.migrateLegacy(identity: deleted), "results")
            try require(deletedResult[0]["reason_code"] as? String == "vault_migration_invalidated")

            let expiry = Date().timeIntervalSince1970 + 0.03
            let expired = try vault.beginLegacyMigration(ids: [id(1)], expiresAt: expiry)
            try waitPast(expiry)
            try expect("vault_migration_busy") {
                _ = try vault.beginLegacyMigration(ids: [], expiresAt: future)
            }
            try expect("vault_migration_expired") { _ = try vault.migrateLegacy(identity: expired) }
            try require(try rows(vault.migrateLegacy(ids: []), "results").isEmpty)
            try require(legacy.readIDs.isEmpty)
            try require(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
        }
    }

    private static func migrationLifetime() throws {
        for interruption in ["expiry", "delete", "cancel"] {
            try fixture { root in
                let first = environment(1), delayed = environment(2), last = service(3)
                let originals = [
                    first.id: try JSONEncoder().encode(first), delayed.id: try JSONEncoder().encode(delayed),
                    last.id: try JSONEncoder().encode(last),
                ]
                let source = SyntheticLegacy(originals)
                let legacy = DelayedLegacy(source, delayedID: delayed.id)
                let vault = Vault(profileDirectory: root, legacySource: legacy)
                let epoch = vault.legacyMigrationEpoch()
                let expiry = Date().timeIntervalSince1970 + (interruption == "expiry" ? 2 : 60)
                let identity = try vault.beginLegacyMigration(
                    ids: [first.id, delayed.id, last.id], expiresAt: expiry, expectedEpoch: epoch
                )
                let worker = Work { try vault.migrateLegacy(identity: identity) }
                defer { legacy.release.signal(); _ = try? worker.get(timeout: 12) }
                try require(legacy.entered.wait(timeout: .now() + 1.5) == .success)
                try require(try vault.loadEnvironment(first.id).secret == first.secret)
                let expected: String
                switch interruption {
                case "expiry":
                    try waitPast(expiry)
                    expected = "vault_migration_expired"
                case "delete":
                    // This succeeds while the interactive read is outstanding,
                    // even though there is not yet a local copy to delete.
                    try vault.remove(delayed.id)
                    expected = "vault_migration_invalidated"
                default:
                    vault.cancelLegacyMigrations(expectedEpoch: epoch)
                    expected = "vault_migration_cancelled"
                }
                try expect("vault_migration_busy") {
                    _ = try vault.beginLegacyMigration(ids: [last.id], expiresAt: Date().timeIntervalSince1970 + 60)
                }
                // Reusing the same identity cannot run a second reader or clear
                // the first worker's gate.
                try expect("vault_migration_busy") { _ = try vault.migrateLegacy(identity: identity) }
                try require(!worker.finished(within: 0.01))
                try require(source.readIDs == [first.id, delayed.id])
                legacy.release.signal()
                let outcome = try worker.get()
                let result = try rows(outcome, "results")
                try require(result[0]["status"] as? String == "migrated")
                try require(result[1]["status"] as? String == "failed")
                try require(result[1]["reason_code"] as? String == expected)
                if interruption == "delete" {
                    try require(result[2]["status"] as? String == "migrated")
                    try require(source.readIDs == [first.id, delayed.id, last.id])
                } else {
                    try require(result[2]["status"] as? String == "failed")
                    try require(result[2]["reason_code"] as? String == expected)
                    try require(source.readIDs == [first.id, delayed.id])
                    try expect("local_vault_missing") { _ = try vault.loadService(last.id) }
                }
                try expect("local_vault_missing") { _ = try vault.loadEnvironment(delayed.id) }
                try require(try vault.loadEnvironment(first.id).secret == first.secret)
                try require(outcome["keychain_originals_retained"] as? Bool == true)
                try require(source.originals == originals)
                let metadata = try JSONSerialization.data(withJSONObject: outcome)
                for secret in [first.secret, delayed.secret, last.secret] {
                    try require(metadata.range(of: Data(secret.utf8)) == nil)
                }
                let readIDs = source.readIDs
                try expect("vault_migration_cancelled") { _ = try vault.migrateLegacy(identity: identity) }
                try require(try rows(vault.migrateLegacy(ids: []), "results").isEmpty)
                try require(source.readIDs == readIDs)
            }
        }
    }

    private static func migrationPublication() throws {
        try fixture { root in
            let delayed = environment(1), seed = environment(9)
            let source = SyntheticLegacy([delayed.id: try JSONEncoder().encode(delayed)])
            let legacy = DelayedLegacy(source, delayedID: delayed.id)
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try vault.storeEnvironment(seed)
            let descriptor = open(directory(root).appendingPathComponent(LocalVault.lockName).path, O_RDWR | O_NOFOLLOW)
            try require(descriptor >= 0)
            defer { close(descriptor) }
            let expiry = Date().timeIntervalSince1970 + 2
            let identity = try vault.beginLegacyMigration(ids: [delayed.id], expiresAt: expiry)
            let worker = Work { try vault.migrateLegacy(identity: identity) }
            defer { flock(descriptor, LOCK_UN); legacy.release.signal(); _ = try? worker.get(timeout: 12) }
            try require(legacy.entered.wait(timeout: .now() + 1) == .success)
            try require(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
            // Return success with less time left than the filesystem-lock wait.
            // The validity check must abort that wait, without replaying a read.
            try waitPast(expiry - 0.25)
            legacy.release.signal()
            try require(legacy.returning.wait(timeout: .now() + 1) == .success)
            let result = try rows(worker.get(), "results")
            try require(result[0]["reason_code"] as? String == "vault_migration_expired")
            try require(source.readIDs == [delayed.id])
            try require(!FileManager.default.fileExists(atPath: record(root, delayed.id).path))
            try require(flock(descriptor, LOCK_UN) == 0)
            try require(try vault.loadEnvironment(seed.id).secret == seed.secret)

            // Exercise the final guard after encrypted temporary-file fsync,
            // not merely the pre-lock guard. A rejected publication cleans its
            // temporary file and preserves both existing key and records.
            let local = LocalVault(profileDirectory: root)
            let keyURL = directory(root).appendingPathComponent(LocalVault.keyName)
            let key = try Data(contentsOf: keyURL)
            var reachedPublication = false
            try expect("vault_migration_expired") {
                try local.save(id: id(2), data: JSONEncoder().encode(environment(2))) {
                    if try FileManager.default.contentsOfDirectory(atPath: directory(root).path)
                        .contains(where: { $0.hasPrefix(".tmp-") }) {
                        reachedPublication = true
                        throw ADRNativeError.rejected("vault_migration_expired")
                    }
                }
            }
            try require(reachedPublication)
            try expect("local_vault_missing") { _ = try local.load(id: id(2)) }
            try require(try Data(contentsOf: keyURL) == key)
            try require(try FileManager.default.contentsOfDirectory(atPath: directory(root).path)
                .allSatisfy { !$0.hasPrefix(".tmp-") })

            // If deletion arrives just after the last publication decision, the
            // writer still owns LOCK_EX. Delete must follow it, not return early
            // for an absent record which is about to be published.
            let publishing = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
            let save = Work {
                try local.save(id: id(3), data: JSONEncoder().encode(environment(3))) {
                    if try FileManager.default.contentsOfDirectory(atPath: directory(root).path)
                        .contains(where: { $0.hasPrefix(".tmp-") }) {
                        publishing.signal()
                        try require(proceed.wait(timeout: .now() + 5) == .success)
                    }
                }
            }
            defer { proceed.signal(); _ = try? save.get() }
            try require(publishing.wait(timeout: .now() + 2) == .success)
            let deletion = Work { try vault.remove(id(3)) }
            defer { proceed.signal(); _ = try? deletion.get() }
            try require(!deletion.finished(within: 0.03))
            proceed.signal()
            try save.get()
            try deletion.get()
            try expect("local_vault_missing") { _ = try local.load(id: id(3)) }
        }
    }

    private static func environmentExecution() throws {
        try fixture { root in
            let legacy = SyntheticLegacy()
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try vault.environmentSelfTest()
            try require(legacy.readIDs.isEmpty)
        }
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func environmentProtection() throws {
        try fixture { root in
            let selected = environment(1)
            let password = EnvironmentCredential(
                id: id(2), name: "Unselected saved password", env_name: "SYNTHETIC_UNSELECTED_PASSWORD",
                secret: "moss & glass/+\"\\\nfield=73!?"
            )
            let api = CredentialProfile(
                id: id(3), name: "Protection-only API secret", origin: "https://example.com",
                auth_type: "api_key", header_name: "X-API-Key", username: "", allowed_paths: ["/"],
                secret: "api.synthetic.only/+42?&=Z"
            )
            let basic = CredentialProfile(
                id: id(4), name: "Protection-only Basic password", origin: "https://example.com",
                auth_type: "basic", header_name: "Authorization", username: "synthetic-user", allowed_paths: ["/"],
                secret: "basic synthetic /+57?"
            )
            let bearer = service(5), legacy = SyntheticLegacy()
            let vault = Vault(profileDirectory: root, legacySource: legacy)
            try vault.storeEnvironment(selected)
            try vault.storeEnvironment(password)
            try vault.store(api)
            try vault.store(basic)
            try vault.store(bearer)
            let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
            let jsonPassword = String(
                data: try JSONSerialization.data(withJSONObject: password.secret, options: .fragmentsAllowed),
                encoding: .utf8
            )!
            // Expected encodings come from their public formats, not from the
            // filtering helper under test. These are literal diagnostic output,
            // not injected values or recognizable provider-token patterns.
            let samples = [
                password.secret, api.secret, Data(api.secret.utf8).base64EncodedString(),
                api.secret.addingPercentEncoding(withAllowedCharacters: unreserved)!,
                password.secret.addingPercentEncoding(withAllowedCharacters: unreserved)!
                    .replacingOccurrences(of: "%20", with: "+"),
                String(jsonPassword.dropFirst().dropLast()),
                basic.authorization, Data("\(basic.username):\(basic.secret)".utf8).base64EncodedString(),
                Data(basic.authorization.utf8).base64EncodedString(),
                Data(bearer.authorization.utf8).base64EncodedString(),
                Data(api.secret.utf8).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: ""),
            ]
            var command = "test -n \"$\(selected.env_name)\" && test -z \"${\(password.env_name)+x}\" || exit 41; "
            for profile in [api, basic, bearer] {
                command += "if /usr/bin/env | /usr/bin/grep -F -- \(shellQuote(profile.secret)) >/dev/null; then exit 42; fi; "
            }
            for (index, sample) in samples.enumerated() {
                command += "printf '%s\\n' \(shellQuote(sample))\(index % 2 == 0 ? "" : " >&2"); "
            }
            command += "printf '%s' \"$\(selected.env_name)\""
            let result = try vault.executeEnvironment(arguments: [
                "ids": [selected.id], "protection_environment_ids": [password.id],
                "protection_service_ids": [api.id, basic.id, bearer.id],
                "command": command, "cwd": root.path, "timeout_seconds": 3,
            ])
            try require(result["exit_code"] as? Int == 0)
            try require(result["redacted"] as? Bool == true)
            try require(result["output_withheld"] as? Bool == false)
            try require(result["stdout"] as? String
                == String(repeating: "[ADR credential hidden]\n", count: (samples.count + 1) / 2) + "[ADR credential hidden]")
            try require(result["stderr"] as? String
                == String(repeating: "[ADR credential hidden]\n", count: samples.count / 2))
            let response = try JSONSerialization.data(withJSONObject: result)
            for sample in samples { try require(response.range(of: Data(sample.utf8)) == nil) }
            for sample in [basic.authorization, Data(basic.authorization.utf8).base64EncodedString()] {
                let check = try vault.checkText(arguments: [
                    "text": sample, "environment_ids": [], "service_ids": [basic.id], "purpose": "output",
                ])
                try require(check["matched"] as? Bool == true)
                try require((check["aliases"] as? [String])?.isEmpty == true)
            }

            // Both the absent-field compatibility default and an explicitly
            // empty protection context still redact every selected secret.
            var echo: [String: Any] = [
                "ids": [selected.id], "command": "printf '%s' \"$\(selected.env_name)\"",
                "cwd": root.path, "timeout_seconds": 3,
            ]
            try require(try vault.executeEnvironment(arguments: echo)["stdout"] as? String == "[ADR credential hidden]")
            echo["protection_environment_ids"] = [String]()
            echo["protection_service_ids"] = [String]()
            try require(try vault.executeEnvironment(arguments: echo)["stdout"] as? String == "[ADR credential hidden]")

            let marker = root.appendingPathComponent("command-must-not-run")
            let guarded: [String: Any] = [
                "ids": [selected.id], "command": ": > " + shellQuote(marker.path),
                "cwd": root.path, "timeout_seconds": 3,
                "protection_environment_ids": [String](), "protection_service_ids": [String](),
            ]
            let malformed: [Any] = [
                NSNull(), true, selected.id, [selected.id, 1] as [Any], [selected.id, selected.id],
                (1...65).map(id), [id(6), "../key.v1"], [String(repeating: "A", count: 32)],
                [id(6) + "\n"], [id(6) + "\0"],
            ]
            for key in ["ids", "protection_environment_ids", "protection_service_ids"] {
                for value in malformed {
                    var arguments = guarded
                    arguments[key] = value
                    try expect(key == "ids" ? "invalid_environment_command" : "invalid_environment_protection") {
                        _ = try vault.executeEnvironment(arguments: arguments)
                    }
                    try require(!FileManager.default.fileExists(atPath: marker.path))
                }
            }
            for ids in [nil, [String]()] as [[String]?] {
                var arguments = guarded
                arguments["ids"] = ids
                try expect("invalid_environment_command") { _ = try vault.executeEnvironment(arguments: arguments) }
            }
            var invalidBeforeLoad = guarded
            invalidBeforeLoad["ids"] = [id(99)] // would otherwise fail with local_vault_missing
            invalidBeforeLoad["protection_service_ids"] = [api.id, NSNull()] as [Any]
            try expect("invalid_environment_protection") {
                _ = try vault.executeEnvironment(arguments: invalidBeforeLoad)
            }
            var overlapping = guarded
            overlapping["protection_service_ids"] = [selected.id]
            try expect("invalid_environment_protection") { _ = try vault.executeEnvironment(arguments: overlapping) }

            try LocalVault(profileDirectory: root).save(id: id(66), data: Data([1]))
            let failures: [(String, String, String)] = [
                ("protection_environment_ids", id(99), "local_vault_missing"),
                ("protection_service_ids", id(99), "local_vault_missing"),
                ("protection_environment_ids", api.id, "local_vault_corrupt"),
                ("protection_service_ids", password.id, "local_vault_corrupt"),
                ("protection_environment_ids", id(66), "local_vault_corrupt"),
                ("protection_service_ids", id(66), "local_vault_corrupt"),
            ]
            for (key, id, code) in failures {
                var arguments = guarded
                arguments[key] = [id]
                try expect(code) { _ = try vault.executeEnvironment(arguments: arguments) }
                try require(!FileManager.default.fileExists(atPath: marker.path))
            }
            try require(chmod(record(root, password.id).path, 0o640) == 0)
            defer { chmod(record(root, password.id).path, 0o600) }
            var unavailable = guarded
            unavailable["protection_environment_ids"] = [password.id]
            try expect("local_vault_permissions") { _ = try vault.executeEnvironment(arguments: unavailable) }
            try require(!FileManager.default.fileExists(atPath: marker.path))
            try require(legacy.readIDs.isEmpty)
        }
    }
}
