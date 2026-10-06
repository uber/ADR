import CryptoKit
import Darwin
import Foundation

/// Stable, content-free diagnostics. Never return a filesystem path, OS error
/// description, cryptographic key, or decoded record over native IPC.
enum LocalVaultFailure: String, Error {
    case invalidID = "invalid_credential_id"
    case missing = "local_vault_missing"
    case corrupt = "local_vault_corrupt"
    case keyMissing = "local_vault_key_missing"
    case keyInvalid = "local_vault_key_invalid"
    case unsafePath = "local_vault_unsafe_path"
    case permissions = "local_vault_permissions"
    case tooLarge = "local_vault_too_large"
    case unavailable = "local_vault_unavailable"
    case busy = "local_vault_busy"
    case exists = "local_vault_exists"
    case removed = "credential_removed_during_save"
    // Publication succeeded, but the following directory sync failed. Inspect
    // status before retrying; do not remove a potentially committed record.
    case writeUncertain = "local_vault_write_uncertain"
}

/// Native-only encrypted storage, scoped to the *same* profile as the core.
///
/// The local random key removes recurring unlock prompts. It is NOT a boundary
/// against the same OS user, a compromised native host, or theft of this whole
/// directory. No key/record values belong in browser, Python, MCP, or audit data.
///
/// Operations use descriptor-relative paths, reject symlinks (including path
/// ancestors), and take a shared-read/exclusive-write process-shared lock with
/// a short monotonic wait. There is no in-memory key cache or mutable shared
/// state. Reads never initialize/repair the vault.
final class LocalVault: @unchecked Sendable {
    static let directoryName = "local-vault"
    static let keyName = "key.v1"
    static let lockName = ".lock"
    static let recordSuffix = ".v1"
    static let maximumPlaintextBytes = 256 * 1024
    private static let header = Data("ADRVLT01".utf8)
    static let maximumRecordBytes = maximumPlaintextBytes + 8 + 12 + 16
    private static let lockWait: TimeInterval = 0.5
    private let profileDirectory: URL?

    init(profileDirectory: URL?) {
        self.profileDirectory = profileDirectory
    }

    /// Computing this URL has no filesystem or Keychain side effects. The core
    /// must prepare its 0700 profile directory before a first write.
    static var defaultProfileDirectory: URL? {
        if let path = ProcessInfo.processInfo.environment["ADR_DESKTOP_STATE_DIR"], !path.isEmpty {
            // The core may have a different working directory. Do not silently
            // reinterpret a relative/tilde override as a different profile.
            guard path.hasPrefix("/"), !path.contains("\0") else { return nil }
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/ADR Desktop", isDirectory: true)
    }

    static func validateID(_ id: String) throws {
        guard id.utf8.count == 32,
              id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw LocalVaultFailure.invalidID
        }
    }

    /// Like the previous Keychain add operation, saving is create-only. It never
    /// overwrites an existing record (even a corrupt one) or replaces a key.
    /// Migration validity is checked during lock waiting and immediately before
    /// atomic publication, not just before entering this filesystem operation.
    func save(id: String, data: Data, checkValidity: () throws -> Void = {}) throws {
        try Self.validateID(id)
        guard !data.isEmpty, data.count <= Self.maximumPlaintextBytes else {
            throw LocalVaultFailure.tooLarge
        }
        try withDirectory(create: true, exclusive: true, checkValidity: checkValidity) { directory in
            let name = id + Self.recordSuffix
            if try entry(directory, name) != nil {
                // Authenticate before reporting a duplicate, so corruption is
                // not misreported as a usable, already-saved credential.
                _ = try load(id: id, directory: directory)
                throw LocalVaultFailure.exists
            }
            let key = try encryptionKey(directory, create: true, checkValidity: checkValidity)
            let sealed: AES.GCM.SealedBox
            do {
                sealed = try AES.GCM.seal(data, using: key, authenticating: associatedData(id))
            } catch {
                throw LocalVaultFailure.unavailable
            }
            guard let combined = sealed.combined else { throw LocalVaultFailure.unavailable }
            try atomicCreate(
                Self.header + combined, name: name, directory: directory, checkValidity: checkValidity
            )
        }
    }

    func load(id: String) throws -> Data {
        try Self.validateID(id)
        return try withDirectory(create: false, exclusive: false) { try load(id: id, directory: $0) }
    }

    /// Deletion needs no decryption key, allowing explicit removal of a damaged
    /// record. It removes only this local copy; legacy Keychain is never touched.
    func remove(id: String) throws {
        try Self.validateID(id)
        do {
            try withDirectory(create: false, exclusive: true) { directory in
                let name = id + Self.recordSuffix
                guard let info = try entry(directory, name) else { return }
                try validateFile(info)
                // Open/validate ACLs and inode identity without reading bytes.
                let descriptor = try openFile(directory, name, expected: info)
                defer { close(descriptor) }
                try verifyEntry(directory, name, descriptor: descriptor)
                guard unlinkat(directory, name, 0) == 0 else { throw LocalVaultFailure.unavailable }
                guard fsync(directory) == 0 else { throw LocalVaultFailure.writeUncertain }
            }
        } catch LocalVaultFailure.missing {
            // An absent local vault/record is already deleted. No legacy lookup.
        }
    }

    private func load(id: String, directory: Int32) throws -> Data {
        guard let raw = try readFile(directory, id + Self.recordSuffix, maximum: Self.maximumRecordBytes) else {
            throw LocalVaultFailure.missing
        }
        guard raw.count > Self.header.count + 12 + 16, raw.starts(with: Self.header) else {
            throw LocalVaultFailure.corrupt
        }
        let key = try encryptionKey(directory, create: false)
        do {
            let box = try AES.GCM.SealedBox(combined: raw.dropFirst(Self.header.count))
            let plaintext = try AES.GCM.open(box, using: key, authenticating: associatedData(id))
            guard !plaintext.isEmpty, plaintext.count <= Self.maximumPlaintextBytes else {
                throw LocalVaultFailure.corrupt
            }
            return plaintext
        } catch {
            // Includes authentication failure, wrong key, truncation, version
            // tampering, and record-ID substitution. Never try legacy storage.
            throw LocalVaultFailure.corrupt
        }
    }

    private func associatedData(_ id: String) -> Data {
        Self.header + Data(("ADR Desktop credential\u{0}" + id).utf8)
    }

    private func encryptionKey(
        _ directory: Int32, create: Bool, checkValidity: () throws -> Void = {}
    ) throws -> SymmetricKey {
        let bytes: Data?
        do {
            bytes = try readFile(directory, Self.keyName, maximum: 32)
        } catch LocalVaultFailure.tooLarge {
            throw LocalVaultFailure.keyInvalid
        }
        if let bytes {
            guard bytes.count == 32 else { throw LocalVaultFailure.keyInvalid }
            return SymmetricKey(data: bytes)
        }
        // Never regenerate a missing key beside existing ciphertext, unknown
        // files, or interrupted-write remnants. Preserve recoverability.
        guard create, try isPristine(directory) else { throw LocalVaultFailure.keyMissing }
        let key = SymmetricKey(size: .bits256)
        try atomicCreate(
            key.withUnsafeBytes { Data($0) }, name: Self.keyName, directory: directory,
            checkValidity: checkValidity
        )
        return key
    }

    private func isPristine(_ directory: Int32) throws -> Bool {
        let duplicate = fcntl(directory, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else { throw LocalVaultFailure.unavailable }
        guard let stream = fdopendir(duplicate) else {
            close(duplicate); throw LocalVaultFailure.unavailable
        }
        defer { closedir(stream) }
        while true {
            errno = 0
            guard let item = readdir(stream) else {
                guard errno == 0 else { throw LocalVaultFailure.unavailable }
                return true
            }
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(item.pointee.d_namlen) + 1) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." && name != Self.lockName { return false }
        }
    }

    private func withDirectory<T>(
        create: Bool, exclusive: Bool, checkValidity: () throws -> Void = {},
        _ action: (Int32) throws -> T
    ) throws -> T {
        try checkValidity()
        let profile = try openProfile()
        defer { close(profile) }
        if create, mkdirat(profile, Self.directoryName, 0o700) != 0, errno != EEXIST {
            throw LocalVaultFailure.unavailable
        }
        let directory = openat(profile, Self.directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw pathFailure(missing: .missing) }
        defer { close(directory) }
        try validateDirectory(directory)
        try verifyEntry(profile, Self.directoryName, descriptor: directory)

        let flags = (exclusive ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            | (create ? O_CREAT : 0)
        let lock = openat(directory, Self.lockName, flags, 0o600)
        guard lock >= 0 else { throw pathFailure(missing: .unavailable) }
        defer { close(lock) }
        var info = stat()
        guard fstat(lock, &info) == 0 else { throw LocalVaultFailure.unavailable }
        try validateFile(info)
        guard info.st_size == 0 else { throw LocalVaultFailure.unsafePath }
        try rejectACL(lock)
        let deadline = ProcessInfo.processInfo.systemUptime + Self.lockWait
        while true {
            try checkValidity()
            if flock(lock, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0 { break }
            guard errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR else {
                throw LocalVaultFailure.unavailable
            }
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw LocalVaultFailure.busy }
            Thread.sleep(forTimeInterval: min(0.005, remaining))
        }
        defer { flock(lock, LOCK_UN) }
        try checkValidity()
        // Waiting must not turn previously checked path/inode/ACL state into
        // permission to use a substituted or newly unsafe filesystem object.
        try validateDirectory(profile)
        try validateDirectory(directory)
        try verifyEntry(profile, Self.directoryName, descriptor: directory)
        guard fstat(lock, &info) == 0 else { throw LocalVaultFailure.unavailable }
        try validateFile(info)
        guard info.st_size == 0 else { throw LocalVaultFailure.unsafePath }
        try rejectACL(lock)
        try verifyEntry(directory, Self.lockName, descriptor: lock)
        // Persist first-time directory creation before any key or record can be
        // acknowledged. Never silently swallow durability failures.
        if create, fsync(profile) != 0 { throw LocalVaultFailure.unavailable }
        return try action(directory)
    }

    private func openProfile() throws -> Int32 {
        guard let profileDirectory else { throw LocalVaultFailure.unsafePath }
        let path = profileDirectory.path
        guard profileDirectory.isFileURL,
              profileDirectory.host == nil || profileDirectory.host == "",
              path.hasPrefix("/"), path.utf8.count < Int(PATH_MAX), !path.contains("\0") else {
            throw LocalVaultFailure.unsafePath
        }
        let components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty, !components.contains("."), !components.contains("..") else {
            throw LocalVaultFailure.unsafePath
        }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw LocalVaultFailure.unavailable }
        do {
            for component in components {
                let child = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw pathFailure(missing: .unavailable) }
                close(descriptor); descriptor = child
                var info = stat()
                guard fstat(descriptor, &info) == 0 else { throw LocalVaultFailure.unavailable }
                // Ancestors may be system-owned, including /private/tmp's
                // sticky directory. The final profile must be owner-only.
                guard info.st_uid == geteuid() || info.st_uid == 0,
                      info.st_mode & 0o022 == 0 || (info.st_uid == 0 && info.st_mode & S_ISVTX != 0) else {
                    throw LocalVaultFailure.permissions
                }
            }
            try validateDirectory(descriptor)
            return descriptor
        } catch {
            close(descriptor); throw error
        }
    }

    private func validateDirectory(_ descriptor: Int32) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw LocalVaultFailure.unavailable }
        guard info.st_mode & S_IFMT == S_IFDIR else { throw LocalVaultFailure.unsafePath }
        guard info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o700 else {
            throw LocalVaultFailure.permissions
        }
        try rejectACL(descriptor)
    }

    private func validateFile(_ info: stat) throws {
        guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1 else {
            throw LocalVaultFailure.unsafePath
        }
        guard info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o600 else {
            throw LocalVaultFailure.permissions
        }
    }

    /// macOS ACLs can grant access beyond mode bits. Fail closed on *any*
    /// extended ACL rather than claim that chmod(0600) neutralizes one.
    private func rejectACL(_ descriptor: Int32) throws {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // Darwin reports ENOENT when this *open descriptor* has no
            // extended ACL (there is no pathname lookup in this call).
            if errno == ENOENT || errno == ENOATTR { return }
            throw LocalVaultFailure.unavailable
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var first: acl_entry_t?
        errno = 0
        let result = acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &first)
        guard result == -1, errno == EINVAL else { throw LocalVaultFailure.permissions }
    }

    private func entry(_ directory: Int32, _ name: String) throws -> stat? {
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return info }
        if errno == ENOENT { return nil }
        throw LocalVaultFailure.unavailable
    }

    private func verifyEntry(_ directory: Int32, _ name: String, descriptor: Int32) throws {
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              let named = try entry(directory, name),
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              named.st_mode & S_IFMT == opened.st_mode & S_IFMT else {
            throw LocalVaultFailure.unsafePath
        }
    }

    private func openFile(_ directory: Int32, _ name: String, expected: stat) throws -> Int32 {
        try validateFile(expected)
        // NONBLOCK prevents special-file substitution from hanging the host.
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw pathFailure(missing: .unavailable) }
        do {
            var opened = stat()
            guard fstat(descriptor, &opened) == 0 else { throw LocalVaultFailure.unavailable }
            try validateFile(opened)
            guard opened.st_ino == expected.st_ino, opened.st_dev == expected.st_dev else {
                throw LocalVaultFailure.unsafePath
            }
            try rejectACL(descriptor)
            return descriptor
        } catch {
            close(descriptor); throw error
        }
    }

    private func readFile(_ directory: Int32, _ name: String, maximum: Int) throws -> Data? {
        guard let info = try entry(directory, name) else { return nil }
        try validateFile(info)
        guard info.st_size >= 0, info.st_size <= maximum else { throw LocalVaultFailure.tooLarge }
        let descriptor = try openFile(directory, name, expected: info)
        defer { close(descriptor) }
        var bytes = [UInt8](repeating: 0, count: maximum + 1)
        var count = 0
        while count < bytes.count {
            let remaining = bytes.count - count
            let amount = bytes.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress!.advanced(by: count), remaining)
            }
            if amount == 0 { break }
            if amount < 0 {
                if errno == EINTR { continue }
                throw LocalVaultFailure.unavailable
            }
            count += amount
        }
        guard count <= maximum else { throw LocalVaultFailure.tooLarge }
        guard count == info.st_size else { throw LocalVaultFailure.corrupt }
        var after = stat()
        guard fstat(descriptor, &after) == 0 else { throw LocalVaultFailure.unavailable }
        try validateFile(after)
        try verifyEntry(directory, name, descriptor: descriptor)
        guard after.st_size == info.st_size else { throw LocalVaultFailure.corrupt }
        return Data(bytes.prefix(count))
    }

    private func atomicCreate(
        _ bytes: Data, name: String, directory: Int32, checkValidity: () throws -> Void = {}
    ) throws {
        let temporary = ".tmp-" + UUID().uuidString.lowercased()
        let descriptor = openat(
            directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600
        )
        guard descriptor >= 0 else { throw LocalVaultFailure.unavailable }
        defer { close(descriptor); unlinkat(directory, temporary, 0) }
        // Only newly created files are chmod'd; never silently repair an unsafe
        // existing directory, key, record, or lock file.
        guard fchmod(descriptor, 0o600) == 0 else { throw LocalVaultFailure.unavailable }
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw LocalVaultFailure.unavailable }
        try validateFile(info)
        try rejectACL(descriptor)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw LocalVaultFailure.unavailable }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw LocalVaultFailure.unavailable }
        try verifyEntry(directory, temporary, descriptor: descriptor)
        try checkValidity()
        // RENAME_EXCL is atomic and will not clobber a concurrently created
        // key, record, symlink, or directory. No unsafe fallback on other FSes.
        guard renameatx_np(directory, temporary, directory, name, UInt32(RENAME_EXCL)) == 0 else {
            throw errno == EEXIST ? LocalVaultFailure.exists : LocalVaultFailure.unavailable
        }
        guard fsync(directory) == 0 else { throw LocalVaultFailure.writeUncertain }
    }

    private func pathFailure(missing: LocalVaultFailure) -> LocalVaultFailure {
        switch errno {
        case ENOENT: return missing
        case ELOOP, ENOTDIR: return .unsafePath
        case EACCES, EPERM: return .permissions
        default: return .unavailable
        }
    }
}
