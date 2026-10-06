import Cocoa

// Settings navigation and current-bundle identity only. Do not probe a TCC
// database or unrelated protected files to fabricate a global FDA verdict.
@MainActor
enum ADRFileAccess {
    enum Target: String {
        case fullDiskAccess = "full_disk_access"
        case filesAndFolders = "files_and_folders"
        case privacySecurity = "privacy_security"

        var navigation: String {
            switch self {
            case .fullDiskAccess:
                return "System Settings > Privacy & Security > Full Disk Access"
            case .filesAndFolders:
                return "System Settings > Privacy & Security > Files & Folders"
            case .privacySecurity:
                return "System Settings > Privacy & Security"
            }
        }
    }

    enum RequestError: Error {
        case unsupportedTarget
    }

    static func settingsURL(for target: Target) -> URL {
        // Apple documents the modern FDA URL for macOS 13 and later. For
        // Files & Folders, use the pane and visible navigation rather than
        // relying on a separately undocumented deep-link suffix.
        let pane = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"
        return URL(string: target == .fullDiskAccess ? pane + "?Privacy_AllFiles" : pane)!
    }

    static func openSettings(
        target rawTarget: String,
        openURL: (URL) -> Bool = { NSWorkspace.shared.open($0) }
    ) throws -> [String: Any] {
        guard let target = Target(rawValue: rawTarget) else { throw RequestError.unsupportedTarget }
        var accepted = openURL(settingsURL(for: target))
        var usedFallback = false
        if !accepted && target == .fullDiskAccess {
            usedFallback = true
            accepted = openURL(settingsURL(for: .privacySecurity))
        }
        // A true result only means a URL handler accepted the request.
        // It proves neither which pane is visible nor a permission change.
        return [
            "request_accepted": accepted,
            "target": target.rawValue,
            "used_fallback": usedFallback,
            "manual_navigation": target.navigation,
            "grants_access": false,
            "full_disk_access": "not_determined",
        ]
    }

    static func identity(coreExecutable: URL? = nil, bundle: Bundle = .main) -> [String: Any] {
        // Display these locally so the user can distinguish copies/builds.
        // macOS determines responsible-code attribution; a containing
        // bundle or a parent/child relationship alone cannot prove it.
        return [
            "app_name": bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String
                ?? bundle.bundleURL.deletingPathExtension().lastPathComponent,
            "bundle_identifier": bundle.bundleIdentifier ?? "",
            "bundle_path": bundle.bundleURL.path,
            "native_executable": bundle.executableURL?.path ?? "",
            "core_executable": coreExecutable?.path ?? "",
            "responsible_code": "not_determined",
            "full_disk_access": "not_determined",
        ]
    }
}
