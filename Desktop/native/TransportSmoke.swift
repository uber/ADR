// Optional live transport check. Sends only a fixed invalid synthetic token to
// GitHub's /user endpoint. Does not read Keychain or environment credentials.
import Foundation
import Darwin

@main struct TransportSmoke {
    static func main() {
        do {
            let packet = try PinnedHTTPS().get(
                host: "api.github.com", path: "/user", header: "Authorization",
                value: "Bearer adr-synthetic-invalid-token-not-a-credential",
                deadline: Date().addingTimeInterval(20)
            )
            guard packet.status == 401,
                  (try JSONSerialization.jsonObject(with: packet.body)) is [String: Any] else {
                throw ADRNativeError.rejected("unexpected_smoke_response")
            }
            print("Pinned HTTPS, hostname verification, and bounded response smoke check passed (HTTP 401)")
        } catch {
            let code = (error as? ADRNativeError)?.code ?? "transport_failed"
            fputs("Synthetic transport check failed: \(code)\n", stderr)
            exit(1)
        }
    }
}
