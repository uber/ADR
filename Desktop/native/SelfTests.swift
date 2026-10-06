import Foundation

enum NativeSelfTests {
    static func require(_ condition: Bool) throws {
        if !condition { throw ADRNativeError.rejected("self_test_assertion_failed") }
    }
    static func rejects(_ action: () throws -> Void) throws {
        var failed = false
        do { try action() } catch { failed = true }
        try require(failed)
    }
    static func run() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let epoch = now.timeIntervalSince1970
        try require(ToolApprovalClock.deadline(expiresAt: epoch - 1, now: now) == nil)
        try require(ToolApprovalClock.deadline(expiresAt: epoch, now: now) == nil)
        try require(ToolApprovalClock.deadline(expiresAt: Double.nan, now: now) == nil)
        try require(ToolApprovalClock.deadline(expiresAt: Double.infinity, now: now) == nil)
        try require(ToolApprovalClock.deadline(expiresAt: "invalid", now: now) == nil)
        try require(ToolApprovalClock.deadline(expiresAt: epoch + 5, now: now) == now.addingTimeInterval(5))
        try require(ToolApprovalClock.deadline(expiresAt: epoch + 500, now: now) == now.addingTimeInterval(100))
        try require(ToolApprovalClock.deadline(expiresAt: nil, now: now) == now.addingTimeInterval(100))
        _ = try ServiceBoundary.origin("https://api.github.com")
        for origin in [
            "http://api.github.com", "https://127.0.0.1", "https://localhost",
            "https://api.github.com@evil.example", "https://api.github.com/path",
            "https://api.github.com:8443", "https://api.github.com#fragment",
        ] {
            try rejects { _ = try ServiceBoundary.origin(origin) }
        }
        try require(try ServiceBoundary.target("/repos/a/b?per_page=10", allowed: ["/repos"]) == "/repos/a/b?per_page=10")
        for path in [
            "//evil.example/path", "/repositories", "/repos/../secrets",
            "/repos/%2e%2e/secrets", "/repos%2fsecret", "/repos\\secret",
            "/repos/a\r\nInjected: header", "https://evil.example",
        ] {
            try rejects { _ = try ServiceBoundary.target(path, allowed: ["/repos"]) }
        }
        for address in [
            "127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.1.1",
            "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::ffff:127.0.0.1",
            "fe80::1", "fc00::1", "2001:db8::1",
        ] { try require(!ServiceBoundary.isPublicAddress(address)) }
        try require(ServiceBoundary.isPublicAddress("140.82.112.6"))
        try require(ServiceBoundary.isPublicAddress("2606:50c0:8000::154"))
        let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}".utf8)
        let packet = try HTTPDecoder.packet(response, eof: false)
        try require(packet?.body == Data("{}".utf8))
        let chunked = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".utf8)
        try require(try HTTPDecoder.packet(chunked, eof: false)?.body == Data("{}".utf8))
        for raw in [
            "HTTP/1.1 302 Found\r\nLocation: https://evil.example\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\ncompressed",
        ] {
            try rejects { _ = try HTTPDecoder.packet(Data(raw.utf8), eof: true) }
        }
        let profile = CredentialProfile(
            id: "01234567890123456789012345678901", name: "Synthetic", origin: "https://api.github.com",
            auth_type: "bearer", header_name: "Authorization", username: "",
            allowed_paths: ["/user"], secret: "synthetic-secret-not-used-on-network"
        )
        try profile.validate()
        let safe = HTTPPacket(status: 200, headers: [:], body: Data("{\"login\":\"synthetic\"}".utf8))
        _ = try profile.safeResult(safe)
        for body in [
            "{\"echo\":\"\(profile.secret)\"}",
            "{\"echo\":\"Bearer \(profile.secret)\"}",
            "{\"echo\":\"\(Data(profile.secret.utf8).base64EncodedString())\"}",
            "{\"echo\":\"\\u0073ynthetic-secret-not-used-on-network\"}",
        ] {
            try rejects {
                _ = try profile.safeResult(HTTPPacket(status: 200, headers: [:], body: Data(body.utf8)))
            }
        }
        try rejects {
            _ = try profile.safeResult(HTTPPacket(
                status: 200, headers: ["content-type": "text/plain; echo=\(profile.secret)"],
                body: Data("ordinary body".utf8)
            ))
        }
        try LocalVaultSelfTests.run()
    }
}
