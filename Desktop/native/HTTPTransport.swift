import Foundation
import Network
import Security
import Darwin

enum ADRNativeError: Error {
    case rejected(String)
    var code: String {
        switch self { case .rejected(let code): return code }
    }
}

struct HTTPPacket {
    let status: Int
    let headers: [String: String]
    let body: Data
}

enum ServiceBoundary {
    static let maximumBody = 512 * 1024

    static func origin(_ value: String) throws -> (URL, String) {
        guard let parts = URLComponents(string: value), parts.scheme == "https",
              let host = parts.host?.lowercased(), host.contains("."),
              parts.port == nil || parts.port == 443,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/",
              host.range(of: "^[a-z0-9.-]+$", options: .regularExpression) != nil,
              host != "localhost", !host.hasSuffix(".localhost"), !host.hasSuffix(".local"),
              let url = URL(string: "https://\(host)") else {
            throw ADRNativeError.rejected("invalid_destination")
        }
        var address = in_addr()
        guard inet_pton(AF_INET, host, &address) != 1 else {
            throw ADRNativeError.rejected("literal_ip_not_allowed")
        }
        return (url, host)
    }

    static func target(_ value: String, allowed: [String]) throws -> String {
        guard value.utf8.count <= 2048, value.hasPrefix("/"), !value.hasPrefix("//"),
              !value.contains("\\"), !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              let parts = URLComponents(string: value), parts.host == nil, parts.scheme == nil,
              parts.fragment == nil, !parts.percentEncodedPath.contains("%"),
              parts.path.range(of: "^/[A-Za-z0-9/_@.:\\-~]*$", options: .regularExpression) != nil,
              !parts.path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }),
              allowed.contains(where: {
                  let prefix = $0 == "/" ? "/" : $0.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                  return $0 == "/" || parts.path == "/\(prefix)" || parts.path.hasPrefix("/\(prefix)/")
              }) else {
            throw ADRNativeError.rejected("path_not_permitted")
        }
        return parts.percentEncodedPath + (parts.percentEncodedQuery.map { "?\($0)" } ?? "")
    }

    static func isPublicAddress(_ value: String) -> Bool {
        let pieces = value.split(separator: ".")
        if pieces.count == 4, let a = UInt8(pieces[0]), let b = UInt8(pieces[1]),
           let c = UInt8(pieces[2]), UInt8(pieces[3]) != nil {
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if (a == 169 && b == 254) || (a == 172 && (16...31).contains(b)) ||
                (a == 192 && b == 168) || (a == 100 && (64...127).contains(b)) ||
                (a == 198 && (18...19).contains(b)) { return false }
            if (a == 192 && b == 0 && (c == 0 || c == 2)) ||
                (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113) ||
                (a == 192 && b == 88 && c == 99) { return false }
            return true
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, value, &ipv6) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        // Only global unicast, excluding special-use/transition ranges.
        guard bytes[0] & 0xe0 == 0x20 else { return false }
        if bytes[0] == 0x20 && bytes[1] == 0x02 { return false }
        if bytes[0...3].elementsEqual([0x20, 0x01, 0x0d, 0xb8]) ||
            bytes[0...3].elementsEqual([0x20, 0x01, 0x00, 0x00]) ||
            bytes[0...3].elementsEqual([0x20, 0x01, 0x00, 0x02]) { return false }
        if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0
            && [UInt8(0x10), UInt8(0x20)].contains(bytes[3] & 0xf0) {
            return false
        }
        return true
    }

    static func resolvePublic(_ host: String) throws -> String {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &result) == 0, let first = result else {
            throw ADRNativeError.rejected("dns_failed")
        }
        defer { freeaddrinfo(first) }
        var addresses: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let item = current {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let info = item.pointee
            if getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                addresses.append(String(cString: buffer))
            }
            current = info.ai_next
        }
        guard !addresses.isEmpty, addresses.allSatisfy(isPublicAddress) else {
            throw ADRNativeError.rejected("destination_is_not_public")
        }
        return addresses.first(where: { !$0.contains(":") }) ?? addresses[0]
    }
}

enum HTTPDecoder {
    static func packet(_ bytes: Data, eof: Bool) throws -> HTTPPacket? {
        let separator = Data([13, 10, 13, 10])
        guard let headerEnd = bytes.range(of: separator) else {
            if bytes.count > 32 * 1024 || eof { throw ADRNativeError.rejected("invalid_response") }
            return nil
        }
        guard headerEnd.lowerBound <= 32 * 1024,
              let head = String(data: bytes[..<headerEnd.lowerBound], encoding: .isoLatin1) else {
            throw ADRNativeError.rejected("invalid_response")
        }
        let lines = head.components(separatedBy: "\r\n")
        let statusLine = (lines.first ?? "").split(separator: " ")
        guard statusLine.count >= 2, ["HTTP/1.1", "HTTP/1.0"].contains(String(statusLine[0])),
              let status = Int(statusLine[1]), (200...599).contains(status) else {
            throw ADRNativeError.rejected("invalid_response")
        }
        if (300...399).contains(status) { throw ADRNativeError.rejected("redirect_refused") }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else {
                throw ADRNativeError.rejected("invalid_response")
            }
            let key = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if ["content-length", "transfer-encoding"].contains(key), headers[key] != nil {
                throw ADRNativeError.rejected("ambiguous_response")
            }
            headers[key] = headers[key].map { "\($0), \(value)" } ?? value
        }
        if let encoding = headers["content-encoding"], encoding.lowercased() != "identity" {
            throw ADRNativeError.rejected("compressed_response_not_supported")
        }
        let raw = Data(bytes[headerEnd.upperBound...])
        guard raw.count <= ServiceBoundary.maximumBody + 32 * 1024 else {
            throw ADRNativeError.rejected("response_too_large")
        }
        let body: Data
        if let transfer = headers["transfer-encoding"] {
            guard transfer.lowercased() == "chunked", headers["content-length"] == nil else {
                throw ADRNativeError.rejected("ambiguous_response")
            }
            guard let decoded = try chunks(raw) else {
                if eof { throw ADRNativeError.rejected("incomplete_response") }
                return nil
            }
            body = decoded
        } else if let text = headers["content-length"] {
            guard !text.isEmpty, text.allSatisfy(\.isNumber), let size = Int(text),
                  size <= ServiceBoundary.maximumBody else {
                throw ADRNativeError.rejected("response_too_large")
            }
            if raw.count < size {
                if eof { throw ADRNativeError.rejected("incomplete_response") }
                return nil
            }
            guard raw.count == size else { throw ADRNativeError.rejected("ambiguous_response") }
            body = raw
        } else {
            if !eof { return nil }
            body = raw
        }
        return HTTPPacket(status: status, headers: headers, body: body)
    }

    static func chunks(_ bytes: Data) throws -> Data? {
        let crlf = Data([13, 10])
        var cursor = bytes.startIndex
        var output = Data()
        while cursor < bytes.endIndex {
            guard let end = bytes.range(of: crlf, in: cursor..<bytes.endIndex) else { return nil }
            guard end.lowerBound - cursor <= 128,
                  let text = String(data: bytes[cursor..<end.lowerBound], encoding: .ascii),
                  let first = text.split(separator: ";", omittingEmptySubsequences: false).first,
                  !first.isEmpty, first.allSatisfy(\.isHexDigit),
                  let size = Int(first, radix: 16), size <= ServiceBoundary.maximumBody - output.count else {
                throw ADRNativeError.rejected("invalid_chunked_response")
            }
            cursor = end.upperBound
            if size == 0 {
                guard bytes.endIndex - cursor >= 2 else { return nil }
                if bytes[cursor..<cursor + 2] == crlf { return output }
                guard bytes.range(of: Data([13, 10, 13, 10]), in: cursor..<bytes.endIndex) != nil else { return nil }
                return output
            }
            guard bytes.endIndex - cursor >= size + 2 else { return nil }
            output.append(bytes[cursor..<cursor + size])
            guard bytes[cursor + size..<cursor + size + 2] == crlf else {
                throw ADRNativeError.rejected("invalid_chunked_response")
            }
            cursor += size + 2
        }
        return nil
    }
}

/// Pin the TCP connection to a verified public IP while validating TLS against
/// the original service hostname. There is no second DNS lookup and no redirect.
final class PinnedHTTPS {
    func get(host: String, path: String, header: String, value: String, deadline: Date) throws -> HTTPPacket {
        let address = try ServiceBoundary.resolvePublic(host)
        guard deadline.timeIntervalSinceNow > 0 else { throw ADRNativeError.rejected("request_expired") }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        let queue = DispatchQueue(label: "org.adr.desktop.https.\(UUID().uuidString)")
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let reference = sec_trust_copy_ref(trust).takeRetainedValue()
            let configured = SecTrustSetPolicies(reference, SecPolicyCreateSSL(true, host as CFString))
            complete(configured == errSecSuccess && SecTrustEvaluateWithError(reference, nil))
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(
            host: NWEndpoint.Host(address), port: 443, using: parameters
        )
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var outcome: Result<HTTPPacket, Error>?
        var received = Data()
        func finish(_ result: Result<HTTPPacket, Error>) {
            lock.lock()
            if outcome == nil { outcome = result; semaphore.signal() }
            lock.unlock()
            connection.cancel()
        }
        func receiveNext() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, eof, error in
                if let data { received.append(data) }
                if received.count > ServiceBoundary.maximumBody + 64 * 1024 {
                    finish(.failure(ADRNativeError.rejected("response_too_large"))); return
                }
                do {
                    if let packet = try HTTPDecoder.packet(received, eof: eof) {
                        finish(.success(packet)); return
                    }
                    if error != nil || eof {
                        finish(.failure(ADRNativeError.rejected("connection_failed"))); return
                    }
                    receiveNext()
                } catch { finish(.failure(error)) }
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard deadline.timeIntervalSinceNow > 0 else {
                    finish(.failure(ADRNativeError.rejected("request_expired"))); return
                }
                let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\(header): \(value)\r\n"
                    + "Accept: application/json, text/plain\r\nAccept-Encoding: identity\r\n"
                    + "Connection: close\r\nUser-Agent: ADR-Desktop/0.1\r\n\r\n"
                connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                    if error != nil { finish(.failure(ADRNativeError.rejected("connection_failed"))) }
                    else { receiveNext() }
                })
            case .failed:
                finish(.failure(ADRNativeError.rejected("tls_or_connection_failed")))
            default: break
            }
        }
        connection.start(queue: queue)
        if semaphore.wait(timeout: .now() + max(0, min(20, deadline.timeIntervalSinceNow))) == .timedOut {
            finish(.failure(ADRNativeError.rejected("request_timeout")))
        }
        lock.lock(); let completed = outcome; lock.unlock()
        return try (completed ?? .failure(ADRNativeError.rejected("request_timeout"))).get()
    }
}
