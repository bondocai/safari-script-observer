//
//  SafariWebExtensionHandler.swift
//  Safari Script Observer Extension
//
//  Native side of the extension. It offers the JavaScript background script
//  one service through browser.runtime.sendNativeMessage:
//
//    {type: "http"}  → call the user's configured model server. Requests made
//                      here carry no browser Origin header, so Ollama and
//                      LM Studio need no CORS configuration. With
//                      publicOnly: true (the investigation's lookups), only
//                      public internet addresses are reached, redirects included.
//

import Foundation
import SafariServices
import os.log

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    private let log = Logger(subsystem: "com.example.SafariScriptObserver", category: "native")

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any] ?? [:]

        Task {
            let reply = await handle(message)
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: reply]
            context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }

    private func handle(_ message: [String: Any]) async -> [String: Any] {
        switch message["type"] as? String {
        case "http":
            return await runHTTP(message)
        default:
            return ["error": "unknown request"]
        }
    }

    // MARK: HTTP requests (model server, and the investigation's public lookups)

    /// Largest response read; the rest is not downloaded.
    private static let maxBody = 2_000_000

    private func runHTTP(_ message: [String: Any]) async -> [String: Any] {
        guard let urlString = message["url"] as? String,
              let url = URL(string: urlString),
              ["http", "https"].contains(url.scheme?.lowercased() ?? "") else {
            return ["error": "invalid model server URL"]
        }
        // Investigation lookups (a suspicious page's home page, where its forms send
        // data, registries) must only reach the public internet: a page must not be
        // able to point them at this Mac or devices on the home network, directly,
        // by a name that resolves there, or by redirecting there. The model server
        // itself is usually on the local network, so its requests are not limited.
        let publicOnly = message["publicOnly"] as? Bool ?? false
        if publicOnly, let reason = await NetworkGuard.refusal(for: url) {
            return ["error": "Not fetched: \(reason)", "refused": true]
        }
        let timeout = (message["timeoutMs"] as? Double ?? 30000) / 1000
        var request = URLRequest(url: url)
        request.httpMethod = (message["method"] as? String) == "GET" ? "GET" : "POST"
        // Never send this Mac's cookies with these requests.
        request.httpShouldHandleCookies = false
        request.timeoutInterval = timeout
        for (name, value) in message["headers"] as? [String: String] ?? [:] {
            request.setValue(value, forHTTPHeaderField: name)
        }
        if request.httpMethod == "POST", let body = message["body"] as? String {
            request.httpBody = Data(body.utf8)
        }
        let started = Date()
        // timeoutInterval only limits silence between bytes; a server dripping
        // bytes slowly is stopped by this overall limit.
        let deadline = started.addingTimeInterval(timeout * 2)
        let watcher = RequestWatcher(publicOnly: publicOnly)
        do {
            let (bytes, response) = try await URLSession.shared.bytes(for: request, delegate: watcher)
            var data = Data()
            data.reserveCapacity(64 * 1024)
            for try await byte in bytes {
                data.append(byte)
                if data.count >= Self.maxBody { bytes.task.cancel(); break }
                if data.count % 65_536 == 0, Date() > deadline {
                    bytes.task.cancel()
                    return ["error": "Could not reach \(url.host ?? "the server"): took too long", "code": NSURLErrorTimedOut]
                }
            }
            if publicOnly, let address = watcher.remoteAddress, NetworkGuard.isPrivateAddress(address) {
                // The name resolved to a public address when checked, then to a private one.
                return ["error": "Not fetched: \(url.host ?? "the site") answered from a private network address", "refused": true]
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            return ["status": status,
                    "body": String(decoding: data, as: UTF8.self),
                    // Where the request ended up after redirects.
                    "finalUrl": response.url?.absoluteString ?? urlString,
                    "seconds": Date().timeIntervalSince(started)]
        } catch {
            if let reason = watcher.refusal {
                return ["error": "Not fetched: \(reason)", "refused": true]
            }
            // The system's error code lets the extension say which step failed
            // (name lookup, connection, timeout, certificate, offline).
            let ns = error as NSError
            return ["error": "Could not reach \(url.host ?? "the model server"): \(error.localizedDescription)",
                    "code": ns.code, "domain": ns.domain]
        }
    }
}

/// Follows a request: refuses redirects to private addresses (public-only
/// requests) and notes the address actually connected to.
private final class RequestWatcher: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let publicOnly: Bool
    private let lock = NSLock()
    private var _refusal: String?
    private var _remoteAddress: String?
    var refusal: String? { lock.withLock { _refusal } }
    var remoteAddress: String? { lock.withLock { _remoteAddress } }

    init(publicOnly: Bool) { self.publicOnly = publicOnly }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        // (The async form of this method crashes the Swift 6.4 compiler.)
        guard publicOnly else { completionHandler(request); return }
        Task {
            if let reason = await NetworkGuard.refusal(for: request.url) {
                self.lock.withLock { self._refusal = "redirect refused, \(reason)" }
                task.cancel()
                completionHandler(nil)
            } else {
                completionHandler(request)
            }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        let address = metrics.transactionMetrics.last(where: { $0.remoteAddress != nil })?.remoteAddress
        lock.withLock { _remoteAddress = address }
    }
}

/// Which addresses public-only requests may reach. Mirrors isPrivateHost in models.js.
enum NetworkGuard {
    /// Why this URL must not be fetched, or nil if it may be.
    static func refusal(for url: URL?) async -> String? {
        guard let url, ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              let host = url.host(percentEncoded: false)?.lowercased(), !host.isEmpty else {
            return "not a web address"
        }
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if isPrivateName(bare) || isPrivateAddress(bare) { return "\(host) is a local or private address" }
        let addresses = await Task.detached { resolve(bare) }.value
        if let local = addresses.first(where: isPrivateAddress) {
            return "\(host) points to a private network address (\(local))"
        }
        return nil
    }

    static func isPrivateName(_ host: String) -> Bool {
        host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local") ||
            host.hasSuffix(".internal") || host.hasSuffix(".home.arpa") || host.hasSuffix(".ts.net") ||
            (!host.contains(".") && !host.contains(":"))
    }

    static func isPrivateAddress(_ address: String) -> Bool {
        var a = address.lowercased()
        if let zone = a.firstIndex(of: "%") { a = String(a[..<zone]) }
        // IPv4-mapped IPv6 (::ffff:192.168.1.1): judge the IPv4 part.
        if a.hasPrefix("::ffff:"), a.contains(".") { a = String(a.dropFirst(7)) }
        let parts = a.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4 {
            let n = parts.compactMap { UInt8($0) }
            guard n.count == 4 else { return false }
            return n[0] == 0 || n[0] == 10 || n[0] == 127 || n[0] >= 224 ||
                (n[0] == 169 && n[1] == 254) || (n[0] == 172 && (16...31).contains(n[1])) ||
                (n[0] == 192 && n[1] == 168) || (n[0] == 100 && (64...127).contains(n[1])) ||
                (n[0] == 198 && (18...19).contains(n[1]))
        }
        guard a.contains(":") else { return false }
        return a == "::" || a == "::1" || a.hasPrefix("fc") || a.hasPrefix("fd") ||
            a.hasPrefix("fe8") || a.hasPrefix("fe9") || a.hasPrefix("fea") || a.hasPrefix("feb") || a.hasPrefix("ff")
    }

    /// The addresses a name resolves to (empty if it doesn't resolve; the request
    /// then fails on its own).
    static func resolve(_ host: String) -> [String] {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0, let first = list else { return [] }
        defer { freeaddrinfo(list) }
        var result: [String] = []
        for info in sequence(first: first, next: { $0.pointee.ai_next }) {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &buffer, socklen_t(buffer.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                result.append(String(cString: buffer))
            }
        }
        return result
    }
}
