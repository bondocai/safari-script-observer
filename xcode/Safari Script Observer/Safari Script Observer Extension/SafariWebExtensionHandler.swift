//
//  SafariWebExtensionHandler.swift
//  Safari Script Observer Extension
//
//  Native side of the extension. It offers the JavaScript background script
//  one service through browser.runtime.sendNativeMessage:
//
//    {type: "http"}  → call the user's configured model server. Requests made
//                      here carry no browser Origin header, so Ollama and
//                      LM Studio need no CORS configuration.
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

    // MARK: User-configured model server

    private func runHTTP(_ message: [String: Any]) async -> [String: Any] {
        guard let urlString = message["url"] as? String,
              let url = URL(string: urlString),
              ["http", "https"].contains(url.scheme?.lowercased() ?? "") else {
            return ["error": "invalid model server URL"]
        }
        var request = URLRequest(url: url)
        request.httpMethod = (message["method"] as? String) == "GET" ? "GET" : "POST"
        // Never send this Mac's cookies with these requests.
        request.httpShouldHandleCookies = false
        request.timeoutInterval = (message["timeoutMs"] as? Double ?? 30000) / 1000
        for (name, value) in message["headers"] as? [String: String] ?? [:] {
            request.setValue(value, forHTTPHeaderField: name)
        }
        if request.httpMethod == "POST", let body = message["body"] as? String {
            request.httpBody = Data(body.utf8)
        }
        let started = Date()
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            return ["status": status,
                    "body": String(decoding: data.prefix(2_000_000), as: UTF8.self),
                    // Where the request ended up after redirects.
                    "finalUrl": response.url?.absoluteString ?? urlString,
                    "seconds": Date().timeIntervalSince(started)]
        } catch {
            // The system's error code lets the extension say which step failed
            // (name lookup, connection, timeout, certificate, offline).
            let ns = error as NSError
            return ["error": "Could not reach \(url.host ?? "the model server"): \(error.localizedDescription)",
                    "code": ns.code, "domain": ns.domain]
        }
    }
}
