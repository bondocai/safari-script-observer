// Test driver for eval/native-check/run.sh (see there).
import Foundation
let h = SafariWebExtensionHandler()
func run(_ label: String, _ m: [String: Any], expect: (([String: Any]) -> Bool)) async {
  let r = await h.runHTTP(m)
  let summary = r["error"].map { "error: \($0)" } ?? "status \(r["status"] ?? "?"), \((r["body"] as? String)?.count ?? 0) bytes"
  print(expect(r) ? "  ok  " : "  FAIL", label, "->", summary.prefix(140))
}
let refused: ([String: Any]) -> Bool = { $0["refused"] as? Bool == true }
let fetched: ([String: Any]) -> Bool = { $0["status"] as? Int == 200 }
let T = Task {
  await run("public-only, 127.0.0.1", ["url": "http://127.0.0.1:8799/", "method": "GET", "publicOnly": true], expect: refused)
  await run("public-only, localhost", ["url": "http://localhost:8799/", "method": "GET", "publicOnly": true], expect: refused)
  await run("public-only, router 192.168.1.1", ["url": "http://192.168.1.1/", "method": "GET", "publicOnly": true], expect: refused)
  await run("public-only, IPv6 loopback", ["url": "http://[::1]:8799/", "method": "GET", "publicOnly": true], expect: refused)
  await run("public-only, public name resolving to 127.0.0.1 (localtest.me)", ["url": "http://localtest.me:8799/", "method": "GET", "publicOnly": true], expect: refused)
  await run("public-only, public site redirecting to 127.0.0.1", ["url": "https://postman-echo.com/redirect-to?url=http%3A%2F%2Flocaltest.me%3A8799%2Fsecret", "method": "GET", "publicOnly": true, "timeoutMs": 10000.0], expect: refused)
  await run("public-only, ordinary public site", ["url": "https://example.com/", "method": "GET", "publicOnly": true], expect: fetched)
  await run("model server (not public-only), 127.0.0.1", ["url": "http://127.0.0.1:8799/", "method": "GET"], expect: fetched)
  await run("model server, local redirect still followed", ["url": "http://127.0.0.1:8799/redirect-local", "method": "GET"], expect: { ($0["body"] as? String)?.contains("/secret") == true })
  await run("5 MB response stops at 2 MB", ["url": "http://127.0.0.1:8799/big", "method": "GET"], expect: { ($0["body"] as? String)?.count == 2_000_000 })
  await run("slow drip stopped by overall limit", ["url": "http://127.0.0.1:8799/drip", "method": "GET", "timeoutMs": 1500.0], expect: { $0["code"] as? Int == NSURLErrorTimedOut })
  exit(0)
}
RunLoop.main.run()
