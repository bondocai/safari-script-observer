// Test bridge: serves Apple's on-device model (Foundation Models) as an
// OpenAI-compatible /v1/chat/completions endpoint on 127.0.0.1, so the
// extension's own eval harnesses can test it unchanged.
//   - system message -> session instructions; user text -> prompt
//   - response_format json_schema -> DynamicGenerationSchema (guided generation)
//   - images are dropped (text only); greedy sampling (like temperature 0)
//   - if the input is too long for the model's context, the user text is cut
//     down and retried; each cut is logged.
import Foundation
import FoundationModels
import Network

let port = NWEndpoint.Port(rawValue: UInt16(CommandLine.arguments.dropFirst().first ?? "8765")!)!
let log = FileHandle.standardError
func say(_ s: String) { log.write((s + "\n").data(using: .utf8)!) }

var stats = ["calls": 0, "cut": 0, "failed": 0, "imagesDropped": 0]
let statsLock = NSLock()
func bump(_ k: String) { statsLock.lock(); stats[k, default: 0] += 1; statsLock.unlock() }

// JSON schema (the subset the extension uses) -> DynamicGenerationSchema
func dynamicSchema(_ s: [String: Any], name: String) -> DynamicGenerationSchema {
  let type = s["type"] as? String ?? "string"
  if let choices = s["enum"] as? [String] {
    return DynamicGenerationSchema(name: name, anyOf: choices)
  }
  if type == "object" {
    let props = s["properties"] as? [String: Any] ?? [:]
    let required = Set(s["required"] as? [String] ?? [])
    let order = (s["required"] as? [String] ?? []) + props.keys.filter { !required.contains($0) }.sorted()
    return DynamicGenerationSchema(name: name, properties: order.map { key in
      DynamicGenerationSchema.Property(name: key,
        schema: dynamicSchema(props[key] as? [String: Any] ?? [:], name: name + "_" + key),
        isOptional: !required.contains(key))
    })
  }
  if type == "array" {
    let items = dynamicSchema(s["items"] as? [String: Any] ?? [:], name: name + "_item")
    return DynamicGenerationSchema(arrayOf: items, minimumElements: s["minItems"] as? Int,
                                   maximumElements: s["maxItems"] as? Int)
  }
  return DynamicGenerationSchema(type: String.self)
}

func text(of content: Any?) -> String {
  if let s = content as? String { return s }
  if let parts = content as? [[String: Any]] {
    if parts.contains(where: { $0["type"] as? String == "image_url" }) { bump("imagesDropped") }
    return parts.compactMap { $0["type"] as? String == "text" ? $0["text"] as? String : nil }.joined(separator: "\n")
  }
  return ""
}

func complete(_ req: [String: Any]) async throws -> String {
  bump("calls")
  let messages = req["messages"] as? [[String: Any]] ?? []
  let system = messages.filter { $0["role"] as? String == "system" }.map { text(of: $0["content"]) }.joined(separator: "\n")
  var user = messages.filter { $0["role"] as? String == "user" }.map { text(of: $0["content"]) }.joined(separator: "\n")
  let maxTokens = req["max_tokens"] as? Int
  var schema: GenerationSchema? = nil
  if let rf = req["response_format"] as? [String: Any], let js = rf["json_schema"] as? [String: Any],
     let s = js["schema"] as? [String: Any] {
    let root = dynamicSchema(s, name: "result")
    schema = try GenerationSchema(root: root, dependencies: [])
  }
  let options = GenerationOptions(sampling: .greedy, maximumResponseTokens: maxTokens.map { max($0, 60) })
  var cut = false
  for attempt in 0..<6 {
    do {
      let session = LanguageModelSession(instructions: system)
      if let schema {
        let r = try await session.respond(to: user, schema: schema, options: options)
        if cut { bump("cut") }
        return r.content.jsonString
      } else {
        let r = try await session.respond(to: user, options: options)
        if cut { bump("cut") }
        return r.content
      }
    } catch LanguageModelSession.GenerationError.exceededContextWindowSize(_) where attempt < 5 {
      // Too long for the model: keep the first 70% of the page description.
      user = String(user.prefix(Int(Double(user.count) * 0.7))) + "\n…(page description cut to fit)"
      cut = true
    }
  }
  throw NSError(domain: "bridge", code: 1, userInfo: [NSLocalizedDescriptionKey: "input too long"])
}

func respond(_ conn: NWConnection, status: Int, body: Data) {
  let head = "HTTP/1.1 \(status) \(status == 200 ? "OK" : "Error")\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
  conn.send(content: head.data(using: .utf8)! + body, completion: .contentProcessed { _ in conn.cancel() })
}

func handle(_ conn: NWConnection, buffer: Data = Data()) {
  conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, done, err in
    var buf = buffer; if let data { buf.append(data) }
    guard let headerEnd = buf.range(of: "\r\n\r\n".data(using: .utf8)!) else {
      if done || err != nil { conn.cancel() } else { handle(conn, buffer: buf) }; return
    }
    let head = String(data: buf[..<headerEnd.lowerBound], encoding: .utf8) ?? ""
    let length = head.split(separator: "\r\n").first { $0.lowercased().hasPrefix("content-length:") }
      .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
    let body = buf[headerEnd.upperBound...]
    if body.count < length && !done { handle(conn, buffer: buf); return }
    let firstLine = head.split(separator: "\r\n").first ?? ""
    if firstLine.hasPrefix("GET") {
      statsLock.lock(); let s = stats; statsLock.unlock()
      let models = ["object": "list", "data": [["id": "apple-on-device", "object": "model"]], "stats": s] as [String: Any]
      respond(conn, status: 200, body: try! JSONSerialization.data(withJSONObject: models)); return
    }
    Task {
      do {
        let req = try JSONSerialization.jsonObject(with: Data(body)) as? [String: Any] ?? [:]
        let started = Date()
        let content = try await complete(req)
        say(String(format: "%.2fs %@", Date().timeIntervalSince(started), String(content.prefix(120))))
        let reply: [String: Any] = ["object": "chat.completion", "model": "apple-on-device",
          "choices": [["index": 0, "finish_reason": "stop", "message": ["role": "assistant", "content": content]]]]
        respond(conn, status: 200, body: try JSONSerialization.data(withJSONObject: reply))
      } catch {
        bump("failed"); say("ERROR \(error)")
        let reply = ["error": ["message": "Apple model: \(error)"]]
        respond(conn, status: 500, body: try! JSONSerialization.data(withJSONObject: reply))
      }
    }
  }
}

say("availability: \(SystemLanguageModel.default.availability)")
let params = NWParameters.tcp
params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
let listener = try NWListener(using: params)
listener.newConnectionHandler = { conn in conn.start(queue: .global()); handle(conn) }
listener.stateUpdateHandler = { say("listener: \($0) on 127.0.0.1:\(port)") }
listener.start(queue: .main)
dispatchMain()
