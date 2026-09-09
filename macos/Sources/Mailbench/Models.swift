import Foundation

struct Session: Decodable, Identifiable {
    let schema_version: Int
    let id: String
    let timestamp: String
    let target: String
    let findings: [Finding]
}
struct Finding: Decodable, Identifiable {
    var id: String { "\(test)|\(target)" }
    let test: String
    let target: String
    let status: String
    let summary: String
    let evidence: JSONValue
    let next_steps: [String]
    let duration_ms: Int
    var symbol: String {
        switch status { case "PASS": return "checkmark.circle.fill"; case "FAIL", "ERROR": return "xmark.octagon.fill"; case "WARN": return "exclamationmark.triangle.fill"; case "SKIP": return "minus.circle"; default: return "info.circle" }
    }
}
indirect enum JSONValue: Codable {
    case object([String: JSONValue]), array([JSONValue]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .null: try c.encodeNil(); case .bool(let v): try c.encode(v); case .number(let v): try c.encode(v); case .string(let v): try c.encode(v); case .array(let v): try c.encode(v); case .object(let v): try c.encode(v) }
    }
    subscript(key: String) -> JSONValue { if case .object(let v) = self { return v[key] ?? .null }; return .null }
    var text: String { if case .string(let v) = self { return v }; if case .number(let v) = self { return String(Int(v)) }; return "" }
    var items: [JSONValue] { if case .array(let v) = self { return v }; return [] }
    var pretty: String { let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]; return (try? String(data: e.encode(self), encoding: .utf8)) ?? "null" }
}
enum Tool: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", environment = "Environment Check", send = "Send Message", smtp = "SMTP Session", dns = "DNS Explorer", mx = "MX", ptr = "PTR", spf = "SPF", dkim = "DKIM", dmarc = "DMARC", tls = "TLS Inspector", message = "Message Inspector", history = "Recent Tests", profiles = "Profiles", settings = "Settings"
    var id: Self { self }
    var symbol: String {
        switch self { case .dashboard: return "square.grid.2x2"; case .environment: return "checklist"; case .send: return "paperplane"; case .smtp: return "terminal"; case .dns, .mx, .ptr: return "network"; case .spf, .dkim, .dmarc, .tls: return "lock.shield"; case .message: return "envelope.open"; case .history: return "clock"; case .profiles: return "person.text.rectangle"; case .settings: return "gearshape" }
    }
}
