import Foundation
import AppKit
import Security

@MainActor
final class Engine: ObservableObject {
    @Published var session: Session?
    @Published var error: String?
    @Published var running = false
    @Published var command = ""
    private var process: Process?
    private var runID = UUID()
    func cancel() {
        runID = UUID()
        process?.terminate()
        process = nil
        running = false
        error = "Test canceled. A message already accepted by the server cannot be recalled."
    }
    func run(_ args: [String], executable: String, password: String? = nil) {
        guard !running else { return }
        let bundled = Bundle.main.url(forResource: "mailbench", withExtension: nil)?.path
        let path = executable.isEmpty ? (bundled ?? "/usr/local/bin/mailbench") : executable
        guard FileManager.default.isExecutableFile(atPath: path) else { error = "Choose the mailbench executable in Settings, or build the bundled app."; return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args + ["--json"]
        let out = Pipe(), err = Pipe(), input = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = input
        command = ([path] + args).map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }.joined(separator: " ")
        running = true; error = nil; session = nil; process = p
        let id = UUID(); runID = id
        do { try p.run() } catch { running = false; self.error = error.localizedDescription; process = nil; return }
        if let password { input.fileHandleForWriting.write(Data((password + "\n").utf8)) }
        try? input.fileHandleForWriting.close()
        // Drain both pipes while the child runs to avoid full-pipe deadlocks on large reports.
        let stderr = LockedData()
        let group = DispatchGroup(); group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stderr.set(err.fileHandleForReading.readDataToEndOfFile()); group.leave()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit(); group.wait()
            let result = Result { try JSONDecoder().decode(Session.self, from: data) }
            Task { @MainActor in
                guard self.runID == id else { return }
                self.running = false; self.process = nil
                switch result {
                case .success(let session):
                    if session.schema_version == 1 { self.session = session }
                    else { self.error = "Unsupported engine schema \(session.schema_version). Update the application." }
                case .failure(let error):
                    self.error = "Engine exited \(p.terminationStatus): \(String(data: stderr.get(), encoding: .utf8) ?? error.localizedDescription)"
                }
            }
        }
    }
}
private final class LockedData: @unchecked Sendable {
    private var data = Data(); private let lock = NSLock()
    func set(_ value: Data) { lock.lock(); defer { lock.unlock() }; data = value }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}
enum Keychain {
    static func save(account: String, password: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "Mailbench.SMTP", kSecAttrAccount as String: account]
        let data = Data(password.utf8)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var values = query; values[kSecValueData as String] = data
            let result = SecItemAdd(values as CFDictionary, nil)
            guard result == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(result)) }
        } else if status != errSecSuccess { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
    static func delete(account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "Mailbench.SMTP", kSecAttrAccount as String: account]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
    static func load(account: String) -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "Mailbench.SMTP", kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var value: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess, let data = value as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
