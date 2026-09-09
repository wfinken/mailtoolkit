import SwiftUI
import AppKit
import UniformTypeIdentifiers

@main
struct MailbenchApp: App {
    var body: some Scene {
        WindowGroup { WorkspaceView().frame(minWidth: 1050, minHeight: 700) }
            .windowStyle(.titleBar)
    }
}
struct WorkspaceView: View {
    @StateObject private var engine = Engine()
    @State private var tool: Tool? = .dashboard
    @State private var target = ""
    @State private var selected: String?
    @State private var recordType = "MX"
    @State private var selector = "halon"
    @State private var ip = ""
    @State private var ehlo = "mailbench.local"
    @State private var sender = ""
    @State private var recipient = ""
    @State private var subject = "[MAILBENCH] SMTP Test"
    @State private var bodyText = "Mailbench implementation test."
    @State private var tls = "starttls"
    @State private var username = ""
    @State private var password = ""
    @State private var useSwaks = false
    @State private var saveHistory = false
    @State private var showingPalette = false
    @State private var paletteQuery = ""
    @State private var transcriptFilter = "all"
    @AppStorage("enginePath") private var enginePath = ""
    var current: Tool { tool ?? .dashboard }
    var body: some View {
        NavigationSplitView {
            List(selection: $tool) {
                Section("Overview") { nav(.dashboard) }
                Section("Test") { nav(.environment); nav(.send); nav(.smtp) }
                Section("Authentication") { nav(.spf); nav(.dkim); nav(.dmarc) }
                Section("Network") { nav(.dns); nav(.mx); nav(.ptr); nav(.tls) }
                Section("Analyze") { nav(.message) }
                Section("Workspace") { nav(.history); nav(.profiles); nav(.settings) }
            }
            .listStyle(.sidebar)
            .navigationTitle("Mailbench")
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } detail: {
            VStack(alignment: .leading, spacing: 0) {
                controls.padding(20)
                Divider()
                if let error = engine.error { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).padding() }
                if engine.running { ProgressView("Running diagnostics…").padding() }
                if current == .settings { settings }
                else if let session = engine.session { results(session) }
                else { emptyState }
                Divider()
                HStack {
                    Text(engine.running ? "Running" : "Ready").font(.caption)
                    Spacer()
                    Toggle("Save local history", isOn: $saveHistory).toggleStyle(.checkbox).help("History includes raw infrastructure and message metadata.")
                    Button("Copy CLI Command") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(engine.command, forType: .string) }.disabled(engine.command.isEmpty)
                }.padding(10)
            }
            .navigationTitle(current.rawValue)
            .toolbar {
                Button { showingPalette = true } label: { Label("Command Palette", systemImage: "command") }.keyboardShortcut("k")
                if engine.running { Button("Cancel", role: .cancel) { engine.cancel() } }
            }
        }
        .sheet(isPresented: $showingPalette) {
            VStack {
                TextField("Find an action", text: $paletteQuery).textFieldStyle(.roundedBorder)
                List(Tool.allCases.filter { paletteQuery.isEmpty || $0.rawValue.localizedCaseInsensitiveContains(paletteQuery) }) { action in
                    Button { tool = action; showingPalette = false } label: { Label(action.rawValue, systemImage: action.symbol) }.buttonStyle(.plain)
                }
            }.padding().frame(width: 450, height: 380)
        }
        .onChange(of: tool) { _, _ in selected = nil; engine.session = nil; engine.error = nil }
    }
    func nav(_ t: Tool) -> some View { Label(t.rawValue, systemImage: t.symbol).tag(t) }
    @ViewBuilder var controls: some View {
        if current != .settings {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    TextField(targetHint, text: $target).textFieldStyle(.roundedBorder).onSubmit { run() }
                    if current == .dns { Picker("Type", selection: $recordType) { ForEach(["A", "AAAA", "MX", "TXT", "PTR", "CNAME", "NS", "SOA", "SRV", "CAA"], id: \.self) { Text($0) } }.frame(width: 160) }
                    if current == .message { Button("Open .eml…") { chooseFile { target = $0 } } }
                    Button(actionLabel) { run() }.keyboardShortcut(.return, modifiers: .command).disabled(engine.running)
                }
                if [.environment, .spf, .dkim, .dmarc, .message].contains(current) {
                    HStack { TextField("Sending IP (SPF / DMARC)", text: $ip); TextField("DKIM selector", text: $selector) }.textFieldStyle(.roundedBorder)
                }
                if [.smtp, .tls, .send, .message, .dmarc].contains(current) {
                    HStack { TextField("EHLO", text: $ehlo); Picker("TLS", selection: $tls) { Text("STARTTLS required").tag("starttls"); Text("Implicit TLS").tag("implicit"); Text("Off").tag("off") } }.textFieldStyle(.roundedBorder)
                }
                if [.send, .message, .dmarc].contains(current) {
                    HStack { TextField("MAIL FROM", text: $sender); if current == .send { TextField("RCPT TO", text: $recipient) } }.textFieldStyle(.roundedBorder)
                }
                if current == .send {
                    TextField("Subject", text: $subject).textFieldStyle(.roundedBorder)
                    TextEditor(text: $bodyText).font(.system(.body, design: .monospaced)).frame(height: 90).border(Color(nsColor: .separatorColor))
                    HStack {
                        TextField("Username (optional)", text: $username)
                        SecureField("Password", text: $password)
                        Button("Save to Keychain") { do { try Keychain.save(account: target + "/" + username, password: password) } catch { engine.error = error.localizedDescription } }
                        Button("Load") { password = Keychain.load(account: target + "/" + username) ?? "" }
                    }.textFieldStyle(.roundedBorder)
                    HStack { Toggle("Use Swaks", isOn: $useSwaks); Button("Preview without sending") { run(dryRun: true) }; Text("Run sends one message to the specified recipient.").font(.caption).foregroundStyle(.secondary) }
                }
                if current == .profiles {
                    HStack { Button("Import TOML…") { chooseFile { execute(["profile", "import", $0]) } }; Button("Run profile") { execute(["check", "--profile", target]) } }
                }
                if current == .history {
                    HStack { Button("Open session") { execute(["history", "show", target]) }; Button("Delete session", role: .destructive) { execute(["history", "delete", target]) }; Button("Export report…") { exportReport() } }
                }
            }
        }
    }
    var targetHint: String {
        switch current { case .send, .smtp, .tls: return "SMTP host:port"; case .ptr: return "IP address"; case .message: return "Path to .eml file"; case .history: return "Session UUID"; case .profiles: return "Profile name"; default: return "Domain, such as example.com" }
    }
    var actionLabel: String { switch current { case .send: return "Send Test"; case .history, .profiles: return "Refresh"; case .message: return "Inspect"; default: return "Run Check" } }
    var emptyState: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Inspect an email environment", systemImage: current.symbol).font(.title2)
            Text("Run a check to see findings and their underlying evidence. Nothing is uploaded; diagnostics connect directly to your configured infrastructure.").foregroundStyle(.secondary).frame(maxWidth: 600, alignment: .leading)
            if current == .dashboard { HStack { Button("SMTP Probe") { tool = .smtp }; Button("DNS Lookup") { tool = .dns }; Button("Analyze Message") { tool = .message } } }
            Spacer()
        }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    var settings: some View {
        Form {
            Section("Shared engine") { TextField("Executable path", text: $enginePath); Button("Choose executable…") { chooseFile { enginePath = $0 } }; Text("Leave blank to use the bundled engine, or /usr/local/bin/mailbench.").foregroundStyle(.secondary) }
            Section("Privacy") { Text("Local history is opt-in and contains raw diagnostic evidence. Profiles never contain passwords. SMTP secrets can be stored in macOS Keychain."); Button("Check dependencies") { execute(["doctor"]) } }
        }.formStyle(.grouped)
    }
    func results(_ session: Session) -> some View {
        HSplitView {
            List(session.findings, selection: $selected) { f in
                VStack(alignment: .leading, spacing: 5) { Label(f.test, systemImage: f.symbol); HStack { Text(f.status).font(.caption.bold()); Spacer(); Text("\(f.duration_ms) ms").font(.caption).foregroundStyle(.secondary) } }.tag(f.id).padding(.vertical, 4)
            }.frame(minWidth: 220, idealWidth: 260, maxWidth: 320)
            ScrollView {
                if let f = session.findings.first(where: { $0.id == selected }) ?? session.findings.first {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack { Label(f.status, systemImage: f.symbol).font(.headline); Spacer(); Text(f.target).foregroundStyle(.secondary) }
                        Text(f.summary).font(.title3).textSelection(.enabled)
                        ForEach(f.next_steps, id: \.self) { Text($0) }
                        if !f.evidence["records"].items.isEmpty {
                            ForEach(Array(f.evidence["records"].items.enumerated()), id: \.offset) { _, row in Text(row.pretty).font(.system(.body, design: .monospaced)).textSelection(.enabled); Divider() }
                        }
                        if !f.evidence["transcript"].items.isEmpty {
                            Picker("Transcript", selection: $transcriptFilter) { ForEach(["all", "client", "server", "tls", "connect"], id: \.self) { Text($0.capitalized) } }.pickerStyle(.segmented)
                            ForEach(Array(f.evidence["transcript"].items.filter { transcriptFilter == "all" || $0["direction"].text == transcriptFilter }.enumerated()), id: \.offset) { _, event in
                                HStack(alignment: .top) { Text(event["elapsed_ms"].text + " ms").frame(width: 70, alignment: .trailing).foregroundStyle(.secondary); Text(event["direction"].text.uppercased()).frame(width: 65); Text(event["text"].text).frame(maxWidth: .infinity, alignment: .leading) }.font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                        DisclosureGroup("Raw Evidence") { Text(f.evidence.pretty).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                        HStack { Button("Copy Evidence") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(f.evidence.pretty, forType: .string) }; Text("Session \(session.id)").font(.caption).foregroundStyle(.secondary) }
                    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                }
            }.frame(minWidth: 420)
        }
    }
    func execute(_ args: [String], password: String? = nil) { engine.run(args + (saveHistory ? ["--save"] : []), executable: enginePath, password: password) }
    func run(dryRun: Bool = false) {
        var args: [String]
        switch current {
        case .dashboard, .environment:
            args = ["check", target]; if !ip.isEmpty { args += ["--ip", ip] }; if !selector.isEmpty { args += ["--selector", selector] }
        case .dns: args = ["dns", recordType.lowercased(), target]
        case .mx: args = ["mx", target]
        case .ptr: args = ["ptr", target]
        case .spf: args = ip.isEmpty ? ["spf", "check", target] : ["spf", "test", target, "--ip", ip, "--ehlo", ehlo]
        case .dkim: args = ["dkim", "check", target, "--selector", selector]
        case .dmarc: args = ["dmarc", "check", target]
        case .smtp, .tls:
            args = current == .tls ? ["tls", target] : ["smtp", "test", target]
            args += ["--ehlo", ehlo, "--tls-mode", tls]
        case .send:
            args = [useSwaks ? "swaks" : "send", target, "--from", sender, "--to", recipient, "--subject", subject, "--body", bodyText, "--ehlo", ehlo, "--tls-mode", tls]
            if dryRun { args += ["--dry-run"] }
            if !username.isEmpty { args += ["--username", username, "--password-stdin"] }
        case .message:
            args = ip.isEmpty ? ["message", "inspect", target] : ["auth", target, "--ip", ip, "--mail-from", sender, "--ehlo", ehlo]
        case .history: args = ["history", "list"]
        case .profiles: args = ["profile", "list"]
        case .settings: args = ["doctor"]
        }
        execute(args, password: current == .send && !username.isEmpty ? password : nil)
    }
    func chooseFile(_ completion: @escaping (String) -> Void) {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { completion(url.path) }
    }
    func exportReport() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "mailbench-report.html"
        if panel.runModal() == .OK, let url = panel.url { execute(["report", target, "--format", "html", "--output", url.path]) }
    }
}
