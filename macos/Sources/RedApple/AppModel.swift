import AppKit
import SwiftUI
import RedAppleCore

@MainActor
final class AppModel: ObservableObject {
    @Published var workspace: Workspace
    @Published var database: PatchDatabase?
    @Published var catalog: BountyCatalog?
    @Published var records: [PatchRecord] = []
    @Published var discovery: DiscoverySnapshot
    @Published var triage: [String: LeadTriage] = [:]
    @Published var refreshing = false
    @Published var notice: String?
    @Published var discoveryWarning: String?
    @Published var lastRead: Date?
    @Published var usingBundledPatches = true
    @Published var engineRunning = false
    @Published var engineMessage: String?
    @Published var engineRepository = UserDefaults.standard.string(forKey: "engineRepository") ?? ""
    @Published var pythonPath = UserDefaults.standard.string(forKey: "pythonPath") ?? "/usr/bin/python3" {
        didSet { UserDefaults.standard.set(pythonPath, forKey: "pythonPath") }
    }
    @Published var timeBudget = 60
    private var engineProcess: Process?
    private var refreshTask: Task<Void, Never>?

    init() {
        let savedPath = UserDefaults.standard.string(forKey: "workspace")
        let workspace = Workspace(root: savedPath.map { URL(fileURLWithPath: $0, isDirectory: true) })
        self.workspace = workspace
        self.discovery = DiscoverySnapshot(workspace: workspace)
        reloadWorkspace()
    }

    func reloadWorkspace() {
        do {
            catalog = try BountyCatalog.bundled()
            database = try workspace.loadPatches()
            usingBundledPatches = !FileManager.default.fileExists(atPath: workspace.url("native-patches.json").path) && !FileManager.default.fileExists(atPath: workspace.url("releases.json").path)
            rebuildRecords()
        } catch { notice = "Could not load patches: \(error.localizedDescription)" }
        do { triage = try workspace.load([String: LeadTriage].self, from: "native-triage.json") ?? [:] }
        catch { notice = "Could not load triage notes: \(error.localizedDescription)" }
        reloadDiscovery()
    }

    func reloadDiscovery() {
        let snapshot = DiscoverySnapshot(workspace: workspace)
        // Transient partial engine writes must not hide the last good lead list.
        if snapshot.warnings.isEmpty { discovery = snapshot }
        else {
            if snapshot.status != nil { discovery.status = snapshot.status }
            if !snapshot.leads.isEmpty { discovery.leads = snapshot.leads }
            if !snapshot.workbenchLeads.isEmpty { discovery.workbenchLeads = snapshot.workbenchLeads }
        }
        discoveryWarning = snapshot.warnings.isEmpty ? nil : snapshot.warnings.joined(separator: "\n")
        lastRead = Date()
    }

    private func rebuildRecords() {
        if let catalog, let database { records = database.records(classifier: BountyClassifier(catalog: catalog)) }
    }

    func refreshPatches() {
        guard !refreshing, let database else { return }
        refreshing = true; notice = nil
        let target = workspace
        refreshTask = Task {
            defer { refreshing = false }
            do {
                let result = try await PatchFetcher().refresh(previous: database)
                try Task.checkCancellation()
                try target.save(result.database, to: "native-patches.json")
                self.database = result.database; usingBundledPatches = false
                rebuildRecords()
                notice = result.warnings.isEmpty ? "Apple patches are up to date." : "Patches refreshed with \(result.warnings.count) advisory warnings. Cached advisories were kept where available.\n" + result.warnings.joined(separator: "\n")
            } catch is CancellationError { notice = "Refresh cancelled. Cached patches were kept." }
            catch { notice = "Refresh failed. Cached patches were kept. \(error.localizedDescription)" }
        }
    }

    func cancelRefresh() { refreshTask?.cancel() }

    func chooseWorkspace() {
        guard !refreshing, !engineRunning else { notice = "Stop the current operation before changing workspace."; return }
        let picker = NSOpenPanel()
        picker.canChooseDirectories = true; picker.canChooseFiles = false
        picker.canCreateDirectories = true; picker.message = "Choose the RedApple engine workspace (REDAPPLE_HOME)."
        guard picker.runModal() == .OK, let url = picker.url else { return }
        workspace = Workspace(root: url)
        UserDefaults.standard.set(url.path, forKey: "workspace")
        database = nil; records = []; triage = [:]
        discovery = DiscoverySnapshot(workspace: workspace)
        reloadWorkspace()
    }

    func saveTriage(id: String, base: LeadTriage, status: String, notes: String) throws -> LeadTriage {
        triage = try workspace.saveTriage(id: id, base: base, edited: LeadTriage(status: status, notes: notes))
        return triage[id]!
    }

    func revealWorkspace() {
        do {
            try FileManager.default.createDirectory(at: workspace.root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            NSWorkspace.shared.open(workspace.root)
        } catch { notice = error.localizedDescription }
    }

    func revealArtifact(_ path: String) {
        let url = path.hasPrefix("/") ? URL(fileURLWithPath: path) : workspace.url(path)
        // Reveal only; engine artifacts are never executed by the app.
        guard FileManager.default.fileExists(atPath: url.path) else { notice = "Artifact not found at \(url.path)"; return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    func chooseEngineRepository() {
        let picker = NSOpenPanel()
        picker.canChooseDirectories = true; picker.canChooseFiles = false
        picker.message = "Choose the integrated RedApple repository containing ra.app_engine."
        if picker.runModal() == .OK, let url = picker.url {
            engineRepository = url.path
            UserDefaults.standard.set(url.path, forKey: "engineRepository")
        }
    }

    func runEngine() {
        guard !engineRunning else { return }
        do {
            let process = try configuredEngine(arguments: ["run", "--time-budget", String(timeBudget), "--json"])
            let fm = FileManager.default
            try fm.createDirectory(at: workspace.root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let log = workspace.url("native-engine.log")
            if !fm.fileExists(atPath: log.path) { fm.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o600]) }
            let handle = try FileHandle(forWritingTo: log)
            try handle.seekToEnd()
            process.standardOutput = handle; process.standardError = handle
            process.terminationHandler = { [weak self] process in
                try? handle.close()
                Task { @MainActor [weak self] in
                    self?.engineRunning = false; self?.engineProcess = nil
                    self?.engineMessage = process.terminationStatus == 0 ? "Engine run finished." : "Engine exited with code \(process.terminationStatus). Open the engine log for details."
                    self?.reloadDiscovery()
                }
            }
            try process.run()
            engineProcess = process; engineRunning = true
            engineMessage = "Engine started. Build output is in the engine log; discovery files refresh every 5 seconds."
        } catch { engineMessage = error.localizedDescription }
    }

    func stopEngine() {
        do {
            let process = try configuredEngine(arguments: ["stop", "--json"])
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            process.terminationHandler = { [weak self] process in
                Task { @MainActor [weak self] in
                    self?.engineMessage = process.terminationStatus == 0 ? "Stop requested. Waiting for engine cleanup." : "Stop failed. Check the engine log."
                    self?.reloadDiscovery()
                }
            }
            try process.run()
            engineMessage = "Requesting engine stop…"
        } catch { engineMessage = error.localizedDescription }
    }

    private func configuredEngine(arguments: [String]) throws -> Process {
        let repo = URL(fileURLWithPath: (engineRepository as NSString).expandingTildeInPath)
        guard !engineRepository.isEmpty, FileManager.default.fileExists(atPath: repo.appendingPathComponent("ra/app_engine/__main__.py").path) else {
            throw EngineError.configuration("Choose the integrated RedApple repository in Settings first. It must contain ra/app_engine.")
        }
        let python = (pythonPath as NSString).expandingTildeInPath
        guard FileManager.default.isExecutableFile(atPath: python) else { throw EngineError.configuration("Choose a valid Python 3 executable in Settings.") }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-m", "ra.app_engine"] + arguments
        process.currentDirectoryURL = repo
        var environment = ProcessInfo.processInfo.environment
        environment["REDAPPLE_HOME"] = workspace.root.path
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + (environment["PATH"] ?? "/usr/bin:/bin")
        if let key = KeychainStore.read(), !key.isEmpty { environment["DEEPSEEK_API_KEY"] = key }
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        return process
    }
    private enum EngineError: LocalizedError {
        case configuration(String)
        var errorDescription: String? { if case .configuration(let message) = self { return message }; return nil }
    }
}
