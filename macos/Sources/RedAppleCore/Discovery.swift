import Foundation

public struct DiscoveryStatus: Decodable {
    public var schemaVersion: Int
    public var state: String
    public var runId: String?
    public var model: String?
    public var updatedAt: String?
    public var message: String?
    public var executions: Int?
    public var crashes: Int?
    public var leads: Int?
}

public struct DiscoveryLead: Decodable, Identifiable {
    public var id: String
    public var title: String
    public var component: String?
    public var summary: String?
    public var assessment: String?
    public var createdAt: String?
    public var runId: String?
    public var artifactPath: String?
    public var categoryId: String?
    public var rating: String?
    public var notes: String? = nil
    public var originalStatus: String? = nil
    public var isEngine: Bool { runId != nil }
    public init(workbench: WorkbenchLead) {
        id = "workbench:" + workbench.id; title = workbench.target; component = workbench.kind
        summary = workbench.notes; createdAt = workbench.updatedAt; notes = workbench.notes
        originalStatus = workbench.status
    }
}

public struct EngineRun: Decodable, Identifiable {
    public var runId: String
    public var iteration: Int?
    public var startedAt: String?
    public var endedAt: String?
    public var wallS: Double?
    public var executions: Int?
    public var crashes: Int?
    public var leads: Int?
    public var newLeads: Int?
    public var model: String?
    public var id: String { runId }
}

public struct ChainStage: Decodable, Identifiable {
    public var stage: String
    public var status: String?
    public var detail: String?
    public var id: String { stage }
}

public struct EvidenceItem: Decodable, Identifiable {
    public var label: String
    public var value: String?
    public var detail: String?
    public var id: String { label }
}

public struct ProvenFinding: Decodable, Identifiable {
    public var id: String
    public var title: String
    public var component: String?
    public var summary: String?
    public var grade: String?
    public var confidence: Double?
    public var sourceKind: String?
    public var createdAt: String?
    public var runId: String?
    public var artifactPath: String?
    public var signature: String?
    public var chain: [ChainStage]
    public var evidence: [EvidenceItem]
    public var nextStep: String?
    public var isValidated: Bool { grade == "exploitable" || grade == "probably-exploitable" }
}

public struct ProvenFeed: Decodable {
    public var schemaVersion: Int?
    public var updatedAt: String?
    public var runId: String?
    public var findings: [ProvenFinding]?
}

public struct DiscoverySnapshot {
    public var status: DiscoveryStatus?
    public var leads: [DiscoveryLead]
    public var workbenchLeads: [WorkbenchLead]
    public var proven: [ProvenFinding]
    public var runs: [EngineRun]
    public var warnings: [String]
    public init(workspace: Workspace) {
        warnings = []; leads = []; workbenchLeads = []; proven = []; runs = []
        do { status = try workspace.load(DiscoveryStatus.self, from: "discovery/status.json") }
        catch { warnings.append("Engine status: \(error.localizedDescription)") }
        do { leads = try workspace.load([DiscoveryLead].self, from: "discovery/leads.json") ?? [] }
        catch { warnings.append("Engine leads: \(error.localizedDescription)") }
        do { workbenchLeads = try workspace.load([WorkbenchLead].self, from: "leads.json") ?? [] }
        catch { warnings.append("Workbench leads: \(error.localizedDescription)") }
        do {
            let feed = try workspace.load(ProvenFeed.self, from: "discovery/proven.json")
            proven = feed?.findings ?? []
        } catch { warnings.append("Proven findings: \(error.localizedDescription)") }
        do { runs = try workspace.load([EngineRun].self, from: "discovery/runs.json") ?? [] }
        catch { warnings.append("Engine runs: \(error.localizedDescription)") }
    }
    public var allLeads: [DiscoveryLead] {
        leads + workbenchLeads.filter { $0.origin != "webkit-discovery" }.map { DiscoveryLead(workbench: $0) }
    }
}
