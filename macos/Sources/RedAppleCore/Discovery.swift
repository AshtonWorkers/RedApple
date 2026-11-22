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

public struct DiscoverySnapshot {
    public var status: DiscoveryStatus?
    public var leads: [DiscoveryLead]
    public var workbenchLeads: [WorkbenchLead]
    public var warnings: [String]
    public init(workspace: Workspace) {
        warnings = []; leads = []; workbenchLeads = []
        do { status = try workspace.load(DiscoveryStatus.self, from: "discovery/status.json") }
        catch { warnings.append("Engine status: \(error.localizedDescription)") }
        do { leads = try workspace.load([DiscoveryLead].self, from: "discovery/leads.json") ?? [] }
        catch { warnings.append("Engine leads: \(error.localizedDescription)") }
        do { workbenchLeads = try workspace.load([WorkbenchLead].self, from: "leads.json") ?? [] }
        catch { warnings.append("Workbench leads: \(error.localizedDescription)") }
    }
    public var allLeads: [DiscoveryLead] {
        leads + workbenchLeads.filter { $0.origin != "webkit-discovery" }.map { DiscoveryLead(workbench: $0) }
    }
}
