import SwiftUI
import RedAppleCore

struct LeadsView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var status = "all"
    @State private var selection: String?
    private var filtered: [DiscoveryLead] {
        let search = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.discovery.allLeads.filter { lead in
            let state = model.triage["engine:" + lead.id]?.status ?? lead.originalStatus ?? "new"
            return (status == "all" || state == status) && (search.isEmpty || (lead.title + " " + (lead.summary ?? "") + " " + (lead.component ?? "")).localizedCaseInsensitiveContains(search))
        }
    }
    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                VStack(spacing: 12) {
                    TextField("Search leads", text: $query).textFieldStyle(.roundedBorder)
                    Picker("Status", selection: $status) {
                        Text("All statuses").tag("all")
                        ForEach(["new", "idea", "investigating", "reported", "dupe", "paid", "archived"], id: \.self) { Text($0.capitalized).tag($0) }
                    }.labelsHidden()
                }.padding(16)
                Divider()
                if filtered.isEmpty {
                    EmptyState(icon: "sparkle.magnifyingglass", title: "No leads yet", message: "Engine findings and saved workbench leads appear here. Try clearing the filters or selecting the engine’s workspace.")
                } else {
                    List(selection: $selection) {
                        ForEach(filtered) { lead in
                            VStack(alignment: .leading, spacing: 7) {
                                Text(lead.title).font(.headline).lineLimit(2)
                                Text(lead.component ?? "Research lead").font(.caption).foregroundStyle(.secondary)
                                HStack {
                                    Pill(text: model.triage["engine:" + lead.id]?.status ?? lead.originalStatus ?? "new", color: .orange)
                                    if lead.isEngine { Pill(text: "DEEPSEEK", color: .purple) }
                                }
                            }.padding(.vertical, 8).tag(lead.id)
                        }
                    }.listStyle(.inset)
                }
                Text("\(filtered.count) leads · Live workspace feed").font(.caption).foregroundStyle(.secondary).padding(12)
            }.frame(minWidth: 280, idealWidth: 340, maxWidth: 420)
            if let lead = filtered.first(where: { $0.id == selection }) {
                LeadDetail(lead: lead).id(model.workspace.root.path + "|" + lead.id)
            } else {
                EmptyState(icon: "bolt.shield", title: "Select a lead", message: "Inspect the engine’s assessment, open its diagnostic artifacts, and keep your own triage notes.")
            }
        }
    }
}

struct LeadDetail: View {
    @EnvironmentObject var model: AppModel
    let lead: DiscoveryLead
    @State private var status = "new"
    @State private var notes = ""
    @State private var saveMessage: String?
    @State private var dirty = false
    @State private var base = LeadTriage()
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack { Pill(text: lead.isEngine ? "ENGINE FINDING" : "WORKBENCH LEAD", color: .red); Spacer(); if let rating = lead.rating { Pill(text: rating.uppercased() + " · MODEL ASSESSMENT", color: .orange) } }
                Text(lead.title).font(.title.bold()).textSelection(.enabled)
                if let run = lead.runId { DetailField(title: "Discovery run", value: run) }
                if let summary = lead.summary { DetailField(title: "Root cause / summary", value: summary) }
                if let assessment = lead.assessment { DetailField(title: "DeepSeek assessment · unverified", value: assessment) }
                if let category = model.catalog?.categories.first(where: { $0.id == lead.categoryId }) {
                    Panel {
                        Text(category.label).font(.headline)
                        Text("Category max \(category.maxReward.dollars)").foregroundStyle(.red).font(.title3.bold())
                        Text("Heuristic mapping, not eligibility or a predicted reward.").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let notes = lead.notes, notes != lead.summary { DetailField(title: "Engine / workbench notes", value: notes) }
                if let artifact = lead.artifactPath {
                    Button { model.revealArtifact(artifact) } label: { Label("Reveal Diagnostic Artifact", systemImage: "doc.text.magnifyingglass") }
                }
                Divider()
                Text("Your Triage").font(.title3.bold())
                Text("Saved separately from the engine’s output. A model’s assessment is not a verified vulnerability.").font(.caption).foregroundStyle(.secondary)
                Picker("Status", selection: $status) {
                    ForEach(["new", "idea", "investigating", "reported", "dupe", "paid", "archived"], id: \.self) { Text($0.capitalized).tag($0) }
                }.onChange(of: status) { _ in dirty = true }
                TextEditor(text: $notes).font(.body).frame(minHeight: 160).padding(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                    .onChange(of: notes) { _ in dirty = true }
                HStack {
                    Button("Save Triage") {
                        do {
                            let saved = try model.saveTriage(id: "engine:" + lead.id, base: base, status: status, notes: notes)
                            base = saved; status = saved.status; notes = saved.notes
                            dirty = false; saveMessage = "Saved."
                        } catch { saveMessage = "Could not save: \(error.localizedDescription)" }
                    }.buttonStyle(.borderedProminent).disabled(!dirty)
                    if dirty { Text("Unsaved changes").font(.caption).foregroundStyle(.orange) }
                }
                if let saveMessage { Text(saveMessage).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
            }.padding(28)
        }.frame(minWidth: 400)
        .onAppear {
            let saved = model.triage["engine:" + lead.id]
            status = saved?.status ?? lead.originalStatus ?? "new"
            notes = saved?.notes ?? ""
            base = saved ?? LeadTriage(status: status, notes: notes)
            dirty = false
        }
    }
}
