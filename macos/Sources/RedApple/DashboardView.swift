import SwiftUI
import RedAppleCore

struct DashboardView: View {
    @EnvironmentObject var model: AppModel

    private var status: DiscoveryStatus? { model.discovery.status }
    private var runs: [EngineRun] { model.discovery.runs }
    private var latestRun: EngineRun? { runs.last }
    private var leads: [DiscoveryLead] { model.discovery.allLeads }
    private var activity: [EngineRun] { Array(runs.suffix(6).reversed()) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                hero
                metrics
                pipeline
                HStack(alignment: .top, spacing: 20) {
                    latestLeads.frame(maxWidth: .infinity)
                    activityPanel.frame(maxWidth: .infinity)
                }
            }
            .padding(32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var hero: some View {
        HStack(spacing: 36) {
            VStack(alignment: .leading, spacing: 14) {
                Text("You start it.")
                    .font(.system(size: 46, weight: .bold))
                    .foregroundStyle(Theme.text)
                Text("It takes it from here.")
                    .font(.system(size: 46, weight: .bold))
                    .foregroundStyle(Theme.accent)
                Text("RedApple loops WebKit discovery on its own — fuzzing, triaging, and promoting validated chains — until you press Stop.")
                    .font(.callout)
                    .foregroundStyle(Theme.secondary)
                    .frame(maxWidth: 460)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 14) {
                    Button(action: { model.engineRunning ? model.stopEngine() : model.runEngine() }) {
                        HStack(spacing: 8) {
                            Image(systemName: model.engineRunning ? "stop.fill" : "play.fill")
                            Text(model.engineRunning ? "Stop" : "Start").font(.headline)
                        }
                        .padding(.horizontal, 26).padding(.vertical, 13)
                        .background(model.engineRunning ? Theme.card : Theme.accent, in: Capsule())
                        .foregroundStyle(model.engineRunning ? Theme.text : .white)
                    }
                    .buttonStyle(.plain)
                    .disabled(!model.engineRunning && !model.engineConfigured)
                    .opacity(!model.engineRunning && !model.engineConfigured ? 0.5 : 1)
                    if let message = model.engineMessage {
                        Text(message).font(.caption).foregroundStyle(Theme.secondary).lineLimit(2)
                    }
                }
                .padding(.top, 6)
            }
            Spacer()
            radar
        }
    }

    private var radar: some View {
        ZStack {
            Circle().stroke(Theme.accent.opacity(0.12), lineWidth: 1).frame(width: 210, height: 210)
            Circle().stroke(Theme.accent.opacity(0.22), lineWidth: 1).frame(width: 140, height: 140)
            Circle().stroke(Theme.accent.opacity(0.35), lineWidth: 1).frame(width: 70, height: 70)
            Circle().fill(Theme.accentSoft).frame(width: 34, height: 34)
            Image(systemName: "apple.logo").font(.system(size: 40, weight: .medium)).foregroundStyle(Theme.accent)
        }
        .frame(width: 230, height: 230)
    }

    private var metrics: some View {
        HStack(spacing: 16) {
            MetricCard(title: "Executions", value: "\(status?.executions ?? 0)", detail: lastRunDetail(keyPath: \.executions), icon: "bolt.fill")
            MetricCard(title: "Crashes", value: "\(status?.crashes ?? 0)", detail: lastRunDetail(keyPath: \.crashes), icon: "exclamationmark.triangle.fill")
            MetricCard(
                title: "Discovered Leads",
                value: "\(status?.leads ?? leads.count)",
                detail: "\(model.discovery.proven.filter { $0.isValidated }.count) validated • \(model.discovery.proven.count) under investigation",
                icon: "sparkle.magnifyingglass"
            )
        }
    }

    private func lastRunDetail(keyPath: KeyPath<EngineRun, Int?>) -> String {
        guard let value = latestRun?[keyPath: keyPath] else { return "No cycles yet" }
        return "+\(value) last cycle"
    }

    private var pipeline: some View {
        Panel {
            HStack(alignment: .top, spacing: 0) {
                pipelineStage("Building", subtitle: "Corpus & engine ready", index: 0)
                pipelineConnector
                pipelineStage("Fuzzing", subtitle: "JavaScriptCore executions", index: 1)
                pipelineConnector
                pipelineStage("Triaging", subtitle: "Crashes graded & chained", index: 2)
                pipelineConnector
                pipelineStage("Complete", subtitle: "Leads & findings published", index: 3)
            }
            HStack {
                Text(statusLabel).font(.caption.weight(.medium)).foregroundStyle(Theme.secondary)
                Spacer()
                if let message = status?.message, !message.isEmpty {
                    Text(message).font(.caption).foregroundStyle(Theme.secondary).lineLimit(1)
                }
            }
        }
    }

    private var pipelineConnector: some View {
        Rectangle().fill(Theme.cardBorder).frame(height: 1).frame(maxWidth: .infinity).padding(.top, 18)
    }

    private func pipelineStage(_ title: String, subtitle: String, index: Int) -> some View {
        let stageState = stageState(for: index)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Circle()
                    .fill(stageState.color)
                    .frame(width: 10, height: 10)
                    .overlay(Circle().stroke(Theme.cardBorder, lineWidth: 1))
                Text(title).font(.callout.weight(.semibold)).foregroundStyle(Theme.text)
            }
            Text(subtitle).font(.caption).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var currentStageIndex: Int {
        switch status?.state {
        case "building": return 0
        case "fuzzing": return 1
        case "triaging": return 2
        case "complete": return 3
        default: return model.engineRunning ? 1 : -1
        }
    }

    private func stageState(for index: Int) -> StageState {
        let current = currentStageIndex
        if current < 0 { return .pending }
        if index < current { return .done }
        if index == current { return .active }
        return .pending
    }

    private var statusLabel: String {
        if model.engineRunning { return "Engine looping — discovery runs back-to-back until Stop." }
        switch status?.state {
        case "stopped": return "Stopped. Start again to keep looping."
        case "failed": return "Engine reported a failure. See the engine log."
        case "complete": return "Run complete."
        default: return "Idle. Press Start and RedApple takes it from here."
        }
    }

    private var latestLeads: some View {
        Panel {
            HStack {
                Text("Latest leads").font(.headline).foregroundStyle(Theme.text)
                Spacer()
                Pill(text: "\(leads.count)", color: Theme.blue)
            }
            if leads.isEmpty {
                EmptyState(icon: "tray", title: "No leads yet", message: "Start the engine and discovered crashes, chains, and escalations will appear here.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(leads.prefix(5))) { lead in
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(lead.title).font(.callout.weight(.medium)).foregroundStyle(Theme.text).lineLimit(1)
                                Text([lead.component, lead.summary].compactMap { $0 }.joined(separator: " · "))
                                    .font(.caption).foregroundStyle(Theme.secondary).lineLimit(2)
                            }
                            Spacer()
                            if let rating = lead.rating {
                                Pill(text: rating, color: ratingColor(rating))
                            }
                        }
                        .padding(.vertical, 10)
                        if lead.id != leads.prefix(5).last?.id { Divider().overlay(Theme.cardBorder) }
                    }
                }
            }
        }
    }

    private var activityPanel: some View {
        Panel {
            HStack {
                Text("Activity").font(.headline).foregroundStyle(Theme.text)
                Spacer()
                Pill(text: "\(runs.count) cycles", color: Theme.green)
            }
            if activity.isEmpty {
                EmptyState(icon: "clock", title: "No cycles yet", message: "Each loop cycle — fuzz, triage, publish — shows up here.")
            } else {
                VStack(spacing: 0) {
                    ForEach(activity) { run in
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "circle.fill").font(.system(size: 6)).foregroundStyle(Theme.accent).padding(.top, 5)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Cycle \(run.iteration ?? 0) complete").font(.callout.weight(.medium)).foregroundStyle(Theme.text)
                                Text("\(run.executions ?? 0) executions · \(run.crashes ?? 0) crashes · +\(run.newLeads ?? 0) new leads")
                                    .font(.caption).foregroundStyle(Theme.secondary)
                            }
                            Spacer()
                            Text(shortTime(run.endedAt)).font(.caption).foregroundStyle(Theme.secondary)
                        }
                        .padding(.vertical, 10)
                        if run.id != activity.last?.id { Divider().overlay(Theme.cardBorder) }
                    }
                }
            }
        }
    }

    private func ratingColor(_ rating: String) -> Color {
        switch rating {
        case "exploitable", "probably-exploitable": return Theme.accent
        case "chain", "escalation": return Theme.blue
        case "unknown": return Theme.amber
        default: return Theme.secondary
        }
    }

    private func shortTime(_ value: String?) -> String {
        guard let value, let date = ISO8601DateFormatter().date(from: value) else { return "" }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

private enum StageState {
    case done, active, pending
    var color: Color {
        switch self {
        case .done: return Theme.green
        case .active: return Theme.accent
        case .pending: return Theme.secondary.opacity(0.4)
        }
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let detail: String
    let icon: String
    var body: some View {
        Panel {
            HStack {
                Image(systemName: icon).font(.title3).foregroundStyle(Theme.accent)
                Spacer()
            }
            Text(value).font(.system(size: 34, weight: .bold, design: .rounded)).foregroundStyle(Theme.text)
            Text(title).font(.caption.weight(.medium)).foregroundStyle(Theme.secondary)
            Text(detail).font(.system(size: 10, weight: .medium, design: .monospaced)).foregroundStyle(Theme.secondary.opacity(0.8))
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var apiKey = ""
    @State private var keyMessage: String?

    var body: some View {
        Form {
            SwiftUI.Section("Engine") {
                LabeledContent("Repository") {
                    HStack {
                        Text(model.engineRepository.isEmpty ? "Not configured" : (model.engineRepository as NSString).lastPathComponent)
                            .lineLimit(1).truncationMode(.middle)
                        Button("Choose…") { model.chooseEngineRepository() }
                    }
                }
                TextField("Python 3 executable", text: $model.pythonPath).disabled(model.engineRunning)
                Stepper("Cycle time budget: \(model.timeBudget) seconds", value: $model.timeBudget, in: 10...3600, step: 10)
                Text("Start runs the engine's discovery loop: it fuzzes, triages, and publishes findings back-to-back until you press Stop.")
                    .font(.caption).foregroundStyle(.secondary)
                SecureField("DeepSeek API key", text: $apiKey)
                HStack {
                    Button("Save to Keychain") {
                        do { try KeychainStore.save(apiKey.trimmingCharacters(in: .whitespacesAndNewlines)); apiKey = ""; keyMessage = "API key saved in macOS Keychain." }
                        catch { keyMessage = error.localizedDescription }
                    }.disabled(apiKey.isEmpty)
                    Button("Remove Saved Key") {
                        do { try KeychainStore.save(""); keyMessage = "Saved API key removed." }
                        catch { keyMessage = error.localizedDescription }
                    }
                }
                Text(keyMessage ?? "The key is passed only to the engine process; it is never saved in workspace JSON.").font(.caption).foregroundStyle(.secondary)
            }
            SwiftUI.Section("Workspace") {
                LabeledContent("REDAPPLE_HOME") {
                    Text(model.workspace.root.path).lineLimit(1).truncationMode(.middle)
                }
                Button("Choose Workspace…") { model.chooseWorkspace() }.disabled(model.engineRunning)
            }
            SwiftUI.Section("About") {
                LabeledContent("RedApple", value: "Continuous WebKit discovery")
                LabeledContent("Workspace files", value: "status · leads · runs · proven findings")
            }
        }
        .formStyle(.grouped)
        .frame(width: 560, height: 620)
    }
}
