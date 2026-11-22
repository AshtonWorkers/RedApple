import SwiftUI
import RedAppleCore

struct DiscoveryView: View {
    @EnvironmentObject var model: AppModel
    @State private var showingEngineSettings = false
    let navigate: (Section) -> Void
    private var state: String { model.discovery.status?.state ?? "not connected" }
    private var stateColor: Color {
        ["failed", "error"].contains(state) ? .orange : state == "not connected" ? .secondary : .green
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Research, in motion.").font(.system(size: 32, weight: .bold, design: .rounded))
                        Text("Your Apple security discovery engine, in one native workspace.").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Pill(text: state.uppercased(), color: stateColor)
                }
                HStack(spacing: 16) {
                    metric("EXECUTIONS", value: model.discovery.status?.executions, icon: "arrow.triangle.2.circlepath")
                    metric("CRASHES", value: model.discovery.status?.crashes, icon: "waveform.path")
                    metric("DISCOVERED LEADS", value: model.discovery.leads.count, icon: "sparkle.magnifyingglass")
                }
                Panel {
                    HStack {
                        Label("Discovery Engine", systemImage: "cpu").font(.headline)
                        Spacer()
                        if let modelName = model.discovery.status?.model { Pill(text: modelName, color: .purple) }
                    }
                    Text(model.discovery.status?.message ?? "Connect the engine’s workspace to watch WebKit discovery runs and DeepSeek triage results appear here.")
                        .foregroundStyle(.secondary).textSelection(.enabled)
                    HStack(spacing: 8) {
                        ForEach(["building", "fuzzing", "triaging", "complete"], id: \.self) { phase in
                            HStack(spacing: 6) {
                                Circle().fill(state == phase ? Color.red : Color.secondary.opacity(0.25)).frame(width: 7, height: 7)
                                Text(phase.capitalized).font(.caption.weight(state == phase ? .bold : .regular))
                            }.frame(maxWidth: .infinity).padding(12).background(.quaternary.opacity(state == phase ? 0.6 : 0.25), in: RoundedRectangle(cornerRadius: 7))
                        }
                    }
                    if let status = model.discovery.status {
                        HStack {
                            Text("Run \(status.runId ?? "—")")
                            Spacer()
                            Text("Engine updated \(status.updatedAt ?? "unknown")")
                        }.font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                        Text("Status is reported by the engine, not a live process check.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        HStack {
                            Button("Choose Engine Workspace…") { model.chooseWorkspace() }
                            Button("Open Workspace") { model.revealWorkspace() }.buttonStyle(.link)
                        }
                    }
                    Divider()
                    HStack(spacing: 12) {
                        Button { model.runEngine() } label: { Label(model.engineRunning ? "Engine Running" : "Start Discovery", systemImage: "play.fill") }
                            .buttonStyle(.borderedProminent).disabled(model.engineRunning)
                        Button { model.stopEngine() } label: { Label("Stop", systemImage: "stop.fill") }
                        Button("Configure Engine…") { showingEngineSettings = true }
                            .buttonStyle(.link)
                        Spacer()
                        Button("Engine Log") { model.revealArtifact("native-engine.log") }.buttonStyle(.link)
                    }
                    if let message = model.engineMessage { Text(message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                }
                Panel {
                    HStack {
                        Text("Latest Leads").font(.headline)
                        Spacer()
                        Button("View all", action: { navigate(.leads) }).buttonStyle(.link)
                    }
                    if model.discovery.leads.isEmpty {
                        EmptyState(icon: "sparkle.magnifyingglass", title: "Waiting for the first finding", message: "New engine leads appear automatically. No sample findings or simulated progress are shown.")
                            .frame(height: 180)
                    } else {
                        ForEach(model.discovery.leads.prefix(5)) { lead in
                            HStack(alignment: .top) {
                                Image(systemName: "bolt.shield").foregroundStyle(.red).padding(.top, 3)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(lead.title).font(.headline)
                                    Text(lead.summary ?? lead.component ?? "Discovery lead").foregroundStyle(.secondary).lineLimit(2)
                                }
                                Spacer()
                                Pill(text: model.triage["engine:" + lead.id]?.status ?? "new", color: .orange)
                            }.padding(.vertical, 5)
                            if lead.id != model.discovery.leads.prefix(5).last?.id { Divider() }
                        }
                    }
                }
                HStack {
                    Label("Apple Patch Intelligence", systemImage: "square.stack.3d.up").font(.headline)
                    Text("\(Set(model.records.map { $0.cve.id }).count) unique CVEs · \(model.database?.releases.count ?? 0) releases").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Explore patches", action: { navigate(.patches) }).buttonStyle(.link)
                }
                Text("Watching \(model.workspace.root.path) · Reloads every 5 seconds")
                    .font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
            }.padding(30)
        }.background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $showingEngineSettings) {
            VStack {
                SettingsView()
                Button("Done") { showingEngineSettings = false }.keyboardShortcut(.cancelAction).padding(.bottom, 20)
            }.environmentObject(model)
        }
    }
    private func metric(_ title: String, value: Int?, icon: String) -> some View {
        Panel {
            HStack { Text(title).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(.secondary); Spacer(); Image(systemName: icon).foregroundStyle(.red) }
            Text(value.map { $0.formatted() } ?? "—").font(.system(size: 31, weight: .semibold, design: .rounded)).monospacedDigit()
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var apiKey = ""
    @State private var keyMessage: String?
    var body: some View {
        Form {
            SwiftUI.Section("Discovery engine") {
                Text(model.engineRepository.isEmpty ? "No engine repository selected" : model.engineRepository)
                    .font(.caption.monospaced()).textSelection(.enabled)
                Button("Choose Engine Repository…") { model.chooseEngineRepository() }.disabled(model.engineRunning)
                TextField("Python 3 executable", text: $model.pythonPath).disabled(model.engineRunning)
                Stepper("Fuzzing time budget: \(model.timeBudget) seconds", value: $model.timeBudget, in: 10...3600, step: 10)
                Text("Start Discovery runs the integrated engine’s Python module from the selected repository. Its first WebKit build may take much longer than the fuzzing time budget.").font(.caption).foregroundStyle(.secondary)
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
            SwiftUI.Section("Engine workspace") {
                Text(model.workspace.root.path).font(.caption.monospaced()).textSelection(.enabled)
                HStack {
                    Button("Choose Workspace…") { model.chooseWorkspace() }.disabled(model.refreshing)
                    Button("Reveal in Finder") { model.revealWorkspace() }
                }
                Text("Use the same folder as the engine’s REDAPPLE_HOME. Engine output is read-only; your triage notes stay in a separate native app file.").font(.caption).foregroundStyle(.secondary)
            }
            SwiftUI.Section("Apple patches") {
                Text("The app starts with the original workbench’s bundled advisory snapshot. Refresh checks Apple’s latest 20 releases and retains older cached history.").font(.caption).foregroundStyle(.secondary)
                Button("Refresh Apple Patches") { model.refreshPatches() }.disabled(model.refreshing)
            }
            SwiftUI.Section("About") {
                Text("RedApple · Native Apple security research workspace")
                Text("Bounty mappings are heuristic category ceilings, not confirmed eligibility or predicted rewards.").font(.caption).foregroundStyle(.secondary)
                Link("Apple Security Bounty", destination: URL(string: "https://security.apple.com/bounty/")!)
            }
        }.padding(24).frame(width: 570)
    }
}
