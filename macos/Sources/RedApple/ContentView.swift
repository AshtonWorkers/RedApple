import SwiftUI
import RedAppleCore

enum Section: String, CaseIterable, Identifiable {
    case discovery = "Discovery", leads = "Leads", patches = "Apple Patches", bounty = "Bounty Categories"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .discovery: return "waveform.path.ecg"
        case .leads: return "sparkle.magnifyingglass"
        case .patches: return "square.stack.3d.up"
        case .bounty: return "target"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @State private var section: Section? = .discovery
    @State private var showingNotice = false
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "apple.logo").font(.system(size: 27)).foregroundStyle(.red)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("RedApple").font(.title2.bold())
                        Text("SECURITY RESEARCH").font(.system(size: 9, weight: .semibold, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    Spacer()
                }.padding(20).padding(.top, 8)
                List(selection: $section) {
                    SwiftUI.Section("WORKSPACE") {
                        ForEach(Section.allCases) { item in
                            Label(item.rawValue, systemImage: item.icon).tag(item)
                                .padding(.vertical, 5)
                        }
                    }
                }.listStyle(.sidebar)
                VStack(alignment: .leading, spacing: 8) {
                    Label("Local research workspace", systemImage: "internaldrive")
                        .font(.caption.weight(.medium))
                    Text(model.workspace.root.lastPathComponent).font(.caption).foregroundStyle(.secondary)
                    Button("Choose Workspace…") { model.chooseWorkspace() }.buttonStyle(.link)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            }.navigationSplitViewColumnWidth(min: 215, ideal: 230, max: 280)
        } detail: {
            VStack(spacing: 0) {
                if let warning = model.discoveryWarning {
                    HStack {
                        Label("Engine data needs attention", systemImage: "exclamationmark.triangle")
                        Text(warning).lineLimit(1).foregroundStyle(.secondary)
                        Spacer()
                    }.font(.caption).padding(10).background(.orange.opacity(0.12)).help(warning)
                }
                switch section ?? .discovery {
                case .discovery: DiscoveryView(navigate: { section = $0 })
                case .leads: LeadsView()
                case .patches: PatchesView()
                case .bounty: BountiesView()
                }
            }
            .navigationTitle((section ?? .discovery).rawValue)
            .toolbar {
                ToolbarItemGroup {
                    if model.notice != nil {
                        Button { showingNotice = true } label: { Image(systemName: "info.circle") }.help("Show latest patch refresh or workspace message")
                    }
                    Button { model.reloadDiscovery() } label: { Label("Reload Discovery", systemImage: "arrow.clockwise") }.help("Reload engine files")
                    Button { model.revealWorkspace() } label: { Label("Workspace", systemImage: "folder") }.help("Reveal workspace in Finder")
                }
            }
            .sheet(isPresented: $showingNotice) {
                VStack(alignment: .leading, spacing: 20) {
                    Text("Workspace Update").font(.title2.bold())
                    ScrollView { Text(model.notice ?? "No new messages.").textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    HStack { Spacer(); Button("Done") { showingNotice = false }.keyboardShortcut(.defaultAction) }
                }.padding(24).frame(width: 560, height: 350)
            }
        }
    }
}

struct Panel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) { content }
            .padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary))
    }
}

struct EmptyState: View {
    let icon: String
    let title: String
    let message: String
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 35, weight: .light)).foregroundStyle(.secondary)
            Text(title).font(.title3.weight(.semibold))
            Text(message).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 400)
        }.padding(36).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct Pill: View {
    let text: String
    var color: Color = .secondary
    var body: some View {
        Text(text).font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundStyle(color).padding(.horizontal, 8).padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
    }
}

struct DetailField: View {
    let title: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(.secondary)
            Text(value.isEmpty ? "Not provided" : value).font(.callout).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
