import SwiftUI
import RedAppleCore

enum Theme {
    static let background = Color(red: 0.055, green: 0.055, blue: 0.07)
    static let sidebar = Color(red: 0.075, green: 0.075, blue: 0.09)
    static let card = Color(red: 0.11, green: 0.11, blue: 0.135)
    static let cardBorder = Color.white.opacity(0.08)
    static let accent = Color(red: 0.92, green: 0.22, blue: 0.28)
    static let accentSoft = accent.opacity(0.14)
    static let text = Color(red: 0.95, green: 0.95, blue: 0.97)
    static let secondary = Color(red: 0.62, green: 0.64, blue: 0.70)
    static let green = Color(red: 0.35, green: 0.82, blue: 0.55)
    static let amber = Color(red: 0.95, green: 0.72, blue: 0.30)
    static let blue = Color(red: 0.42, green: 0.62, blue: 0.98)
}

enum Section: String, CaseIterable, Identifiable {
    case discovery = "Discovery", proven = "Proven Findings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .discovery: return "radar"
        case .proven: return "checkmark.seal"
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
                HStack(spacing: 12) {
                    Image(systemName: "apple.logo").font(.system(size: 26, weight: .medium)).foregroundStyle(Theme.accent)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("RedApple").font(.title3.weight(.semibold)).foregroundStyle(Theme.text)
                        Text("SECURITY RESEARCH").font(.system(size: 9, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.secondary)
                    }
                    Spacer()
                }.padding(20).padding(.top, 10)
                List(selection: $section) {
                    SwiftUI.Section {
                        navRow(.discovery)
                        navRow(.proven)
                    } header: {
                        Text("PAGES").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.secondary)
                    }
                }
                .listStyle(.sidebar)
                .scrollContentBackground(.hidden)
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Circle().fill(model.engineRunning ? Theme.green : Theme.secondary).frame(width: 7, height: 7)
                        Text(model.engineRunning ? "Engine looping" : "Engine idle")
                            .font(.caption.weight(.medium)).foregroundStyle(Theme.text)
                    }
                    Text(model.workspace.root.lastPathComponent).font(.caption).foregroundStyle(Theme.secondary).lineLimit(1)
                    Button("Choose Workspace…") { model.chooseWorkspace() }.buttonStyle(.link).font(.caption)
                }
                .frame(maxWidth: .infinity, alignment: .leading).padding(16)
                .background(Theme.sidebar)
            }
            .background(Theme.sidebar)
            .navigationSplitViewColumnWidth(min: 210, ideal: 225, max: 260)
        } detail: {
            VStack(spacing: 0) {
                if let warning = model.discoveryWarning {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.amber)
                        Text(warning).lineLimit(1).foregroundStyle(Theme.secondary)
                        Spacer()
                    }.font(.caption).padding(10).background(Theme.amber.opacity(0.1))
                }
                switch section ?? .discovery {
                case .discovery: DashboardView()
                case .proven: ProvenFindingsView()
                }
            }
            .background(Theme.background)
            .navigationTitle((section ?? .discovery).rawValue)
            .toolbar {
                ToolbarItemGroup {
                    if model.notice != nil {
                        Button { showingNotice = true } label: { Image(systemName: "info.circle") }.help("Show latest workspace message")
                    }
                    Button { model.reloadDiscovery() } label: { Label("Reload", systemImage: "arrow.clockwise") }.help("Reload engine files")
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

    private func navRow(_ item: Section) -> some View {
        HStack {
            Label(item.rawValue, systemImage: item.icon)
            Spacer()
            if item == .proven && !model.discovery.proven.isEmpty {
                Text("\(model.discovery.proven.count)")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Theme.accent)
                    .padding(.horizontal, 7).padding(.vertical, 3)
                    .background(Theme.accentSoft, in: Capsule())
            }
        }
        .tag(item)
        .padding(.vertical, 4)
    }
}

struct Panel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) { content }
            .padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Theme.cardBorder))
    }
}

struct EmptyState: View {
    let icon: String
    let title: String
    let message: String
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 35, weight: .light)).foregroundStyle(Theme.secondary)
            Text(title).font(.title3.weight(.semibold)).foregroundStyle(Theme.text)
            Text(message).font(.callout).foregroundStyle(Theme.secondary).multilineTextAlignment(.center).frame(maxWidth: 400)
        }.padding(36).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct Pill: View {
    let text: String
    var color: Color = Theme.secondary
    var body: some View {
        Text(text).font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundStyle(color).padding(.horizontal, 8).padding(.vertical, 4)
            .background(color.opacity(0.12), in: Capsule())
    }
}

struct DetailField: View {
    let title: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.secondary)
            Text(value.isEmpty ? "Not provided" : value).font(.callout).foregroundStyle(Theme.text).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
