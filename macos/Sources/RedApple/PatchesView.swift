import SwiftUI
import RedAppleCore

struct PatchesView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var releaseID: String?
    @State private var selectedRecord: String?
    private var releases: [SecurityRelease] { model.database?.releases ?? [] }
    private var activeRelease: SecurityRelease? { releases.first { $0.id == releaseID } ?? releases.first { $0.cveCount > 0 } }
    private var records: [PatchRecord] {
        let search = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.records.filter { $0.release.id == activeRelease?.id && (search.isEmpty || $0.searchableText.localizedCaseInsensitiveContains(search)) }
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.usingBundledPatches ? "BUNDLED APPLE SNAPSHOT" : "CACHED APPLE ADVISORIES").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(.secondary)
                    Text("Fetched \(model.database?.fetchedAt ?? "unknown")").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if model.refreshing {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { model.cancelRefresh() }
                } else {
                    Button { model.refreshPatches() } label: { Label("Refresh from Apple", systemImage: "arrow.clockwise") }
                }
            }.padding(16)
            if let notice = model.notice { Text(notice).font(.caption).foregroundStyle(.secondary).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).padding(.bottom, 10).help(notice) }
            Divider()
            HSplitView {
                List(selection: $releaseID) {
                    ForEach(releases) { release in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(release.name).font(.headline)
                            HStack { Text(release.date); Spacer(); Text("\(release.cveCount) CVEs") }.font(.caption).foregroundStyle(.secondary)
                        }.padding(.vertical, 8).tag(release.id)
                    }
                }.listStyle(.inset).frame(minWidth: 230, idealWidth: 260, maxWidth: 320)
                VStack(alignment: .leading, spacing: 0) {
                    if let release = activeRelease {
                        VStack(alignment: .leading, spacing: 9) {
                            Text(release.name).font(.title2.bold())
                            Text(release.availableFor).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            HStack {
                                if let previous = release.diffFrom {
                                    Text("Diff from \(previous.version) → \(release.version ?? "current")").font(.caption.monospaced())
                                    if let address = previous.url, let url = URL(string: address) { Link("Previous advisory", destination: url).font(.caption) }
                                }
                                Spacer()
                                if let address = release.url, let url = URL(string: address) { Link("Apple advisory ↗", destination: url).font(.caption) }
                            }
                            TextField("Search CVE, component or impact", text: $query).textFieldStyle(.roundedBorder)
                        }.padding(18)
                    }
                    Divider()
                    if records.isEmpty {
                        EmptyState(icon: "doc.text.magnifyingglass", title: "No matching CVEs", message: "This release may not publish CVE entries, or the search has no matches.")
                    } else {
                        List(selection: $selectedRecord) {
                            ForEach(records) { record in
                                VStack(alignment: .leading, spacing: 7) {
                                    HStack {
                                        Text(record.cve.id).font(.system(.headline, design: .monospaced))
                                        Spacer()
                                        if record.match.inTheWild { Pill(text: "EXPLOITED IN THE WILD", color: .orange) }
                                    }
                                    Text(record.entry.component).font(.subheadline.weight(.medium))
                                    Text(record.entry.impact).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                                    if let category = record.match.category {
                                        Text("Category max \(category.maxReward.dollars) · \(category.entryPoint)").font(.caption.weight(.medium)).foregroundStyle(.red)
                                    } else { Text("Unmapped · review required").font(.caption).foregroundStyle(.secondary) }
                                }.padding(.vertical, 9).tag(record.id)
                            }
                        }.listStyle(.inset)
                    }
                }.frame(minWidth: 320)
                if let record = records.first(where: { $0.id == selectedRecord }) {
                    PatchDetail(record: record).frame(minWidth: 280, idealWidth: 330, maxWidth: 450)
                }
            }
        }
    }
}

struct PatchDetail: View {
    let record: PatchRecord
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text(record.cve.id).font(.title3.bold().monospaced()).textSelection(.enabled)
                DetailField(title: "Component", value: record.entry.component)
                DetailField(title: "Impact", value: record.entry.impact)
                DetailField(title: "Fix", value: record.entry.description)
                DetailField(title: "Credit", value: record.cve.credit)
                if let category = record.match.category {
                    DetailField(title: "Likely bounty category", value: category.label)
                    Text("Category max \(category.maxReward.dollars)").font(.title3.bold()).foregroundStyle(.red)
                    if category.targetFlagRequired { Pill(text: "TARGET FLAG REQUIRED", color: .orange) }
                }
                Text(record.match.reason).font(.caption).foregroundStyle(.secondary)
                Text("A patched CVE is not itself a new bounty finding.").font(.caption).foregroundStyle(.secondary)
                Link("Apple’s current bounty categories ↗", destination: URL(string: "https://security.apple.com/bounty/categories/")!).font(.caption)
            }.padding(22)
        }
    }
}

struct BountiesView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Outcome, not bug class.").font(.system(size: 30, weight: .bold, design: .rounded))
                Text("Apple’s published reward ceilings. Full exploit-chain evidence, scope and Target Flags determine eligibility — these are not predicted payouts.").foregroundStyle(.secondary)
                HStack {
                    Text("Snapshot \(model.catalog?.fetchedAt ?? "unknown")").font(.caption.monospaced()).foregroundStyle(.secondary)
                    Spacer()
                    Link("Current Apple categories ↗", destination: URL(string: "https://security.apple.com/bounty/categories/")!)
                }
                TextField("Search categories", text: $query).textFieldStyle(.roundedBorder)
                ForEach((model.catalog?.categories ?? []).filter { query.isEmpty || ($0.label + " " + $0.program).localizedCaseInsensitiveContains(query) }) { category in
                    Panel {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 7) {
                                Text(category.program.uppercased()).font(.caption.monospaced()).foregroundStyle(.secondary)
                                Text(category.entryPoint).font(.headline)
                                Text(category.endPoint).foregroundStyle(.secondary)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 7) {
                                Text(category.maxReward.dollars).font(.title2.bold()).foregroundStyle(.red)
                                Text("CATEGORY MAX").font(.system(size: 9, weight: .semibold, design: .monospaced)).foregroundStyle(.secondary)
                            }
                        }
                        if category.targetFlagRequired { Pill(text: "TARGET FLAG REQUIRED", color: .orange) }
                    }
                }
            }.padding(30)
        }.background(Color(nsColor: .windowBackgroundColor))
    }
}
