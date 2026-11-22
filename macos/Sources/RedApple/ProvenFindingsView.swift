import SwiftUI
import AppKit
import RedAppleCore

private enum FindingsFilter: String, CaseIterable, Identifiable {
    case all = "All", highPotential = "High potential", validated = "Validated"
    var id: String { rawValue }
    func matches(_ finding: ProvenFinding) -> Bool {
        switch self {
        case .all: return true
        case .highPotential: return (finding.confidence ?? 0) >= 0.6
        case .validated: return finding.isValidated
        }
    }
}

struct ProvenFindingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var filter: FindingsFilter = .all
    @State private var selection: String?

    private var findings: [ProvenFinding] {
        model.discovery.proven.filter { filter.matches($0) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Text("Signals worth following.")
                    .font(.title3.weight(.semibold)).foregroundStyle(Theme.text)
                Spacer()
                Picker("Filter", selection: $filter) {
                    ForEach(FindingsFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 340)
                Text("\(findings.count) of \(model.discovery.proven.count)")
                    .font(.caption).foregroundStyle(Theme.secondary)
            }
            .padding(.horizontal, 24).padding(.vertical, 16)
            Divider().overlay(Theme.cardBorder)
            if findings.isEmpty {
                EmptyState(
                    icon: "checkmark.seal",
                    title: "No proven findings yet",
                    message: "Validated crashes and exploit chains the engine promotes will appear here with their evidence."
                )
            } else {
                HSplitView {
                    findingList.frame(minWidth: 320, idealWidth: 380, maxWidth: 460)
                    detail.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
    }

    private var findingList: some View {
        ScrollView {
            VStack(spacing: 10) {
                ForEach(findings) { finding in
                    Button { selection = finding.id } label: {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(finding.title).font(.callout.weight(.semibold)).foregroundStyle(Theme.text)
                                    .multilineTextAlignment(.leading).lineLimit(2)
                                Spacer(minLength: 8)
                                if finding.isValidated { Pill(text: "VALIDATED", color: Theme.accent) }
                            }
                            HStack(spacing: 8) {
                                if let component = finding.component, !component.isEmpty {
                                    Pill(text: component, color: Theme.blue)
                                }
                                if let grade = finding.grade {
                                    Pill(text: grade, color: gradeColor(grade))
                                }
                                if let kind = finding.sourceKind {
                                    Pill(text: kind, color: Theme.secondary)
                                }
                                Spacer()
                                if let confidence = finding.confidence {
                                    Text(String(format: "%.0f%%", confidence * 100))
                                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                        .foregroundStyle(Theme.secondary)
                                }
                            }
                        }
                        .padding(14)
                        .background(Theme.card, in: RoundedRectangle(cornerRadius: 12))
                        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(selection == finding.id ? Theme.accent.opacity(0.6) : Theme.cardBorder))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(16)
        }
        .background(Theme.background)
        .onAppear { if selection == nil { selection = findings.first?.id } }
        .onChange(of: filter) { _ in selection = findings.first?.id }
    }

    @ViewBuilder
    private var detail: some View {
        if let finding = findings.first(where: { $0.id == selection }) ?? findings.first {
            FindingDetail(finding: finding)
                .id(finding.id)
        } else {
            EmptyState(icon: "doc.text.magnifyingglass", title: "Select a finding", message: "Choose a proven finding to inspect its chain and evidence.")
        }
    }

    private func gradeColor(_ grade: String) -> Color {
        switch grade {
        case "exploitable", "probably-exploitable": return Theme.accent
        case "chain", "escalation": return Theme.blue
        default: return Theme.secondary
        }
    }
}

private struct FindingDetail: View {
    let finding: ProvenFinding
    @EnvironmentObject var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                chainCard
                evidenceCard
                nextStepCard
            }
            .padding(28)
            .frame(maxWidth: 720, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                if finding.isValidated { Pill(text: "VALIDATED", color: Theme.accent) }
                if let grade = finding.grade { Pill(text: grade, color: Theme.accent) }
                if let kind = finding.sourceKind { Pill(text: kind, color: Theme.blue) }
            }
            Text(finding.title).font(.title2.weight(.bold)).foregroundStyle(Theme.text)
            Text([finding.component, finding.summary].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " — "))
                .font(.callout).foregroundStyle(Theme.secondary)
            if let signature = finding.signature, !signature.isEmpty {
                Text("Signature \(signature)").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.secondary)
            }
        }
    }

    private var chainCard: some View {
        Panel {
            Text("Exploit-chain hypothesis").font(.headline).foregroundStyle(Theme.text)
            if finding.chain.isEmpty {
                Text("No chain stages recorded yet.").font(.callout).foregroundStyle(Theme.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(finding.chain.enumerated()), id: \.element.id) { index, stage in
                        HStack(alignment: .top, spacing: 14) {
                            VStack(spacing: 0) {
                                Circle()
                                    .fill(stageColor(stage.status))
                                    .frame(width: 12, height: 12)
                                    .overlay(Circle().stroke(Theme.cardBorder, lineWidth: 1))
                                if index < finding.chain.count - 1 {
                                    Rectangle().fill(Theme.cardBorder).frame(width: 1, height: 26)
                                }
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(stage.stage).font(.callout.weight(.semibold)).foregroundStyle(Theme.text)
                                    Spacer()
                                    Pill(text: (stage.status ?? "unproven").uppercased(), color: stageColor(stage.status))
                                }
                                if let detail = stage.detail, !detail.isEmpty {
                                    Text(detail).font(.caption).foregroundStyle(Theme.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
        }
    }

    private var evidenceCard: some View {
        Panel {
            Text("Evidence collected").font(.headline).foregroundStyle(Theme.text)
            if finding.evidence.isEmpty {
                Text("No structured evidence recorded yet.").font(.callout).foregroundStyle(Theme.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(finding.evidence) { item in
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "checkmark.circle.fill").font(.callout).foregroundStyle(Theme.green)
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(item.label).font(.callout.weight(.medium)).foregroundStyle(Theme.text)
                                    Spacer()
                                    if let value = item.value, !value.isEmpty {
                                        Text(value).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.secondary)
                                    }
                                }
                                if let detail = item.detail, !detail.isEmpty {
                                    Text(detail).font(.caption).foregroundStyle(Theme.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 9)
                        if item.id != finding.evidence.last?.id { Divider().overlay(Theme.cardBorder) }
                    }
                }
            }
        }
    }

    private var nextStepCard: some View {
        Panel {
            Text("RedApple's next step").font(.headline).foregroundStyle(Theme.text)
            Text(finding.nextStep ?? "Review the diagnostic artifact and record triage notes.")
                .font(.callout).foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let path = finding.artifactPath, !path.isEmpty {
                Button {
                    let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                } label: {
                    Label("Reveal Diagnostic Artifact", systemImage: "folder")
                }
                .buttonStyle(.bordered)
                .padding(.top, 4)
            }
        }
    }

    private func stageColor(_ status: String?) -> Color {
        switch status {
        case "confirmed": return Theme.accent
        case "supported": return Theme.green
        case "exploring": return Theme.amber
        default: return Theme.secondary
        }
    }
}
