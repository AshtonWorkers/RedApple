import XCTest
@testable import RedAppleCore

final class CoreTests: XCTestCase {
    func testOriginalSnapshotAndCatalogLoad() throws {
        let database = try PatchDatabase.bundled()
        let catalog = try BountyCatalog.bundled()
        let records = database.records(classifier: BountyClassifier(catalog: catalog))
        XCTAssertGreaterThan(database.releases.count, 100)
        XCTAssertGreaterThan(Set(records.map { $0.cve.id }).count, 1000)
        XCTAssertEqual(catalog.categories.count, 28)
        XCTAssertTrue(records.contains { $0.match.category != nil })
    }

    func testPlatformScopeAndOutcomeRequiredForBounty() throws {
        let classifier = BountyClassifier(catalog: try .bundled())
        func category(_ component: String, _ impact: String, _ platform: String) -> String? {
            classifier.classify(component: component, impact: impact, platform: platform).category?.id
        }
        XCTAssertEqual(category("WebKit", "Processing web content may lead to arbitrary code execution", "Safari 27"), "category-9")
        XCTAssertEqual(category("Kernel", "An app may execute arbitrary code with kernel privileges", "iOS 27"), "category-5")
        XCTAssertNil(category("Kernel", "An app may execute arbitrary code with kernel privileges", "macOS 27"))
        XCTAssertNil(category("Bluetooth", "An attacker may cause a denial of service", "iOS 27"))
        XCTAssertEqual(category("Photos", "An app may access sensitive user data", "macOS 27"), "macos-tcc-data")
        XCTAssertEqual(category("TCC", "An app may escape the sandbox and capture the TCC Target Flag", "macOS 27"), "macos-tcc-sandbox")
        XCTAssertEqual(category("Gatekeeper", "An app may bypass Gatekeeper", "macOS 27"), "macos-gatekeeper-partial")
        XCTAssertNil(category("copyfile", "An app may bypass Gatekeeper checks", "iOS 27"))
    }

    func testExploitationStatusDoesNotInventAPayout() throws {
        let result = BountyClassifier(catalog: try .bundled()).classify(component: "ImageIO", impact: "May have been exploited in the wild", platform: "iOS 27")
        XCTAssertTrue(result.inTheWild)
        XCTAssertNil(result.category)
    }

    func testParsesIndexDatesAndRejectsThirdPartyAdvisories() throws {
        let html = """
        <table><tr><th>Product</th><th>Devices</th><th>Date</th></tr>
        <tr><td><a href="/en-us/123456">macOS 27.1</a></td><td>Mac</td><td>November 18, 2026</td></tr>
        <tr><td><a href="https://example.com/123456">iOS 27</a></td><td>iPhone</td><td>1 Sep 2026</td></tr></table>
        """
        let releases = try AppleAdvisories.parseIndex(html)
        XCTAssertEqual(releases.count, 2)
        XCTAssertEqual(releases[0].date, "2026-11-18")
        XCTAssertEqual(releases[0].url, "https://support.apple.com/en-us/123456")
        XCTAssertNil(releases[1].url)
        XCTAssertThrowsError(try AppleAdvisories.parseIndex("<p>Maintenance</p>"))
    }

    func testParsesMultipleCVEsAndPreservesMetadata() throws {
        let advisory = try AppleAdvisories.parseAdvisory("""
        <h1>About macOS 27.1</h1><p>Build 26A123</p><h2>WebKit</h2>
        <p>Available for: Mac</p><p>Impact: Web content may execute arbitrary code</p>
        <p>Description: Improved checks &amp; memory management.</p>
        <p>CVE-2026-12345: Alice; CVE-2026-12346: Bob</p>
        <h2>Kernel</h2><p>Impact: An app may corrupt kernel memory</p><p>CVE-2026-12347: Apple</p>
        """)
        XCTAssertEqual(advisory.entries.count, 2)
        XCTAssertEqual(advisory.entries[0].cves.map(\.id), ["CVE-2026-12345", "CVE-2026-12346"])
        XCTAssertEqual(advisory.entries[0].cves[0].credit, "Alice")
        XCTAssertEqual(advisory.entries[0].description, "Improved checks & memory management.")
        XCTAssertEqual(advisory.title, "About macOS 27.1")
        XCTAssertEqual(advisory.builds, ["26A123"])
    }

    func testFailedAdvisoryRefreshKeepsCachedCVEsBuildsAndHistory() async throws {
        let previous = try JSON.decoder.decode(PatchDatabase.self, from: Data("""
        {"source":"test","fetched_at":"old","releases":[
        {"name":"macOS 27.1","available_for":"Mac","date":"2026-11-18","url":"https://support.apple.com/en-us/123456","builds":["26A123"],"advisory_title":"Cached title","entries":[{"component":"WebKit","available_for":"Mac","impact":"Code execution","description":"Fix","cves":[{"id":"CVE-2026-12345","credit":"Alice"}]}]},
        {"name":"macOS 27.0","available_for":"Mac","date":"2026-10-01","entries":[]}
        ]}
        """.utf8))
        let fetcher = PatchFetcher { url in
            if url == AppleAdvisories.index {
                return "<table><tr><td><a href='/en-us/123456'>macOS 27.1</a></td><td>Mac</td><td>18 Nov 2026</td></tr></table>"
            }
            throw AdvisoryError.invalidResponse
        }
        let result = try await fetcher.refresh(previous: previous)
        XCTAssertEqual(result.database.releases.count, 2)
        let current = try XCTUnwrap(result.database.releases.first)
        XCTAssertEqual(current.cveCount, 1)
        XCTAssertEqual(current.builds, ["26A123"])
        XCTAssertEqual(current.advisoryTitle, "Cached title")
        XCTAssertEqual(current.diffFrom?.version, "27.0")
        XCTAssertEqual(result.warnings.count, 1)
    }

    func testWorkspaceWritesPrivateAtomicTriageWithoutTouchingEngine() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let workspace = Workspace(root: root)
        try workspace.save(["one": LeadTriage(status: "investigating", notes: "Research notes")], to: "native-triage.json")
        let loaded = try XCTUnwrap(workspace.load([String: LeadTriage].self, from: "native-triage.json"))
        XCTAssertEqual(loaded["one"]?.notes, "Research notes")
        try workspace.save(["one": LeadTriage(status: "reported", notes: "Updated")], to: "native-triage.json")
        XCTAssertEqual(try workspace.load([String: LeadTriage].self, from: "native-triage.json")?["one"]?.status, "reported")
        let mode = try FileManager.default.attributesOfItem(atPath: workspace.url("native-triage.json").path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["native-triage.json"])
    }

    func testEngineContractAndWorkbenchDeduplication() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent("discovery"), withIntermediateDirectories: true)
        try Data("""
        {"schema_version":1,"state":"triaging","model":"deepseek-flash","executions":42,"crashes":1,"leads":1}
        """.utf8).write(to: root.appendingPathComponent("discovery/status.json"))
        try Data("""
        [{"id":"crash-1","title":"WebKit diagnostic","summary":"Diagnostic finding","run_id":"run-1","artifact_path":"discovery/triage/crash-1.json","category_id":"category-9"}]
        """.utf8).write(to: root.appendingPathComponent("discovery/leads.json"))
        // v1 leads have no mandatory id field. Engine mirrors must not appear twice.
        try Data("""
        [{"kind":"component","target":"WebKit diagnostic","status":"investigating","notes":"Engine","updated_at":"today","origin":"webkit-discovery"},
        {"kind":"component","target":"Manual research","status":"idea","notes":"Manual","updated_at":"today"}]
        """.utf8).write(to: root.appendingPathComponent("leads.json"))
        let snapshot = DiscoverySnapshot(workspace: Workspace(root: root))
        XCTAssertTrue(snapshot.warnings.isEmpty)
        XCTAssertEqual(snapshot.status?.executions, 42)
        XCTAssertEqual(snapshot.leads.first?.categoryId, "category-9")
        XCTAssertEqual(snapshot.allLeads.count, 2)
    }

    func testIdenticalConcurrentTriageEditsAreIdempotent() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let workspace = Workspace(root: root)
        let base = LeadTriage(status: "new", notes: "old")
        _ = try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "investigating", notes: "old"))
        let merged = try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "investigating", notes: "newer notes"))
        XCTAssertEqual(merged["one"]?.status, "investigating")
        XCTAssertEqual(merged["one"]?.notes, "newer notes")
        let matchingNotes = try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "new", notes: "newer notes"))
        XCTAssertEqual(matchingNotes["one"]?.status, "investigating")
        XCTAssertEqual(matchingNotes["one"]?.notes, "newer notes")
    }

    func testStatusOnlyTriageMergesConcurrentNotesAndRejectsConflictingEdit() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let workspace = Workspace(root: root)
        let base = LeadTriage(status: "new", notes: "old")
        _ = try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "new", notes: "newer notes"))
        let merged = try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "investigating", notes: "old"))
        XCTAssertEqual(merged["one"]?.notes, "newer notes")
        XCTAssertEqual(merged["one"]?.status, "investigating")
        XCTAssertThrowsError(try workspace.saveTriage(id: "one", base: base, edited: LeadTriage(status: "new", notes: "stale overwrite")))
    }

    func testSavingPreservesPermissionsOfExistingSharedDirectory() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o770], ofItemAtPath: root.path)
        try Workspace(root: root).save(["note": "private"], to: "native-triage.json")
        let mode = try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o770)
    }
}
