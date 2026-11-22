import Foundation

public enum JSON {
    public static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
    public static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

public struct PatchDatabase: Codable {
    public var source: String
    public var fetchedAt: String
    public var releases: [SecurityRelease]
    public static func bundled() throws -> Self {
        try JSON.decoder.decode(Self.self, from: Resources.data(named: "seed"))
    }
}

public struct SecurityRelease: Codable, Identifiable, Hashable {
    public var id: String { name + "|" + date }
    public var name: String
    public var availableFor: String
    public var date: String
    public var url: String?
    public var entries: [PatchEntry]
    public var builds: [String]?
    public var advisoryTitle: String?
    public var version: String?
    public var os: String?
    public var diffFrom: PreviousRelease?
    public var cveCount: Int { Set(entries.flatMap { $0.cves.map(\.id) }).count }
    public init(name: String, availableFor: String, date: String, url: String?, entries: [PatchEntry] = []) {
        self.name = name; self.availableFor = availableFor; self.date = date
        self.url = url; self.entries = entries
    }
}

public struct PreviousRelease: Codable, Hashable {
    public var name: String
    public var version: String
    public var url: String?
    public var date: String
}

public struct PatchEntry: Codable, Hashable {
    public var component: String
    public var availableFor: String
    public var impact: String
    public var description: String
    public var cves: [CVE]
    public init(component: String, availableFor: String = "", impact: String = "", description: String = "", cves: [CVE] = []) {
        self.component = component; self.availableFor = availableFor; self.impact = impact
        self.description = description; self.cves = cves
    }
}

public struct CVE: Codable, Hashable {
    public var id: String
    public var credit: String
    public init(id: String, credit: String = "") { self.id = id; self.credit = credit }
}

public struct BountyCatalog: Decodable {
    public var fetchedAt: String
    public var categories: [BountyCategory]
    public var mappingPolicy: String
    public static func bundled() throws -> Self {
        try JSON.decoder.decode(Self.self, from: Resources.data(named: "bounty_categories"))
    }
}

public struct BountyCategory: Decodable, Identifiable, Hashable {
    public var id: String
    public var program: String
    public var entryPoint: String
    public var endPoint: String
    public var maxReward: Int
    public var description: String
    public var source: String
    public var targetFlagRequired: Bool
    public var label: String { entryPoint + " / " + endPoint }
}

public struct BountyMatch {
    public var category: BountyCategory?
    public var inTheWild: Bool
    public var reason: String {
        category == nil ? "Entry point or qualifying outcome not established; review required." :
        "Likely category, not eligibility. Full chain, scope and Target Flags are unverified."
    }
}

public struct PatchRecord: Identifiable {
    public let release: SecurityRelease
    public let entry: PatchEntry
    public let cve: CVE
    public let match: BountyMatch
    public var id: String { release.id + "|" + entry.component + "|" + cve.id }
    public var searchableText: String { [release.name, entry.component, entry.impact, entry.description, cve.id, cve.credit].joined(separator: " ") }
}

public extension PatchDatabase {
    func records(classifier: BountyClassifier) -> [PatchRecord] {
        releases.flatMap { release in
            release.entries.flatMap { entry in
                entry.cves.map { cve in
                    PatchRecord(release: release, entry: entry, cve: cve,
                                match: classifier.classify(component: entry.component, impact: entry.impact,
                                                           description: entry.description, platform: release.name))
                }
            }
        }
    }
}

public extension Int {
    var dollars: String { formatted(.currency(code: "USD").precision(.fractionLength(0))) }
}
