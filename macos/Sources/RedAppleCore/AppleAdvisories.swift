import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SwiftSoup

public enum AdvisoryError: LocalizedError {
    case unrecognizedIndex, invalidResponse, unexpectedHost
    public var errorDescription: String? {
        switch self {
        case .unrecognizedIndex: return "Apple’s release index could not be recognized. Cached patches have been kept."
        case .invalidResponse: return "Apple’s advisory service returned an invalid response."
        case .unexpectedHost: return "The advisory URL is not on support.apple.com."
        }
    }
}

/// Uses the same table rows and heading/paragraph blocks as the original Python fetcher.
public enum AppleAdvisories {
    public static let index = "https://support.apple.com/en-us/100100"
    public static func parseIndex(_ html: String) throws -> [SecurityRelease] {
        let document = try SwiftSoup.parse(html)
        var releases: [SecurityRelease] = []
        for row in try document.select("tr") {
            let cells = try row.select("td")
            guard cells.size() == 3, let date = parseDate(try cells[2].text()) else { continue }
            let name = try cells[0].text().components(separatedBy: "This update")[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let hrefs = try cells[0].select("a[href]").array().map { try $0.attr("href") }
            let advisory = hrefs.compactMap { URL(string: $0, relativeTo: URL(string: index))?.absoluteURL }
                .first { $0.scheme == "https" && $0.host == "support.apple.com" && $0.path.range(of: #"/\d{6}"#, options: .regularExpression) != nil }
            releases.append(SecurityRelease(name: name, availableFor: try cells[1].text(), date: date, url: advisory?.absoluteString))
        }
        guard !releases.isEmpty else { throw AdvisoryError.unrecognizedIndex }
        return releases.sorted { $0.date > $1.date }
    }

    public static func parseAdvisory(_ html: String) throws -> (entries: [PatchEntry], title: String?, builds: [String]) {
        let document = try SwiftSoup.parse(html)
        var entries: [PatchEntry] = []
        var current: PatchEntry?
        var textBlocks: [String] = []
        let regex = try NSRegularExpression(pattern: #"CVE-\d{4}-\d{4,}"#)
        for block in try document.select("h1, h2, h3, p") {
            let tag = block.tagName()
            let text = try block.text()
            textBlocks.append(text)
            if tag == "h2" || tag == "h3" {
                if let entry = current, !entry.impact.isEmpty || !entry.cves.isEmpty { entries.append(entry) }
                current = PatchEntry(component: text)
            } else if current != nil {
                for (label, field) in [("Available for:", 0), ("Impact:", 1), ("Description:", 2)] where text.hasPrefix(label) {
                    let value = String(text.dropFirst(label.count)).trimmingCharacters(in: .whitespacesAndNewlines)
                    if field == 0 { current?.availableFor = value }
                    if field == 1 { current?.impact = value }
                    if field == 2 { current?.description = value }
                }
                if text.hasPrefix("CVE-") {
                    let nsText = text as NSString
                    let matches = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
                    for (offset, match) in matches.enumerated() {
                        let end = offset + 1 < matches.count ? matches[offset + 1].range.location : nsText.length
                        let start = NSMaxRange(match.range)
                        let credit = nsText.substring(with: NSRange(location: start, length: end - start)).trimmingCharacters(in: CharacterSet(charactersIn: ": ;,"))
                        current?.cves.append(CVE(id: nsText.substring(with: match.range), credit: credit))
                    }
                }
            }
        }
        if let entry = current, !entry.impact.isEmpty || !entry.cves.isEmpty { entries.append(entry) }
        let fullText = textBlocks.joined(separator: " ") as NSString
        let buildRegex = try NSRegularExpression(pattern: #"\b[Bb]uild\s+(\d{2}[A-Z]\d+[a-z]?)\b"#)
        let builds = Set(buildRegex.matches(in: fullText as String, range: NSRange(location: 0, length: fullText.length)).map { fullText.substring(with: $0.range(at: 1)) }).sorted()
        return (entries, try document.select("h1").first()?.text(), builds)
    }

    private static func parseDate(_ value: String) -> String? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        for format in ["d MMM yyyy", "MMMM d, yyyy", "d MMMM yyyy"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: value) {
                formatter.dateFormat = "yyyy-MM-dd"
                return formatter.string(from: date)
            }
        }
        return nil
    }

    public static func enrichVersions(_ releases: inout [SecurityRelease]) {
        let regex = try! NSRegularExpression(pattern: #"\b(iOS|iPadOS|macOS|tvOS|watchOS|visionOS|Safari)\b.*?(\d+(?:\.\d+)*)"#)
        for i in releases.indices {
            let name = releases[i].name as NSString
            if let match = regex.firstMatch(in: name as String, range: NSRange(location: 0, length: name.length)) {
                releases[i].os = name.substring(with: match.range(at: 1))
                releases[i].version = name.substring(with: match.range(at: 2))
            }
        }
        for i in releases.indices {
            guard let version = releases[i].version, let os = releases[i].os else { continue }
            let previous = releases.filter {
                $0.os == os && $0.date <= releases[i].date && $0.version?.split(separator: ".").first == version.split(separator: ".").first &&
                ($0.version ?? version).compare(version, options: .numeric) == .orderedAscending
            }.max { ($0.version ?? "").compare($1.version ?? "", options: .numeric) == .orderedAscending }
            releases[i].diffFrom = previous.map { PreviousRelease(name: $0.name, version: $0.version!, url: $0.url, date: $0.date) }
        }
    }
}

public struct RefreshResult {
    public var database: PatchDatabase
    public var warnings: [String]
}

public struct PatchFetcher {
    public typealias Downloader = (String) async throws -> String
    private let download: Downloader
    public init(download: @escaping Downloader = PatchFetcher.downloadApple) { self.download = download }

    public func refresh(previous: PatchDatabase, limit: Int = 20) async throws -> RefreshResult {
        let latest = try AppleAdvisories.parseIndex(try await download(AppleAdvisories.index))
        var old: [String: SecurityRelease] = [:]
        for release in previous.releases { old[release.id] = release }
        var warnings: [String] = []
        // Keep older cached releases; only refresh the latest window on each request.
        for var release in latest.prefix(limit) {
            try Task.checkCancellation()
            if let url = release.url {
                do {
                    let advisory = try AppleAdvisories.parseAdvisory(try await download(url))
                    // An empty parse must not silently replace an existing CVE-bearing advisory.
                    if advisory.entries.isEmpty, let cached = old[release.id], !cached.entries.isEmpty {
                        warnings.append("\(release.name): no entries recognized; kept cached advisory.")
                        continue
                    }
                    release.entries = advisory.entries; release.advisoryTitle = advisory.title; release.builds = advisory.builds
                } catch is CancellationError { throw CancellationError() }
                catch {
                    warnings.append("\(release.name): \(error.localizedDescription)")
                    if old[release.id] != nil { continue }
                }
            }
            old[release.id] = release
        }
        var releases = Array(old.values).sorted { $0.date == $1.date ? $0.name < $1.name : $0.date > $1.date }
        AppleAdvisories.enrichVersions(&releases)
        return RefreshResult(database: PatchDatabase(source: AppleAdvisories.index, fetchedAt: ISO8601DateFormatter().string(from: Date()), releases: releases), warnings: warnings)
    }

    public static func downloadApple(_ address: String) async throws -> String {
        guard let url = URL(string: address), url.host == "support.apple.com", url.scheme == "https" else { throw AdvisoryError.unexpectedHost }
        var request = URLRequest(url: url, timeoutInterval: 40)
        request.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15 RedApple/2.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
              response.url?.host == "support.apple.com", let html = String(data: data, encoding: .utf8) else { throw AdvisoryError.invalidResponse }
        return html
    }
}
