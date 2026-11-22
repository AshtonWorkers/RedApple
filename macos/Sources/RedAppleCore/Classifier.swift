import Foundation

/// Port of PR #1's classifier. A category ceiling is never a predicted CVE payout.
public struct BountyClassifier {
    public let catalog: BountyCatalog
    public init(catalog: BountyCatalog) { self.catalog = catalog }
    public func classify(component: String, impact: String, description: String = "", platform: String) -> BountyMatch {
        let text = (component + " " + impact).lowercased()
        let outcome = impact.lowercased()
        func has(_ words: [String], in value: String) -> Bool { words.contains { value.contains($0) } }
        let ios = platform.range(of: #"\b(?:ios|ipados)\b"#, options: [.regularExpression, .caseInsensitive]) != nil
        let mac = platform.lowercased().contains("macos")
        let browser = has(["webkit", "web content", "webcontent", "safari", "webpage"], in: text)
        let sandbox = text.contains("sandbox") && has(["escape", "break out", "bypass"], in: outcome)
        let code = has(["code execution", "execute arbitrary code", "execute code", "memory corruption", "corrupt memory", "corrupt kernel memory", "corrupt process memory", "kernel privileges"], in: outcome)
        let data = has(["sensitive user data", "sensitive data", "private information", "sensitive information", "location information", "protected data", "receive its messages", "photos", "request data"], in: outcome)
        let app = outcome.range(of: #"\b(?:an?|malicious) app(?:lication)?\b"#, options: .regularExpression) != nil
        let wireless = has(["bluetooth", "wi-fi", "wireless", "proximity", "in range"], in: text)
        let pcc = text.contains("private cloud compute") || text.range(of: #"\bpcc\b"#, options: .regularExpression) != nil
        var identifier: String?
        if pcc {
            if data && has(["configuration", "deployment", "accidental disclosure"], in: outcome) { identifier = "pcc-config" }
            else if outcome.contains("privileged network") {
                if outcome.contains("unattested") && code { identifier = "pcc-network-code" }
                else if data && outcome.contains("outside") { identifier = "pcc-network-data" }
            } else if outcome.contains("remote") && outcome.contains("request") {
                if outcome.contains("unsigned code") && outcome.contains("arbitrary entitlements") { identifier = "pcc-remote-code" }
                else if data && outcome.contains("outside") { identifier = "pcc-remote-data" }
            }
        } else if mac && text.contains("gatekeeper") && outcome.contains("bypass") {
            identifier = ["complete", "safari", "quarantin", "standard"].allSatisfy(outcome.contains) ? "macos-gatekeeper-complete" : "macos-gatekeeper-partial"
        } else if browser && sandbox { identifier = "category-8" }
        else if has(["physical access", "lock screen"], in: outcome) && outcome.contains("locked") && data { identifier = "category-4" }
        else if wireless && code && text.contains("apple-designed") && outcome.contains("application processor") && has(["in range", "proximity", "bluetooth range", "wi-fi range"], in: outcome) { identifier = "category-3" }
        else if browser && code { identifier = text.contains("kernel") ? "category-7" : "category-9" }
        else if mac {
            if (text.contains("tcc") && (data || outcome.contains("tcc target flag"))) || (data && app) {
                let flag = outcome.contains("tcc target flag")
                identifier = flag && sandbox ? "macos-tcc-sandbox" : flag ? "macos-tcc-flag" : "macos-tcc-data"
            } else if sandbox { identifier = "macos-sandbox" }
        } else if ios && app {
            if text.contains("kernel") && code { identifier = "category-5" }
            else if data { identifier = "category-6" }
        }
        let wild = has(["actively exploited", "exploited in the wild", "exploited against", "may have been exploited"], in: (impact + " " + description).lowercased())
        return BountyMatch(category: catalog.categories.first { $0.id == identifier }, inTheWild: wild)
    }
}
