import Foundation

enum Resources {
    static func data(named name: String) throws -> Data {
        // SwiftPM's generated Bundle.module accessor assumes a CLI-style sibling
        // bundle and may embed a build-machine fallback. A real .app uses Resources.
        if let resourceRoot = Bundle.main.resourceURL {
            let packaged = resourceRoot.appendingPathComponent("RedApple_RedAppleCore.bundle")
            if let bundle = Bundle(url: packaged), let url = bundle.url(forResource: name, withExtension: "json") {
                return try Data(contentsOf: url)
            }
        }
        if Bundle.main.bundleURL.pathExtension == "app" { throw CocoaError(.fileReadNoSuchFile) }
        guard let url = Bundle.module.url(forResource: name, withExtension: "json") else { throw CocoaError(.fileReadNoSuchFile) }
        return try Data(contentsOf: url)
    }
}
