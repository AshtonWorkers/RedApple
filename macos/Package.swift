// swift-tools-version: 5.9
import PackageDescription

var products: [Product] = [.library(name: "RedAppleCore", targets: ["RedAppleCore"])]
var targets: [Target] = [
    .target(name: "RedAppleCore", dependencies: ["SwiftSoup"], resources: [.process("Resources")]),
    .testTarget(name: "RedAppleCoreTests", dependencies: ["RedAppleCore"])
]
#if os(macOS)
products.append(.executable(name: "RedApple", targets: ["RedApple"]))
targets.append(.executableTarget(name: "RedApple", dependencies: ["RedAppleCore"]))
#endif

let package = Package(
    name: "RedApple",
    platforms: [.macOS(.v13)],
    products: products,
    dependencies: [
        .package(url: "https://github.com/scinfu/SwiftSoup.git", exact: "2.7.6")
    ],
    targets: targets
)
