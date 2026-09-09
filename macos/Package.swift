// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "Mailbench",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Mailbench", targets: ["Mailbench"])],
    targets: [.executableTarget(name: "Mailbench", path: "Sources/Mailbench")]
)
