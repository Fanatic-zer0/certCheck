// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Certcheck",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Certcheck",
            path: "Sources/Certcheck",
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        )
    ]
)
