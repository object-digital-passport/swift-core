// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-core",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        // Everything a conforming implementation needs, with no platform
        // dependencies: canonical form, hashes, registry reads, wallet crypto.
        .library(name: "ODPCore", targets: ["ODPCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Boilertalk/secp256k1.swift", exact: "0.1.7"),
    ],
    targets: [
        .target(
            name: "ODPCore",
            dependencies: [.product(name: "secp256k1", package: "secp256k1.swift")],
            resources: [.process("Resources")]
        ),
        .testTarget(name: "ODPCoreTests", dependencies: ["ODPCore"]),
    ]
)
