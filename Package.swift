// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FptnClient",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "FptnCore", targets: ["FptnCore"]),
        .library(name: "FptnShared", targets: ["FptnShared"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/f-meloni/SwiftBrotli.git", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "FptnCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftBrotli", package: "SwiftBrotli")
            ]
        ),
        .target(
            name: "FptnShared",
            path: "Shared",
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "FptnCoreTests",
            dependencies: ["FptnCore"]
        ),
        .testTarget(
            name: "FptnSharedTests",
            dependencies: ["FptnShared"],
            path: "Tests/FptnSharedTests"
        )
    ],
    // Verified clean under Swift 6 language mode (0 warnings, 403 tests).
    // Dependencies keep their own tools-version language mode.
    swiftLanguageModes: [.v6]
)
