// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FptnProbe",
    dependencies: [
        .package(path: "../..")
    ],
    targets: [
        .executableTarget(
            name: "FptnProbe",
            dependencies: [
                .product(name: "FptnCore", package: "FptnClient-iOS")
            ]
        )
    ],
    swiftLanguageModes: [.v5]
)
