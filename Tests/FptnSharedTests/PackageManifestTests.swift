import Foundation
import XCTest

/// The whole package is built and tested in Swift 6 language mode. This guard
/// prevents an accidental downgrade that would silently reintroduce the
/// concurrency errors found during the Swift 6 migration.
final class PackageManifestTests: XCTestCase {
    func testPackageUsesSwift6LanguageMode() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnSharedTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        let manifest = try String(
            contentsOf: root.appendingPathComponent("Package.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(
            manifest.contains("swiftLanguageModes: [.v6]"),
            "Package.swift must stay in Swift 6 language mode"
        )
    }
}
