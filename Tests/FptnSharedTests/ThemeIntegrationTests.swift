import Foundation
import XCTest

/// The SwiftUI layer and the Xcode test target can only be type-checked by the
/// macOS CI job. These guards keep them connected to the shared theme tokens
/// and to CI from Linux.
final class ThemeIntegrationTests: XCTestCase {
    private func source(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnSharedTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    func testPaletteAdapterUsesSharedTokensWithoutDuplicatingColors() throws {
        let adapter = try source("App/Theme/AppTheme.swift")
        XCTAssertTrue(adapter.contains("ThemeTokens"), "palette must use shared tokens")
        XCTAssertTrue(adapter.contains("Color(tokens."), "palette must map tokens onto Color")
        XCTAssertFalse(
            adapter.contains("Color(red:"),
            "colour literals must not be duplicated outside ThemeTokens"
        )
    }

    func testViewsConsumeTheSharedPalette() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let directories = ["App/Views", "App/Theme"]
        for directory in directories {
            let enumerator = try XCTUnwrap(
                FileManager.default.enumerator(
                    at: root.appendingPathComponent(directory),
                    includingPropertiesForKeys: nil
                ),
                "Missing \(directory)"
            )
            while let url = enumerator.nextObject() as? URL {
                guard url.pathExtension == "swift" else { continue }
                let text = try String(contentsOf: url, encoding: .utf8)
                XCTAssertFalse(
                    text.contains("Color(red:"),
                    "\(url.lastPathComponent) must not hard-code theme colours"
                )
            }
        }
    }

    func testXcodeThemeUITestTargetIsConfigured() throws {
        let project = try source("project.yml")
        XCTAssertTrue(project.contains("FptnClientTests"), "missing UI test target")
        XCTAssertTrue(project.contains("test:"), "scheme must have a test action")
        let workflow = try source(".github/workflows/ci.yml")
        XCTAssertTrue(workflow.contains("Run theme UI tests"), "CI must run the theme UI tests")
        XCTAssertTrue(workflow.contains("platform=iOS Simulator,name="), "tests need a simulator")
        XCTAssertTrue(workflow.contains("            test"), "xcodebuild must use the test action")
    }

    func testUITestsRenderEveryTheme() throws {
        let tests = try source("Tests/FptnClientTests/ThemeRenderingTests.swift")
        XCTAssertTrue(tests.contains("ImageRenderer"), "UI tests must render SwiftUI views")
        XCTAssertTrue(tests.contains("AppTheme.allCases"), "both themes must be rendered")
        XCTAssertTrue(tests.contains("TrafficChartView"), "the chart must be rendered too")
    }
}
