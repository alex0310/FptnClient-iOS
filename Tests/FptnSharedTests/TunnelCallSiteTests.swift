import Foundation
import XCTest

/// `PacketTunnelProvider` lives in the iOS-only extension target, so Linux
/// cannot type-check it. This test guards the `TunnelRuntime.start` call site
/// against a wrong argument label found by the macOS CI build.
final class TunnelCallSiteTests: XCTestCase {
    func testStartTunnelUsesCompletionLabel() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnSharedTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        let file = root.appendingPathComponent("Tunnel/PacketTunnelProvider.swift")
        let source = try String(contentsOf: file, encoding: .utf8)

        XCTAssertTrue(
            source.contains("runtime.start(completion: completionHandler)"),
            "TunnelRuntime.start expects a 'completion:' label"
        )
        XCTAssertFalse(
            source.contains("start(completionHandler:"),
            "TunnelRuntime.start has no 'completionHandler:' label"
        )
    }
}
