import Foundation
import XCTest

/// `App/` and `Tunnel/` are only type-checked by the macOS CI job. These
/// guards keep the extension → app traffic pipeline wired from Linux too.
final class TrafficIntegrationTests: XCTestCase {
    private func source(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnSharedTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    func testExtensionRecordsAndPublishesTraffic() throws {
        let runtime = try source("Tunnel/TunnelRuntime.swift")
        XCTAssertTrue(runtime.contains("onInboundTraffic:"), "relay must observe inbound packets")
        XCTAssertTrue(runtime.contains("onOutboundTraffic:"), "relay must observe outbound packets")
        XCTAssertTrue(runtime.contains("TrafficSnapshotStore.write"), "extension must publish snapshots")
        XCTAssertTrue(runtime.contains("publishTraffic()"), "timer must publish snapshots")
    }

    func testAppPollsTrafficSnapshots() throws {
        let model = try source("App/AppModel.swift")
        XCTAssertTrue(model.contains("TrafficSnapshotStore.read"), "app must read snapshots")
        XCTAssertTrue(model.contains("trafficSpeed"), "app must expose throughput")
        XCTAssertTrue(model.contains("updateTrafficPolling()"), "status changes must drive polling")
    }

    func testDiagnosticsDisplaysTraffic() throws {
        let view = try source("App/Views/DiagnosticsView.swift")
        XCTAssertTrue(view.contains("diagnosticsTraffic"), "diagnostics must show traffic")
        XCTAssertTrue(view.contains("TrafficFormatter.bytes"), "diagnostics must format byte totals")
        XCTAssertTrue(view.contains("TrafficFormatter.speed"), "diagnostics must format speeds")
    }
}
