import Foundation
import XCTest

@testable import FptnShared

final class TrafficMetricsTests: XCTestCase {
    // MARK: - Counter

    func testCounterAccumulatesBytesAndPackets() {
        let counter = TrafficCounter()
        counter.recordInbound(bytes: 120, packets: 1)
        counter.recordInbound(bytes: 80, packets: 2)
        counter.recordOutbound(bytes: 40, packets: 1)

        let value = counter.snapshot()
        XCTAssertEqual(value.rxBytes, 200)
        XCTAssertEqual(value.rxPackets, 3)
        XCTAssertEqual(value.txBytes, 40)
        XCTAssertEqual(value.txPackets, 1)
    }

    func testCounterConcurrentIncrementsAreExact() {
        let counter = TrafficCounter()
        let iterations = 1_000
        DispatchQueue.concurrentPerform(iterations: iterations) { _ in
            counter.recordInbound(bytes: 1)
            counter.recordOutbound(bytes: 2)
        }
        let value = counter.snapshot()
        XCTAssertEqual(value.rxBytes, UInt64(iterations))
        XCTAssertEqual(value.txBytes, UInt64(iterations * 2))
        XCTAssertEqual(value.rxPackets, UInt64(iterations))
    }

    func testCounterIgnoresNegativeLengths() {
        let counter = TrafficCounter()
        counter.recordInbound(bytes: -10, packets: -1)
        XCTAssertEqual(counter.snapshot().rxBytes, 0)
        XCTAssertEqual(counter.snapshot().rxPackets, 0)
    }

    func testCounterResetStartsANewSession() {
        let counter = TrafficCounter()
        counter.recordInbound(bytes: 500)
        let before = counter.snapshot()
        let after = counter.reset()
        XCTAssertNotEqual(before.sessionID, after.sessionID)
        XCTAssertEqual(after.rxBytes, 0)
        XCTAssertEqual(counter.snapshot().rxBytes, 0)
    }

    func testSnapshotAddClampsOverflow() {
        let base = TrafficSnapshot(rxBytes: UInt64.max, txBytes: 1)
        let result = base.adding(rxBytes: 5, txBytes: 2)
        XCTAssertEqual(result.rxBytes, UInt64.max)
        XCTAssertEqual(result.txBytes, 3)
    }

    // MARK: - Speed

    func testSpeedComputesAverageThroughput() {
        let session = UUID()
        let start = Date(timeIntervalSinceReferenceDate: 100)
        let earlier = TrafficSnapshot(
            sessionID: session, rxBytes: 1_000, txBytes: 500, updatedAt: start
        )
        let current = TrafficSnapshot(
            sessionID: session, rxBytes: 3_000, txBytes: 1_500,
            updatedAt: start.addingTimeInterval(2)
        )
        let speed = current.speed(relativeTo: earlier)
        XCTAssertEqual(speed?.rxBytesPerSecond, 1_000)
        XCTAssertEqual(speed?.txBytesPerSecond, 500)
    }

    func testSpeedRejectsDifferentSession() {
        let start = Date(timeIntervalSinceReferenceDate: 100)
        let earlier = TrafficSnapshot(rxBytes: 0, updatedAt: start)
        let current = TrafficSnapshot(
            rxBytes: 1_000, updatedAt: start.addingTimeInterval(1)
        )
        XCTAssertNil(current.speed(relativeTo: earlier))
    }

    func testSpeedRejectsBackwardsTime() {
        let session = UUID()
        let start = Date(timeIntervalSinceReferenceDate: 100)
        let earlier = TrafficSnapshot(sessionID: session, updatedAt: start)
        let current = TrafficSnapshot(
            sessionID: session, rxBytes: 1_000,
            updatedAt: start.addingTimeInterval(-1)
        )
        XCTAssertNil(current.speed(relativeTo: earlier))
    }

    func testSpeedRejectsCounterReset() {
        let session = UUID()
        let start = Date(timeIntervalSinceReferenceDate: 100)
        let earlier = TrafficSnapshot(
            sessionID: session, rxBytes: 5_000, updatedAt: start
        )
        let current = TrafficSnapshot(
            sessionID: session, rxBytes: 100,
            updatedAt: start.addingTimeInterval(1)
        )
        XCTAssertNil(current.speed(relativeTo: earlier))
    }

    // MARK: - Formatting

    func testFormatterBytesUsesBinaryUnits() {
        XCTAssertEqual(TrafficFormatter.bytes(0), "0 B")
        XCTAssertEqual(TrafficFormatter.bytes(512), "512 B")
        XCTAssertEqual(TrafficFormatter.bytes(1_023), "1023 B")
        XCTAssertEqual(TrafficFormatter.bytes(1_024), "1.0 KiB")
        XCTAssertEqual(TrafficFormatter.bytes(1_536), "1.5 KiB")
        XCTAssertEqual(TrafficFormatter.bytes(1_048_576), "1.0 MiB")
    }

    func testFormatterSpeedHandlesInvalidValues() {
        XCTAssertEqual(TrafficFormatter.speed(-1), "0 B/s")
        XCTAssertEqual(TrafficFormatter.speed(.infinity), "0 B/s")
        XCTAssertEqual(TrafficFormatter.speed(.nan), "0 B/s")
        XCTAssertEqual(TrafficFormatter.speed(512), "512 B/s")
        XCTAssertEqual(TrafficFormatter.speed(2_048), "2.0 KiB/s")
    }

    func testFormatterPacketsIsExact() {
        XCTAssertEqual(TrafficFormatter.packets(12_345), "12345")
    }

    // MARK: - Store

    func testStoreRoundTrip() {
        let defaults = makeDefaults()
        let snapshot = TrafficSnapshot(rxBytes: 1_234, txBytes: 56, rxPackets: 7, txPackets: 8)
        TrafficSnapshotStore.write(snapshot, defaults: defaults)
        XCTAssertEqual(TrafficSnapshotStore.read(defaults: defaults), snapshot)
    }

    func testStoreReturnsNilWhenAbsent() {
        XCTAssertNil(TrafficSnapshotStore.read(defaults: makeDefaults()))
    }

    func testStoreReturnsNilForMalformedPayload() {
        let defaults = makeDefaults()
        defaults.set(Data([0x00, 0x01, 0x02]), forKey: TrafficSnapshotStore.key)
        XCTAssertNil(TrafficSnapshotStore.read(defaults: defaults))
    }

    func testStoreClearRemovesSnapshot() {
        let defaults = makeDefaults()
        TrafficSnapshotStore.write(TrafficSnapshot(rxBytes: 9), defaults: defaults)
        TrafficSnapshotStore.clear(defaults: defaults)
        XCTAssertNil(TrafficSnapshotStore.read(defaults: defaults))
    }

    private func makeDefaults() -> UserDefaults {
        UserDefaults(suiteName: "FptnTrafficTests.\(UUID().uuidString)")!
    }
}
