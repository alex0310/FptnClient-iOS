import Foundation
import XCTest

@testable import FptnShared

final class TrafficChartTests: XCTestCase {
    private func sample(
        _ rx: Double,
        _ tx: Double = 0,
        at offset: TimeInterval = 0
    ) -> TrafficSample {
        TrafficSample(
            timestamp: Date(timeIntervalSinceReferenceDate: offset),
            rxBytesPerSecond: rx,
            txBytesPerSecond: tx
        )
    }

    // MARK: - History

    func testHistoryKeepsInsertionOrder() {
        var history = TrafficHistory(limit: 3)
        history.append(sample(10, at: 0))
        history.append(sample(20, at: 1))
        XCTAssertEqual(history.samples.map(\.rxBytesPerSecond), [10, 20])
        XCTAssertEqual(history.count, 2)
        XCTAssertFalse(history.isEmpty)
    }

    func testHistoryDropsOldestBeyondLimit() {
        var history = TrafficHistory(limit: 3)
        for index in 0..<5 {
            history.append(sample(Double(index), at: Double(index)))
        }
        XCTAssertEqual(history.samples.map(\.rxBytesPerSecond), [2, 3, 4])
        XCTAssertEqual(history.samples.map(\.timestamp.timeIntervalSinceReferenceDate), [2, 3, 4])
    }

    func testHistoryLimitIsAtLeastTwo() {
        var history = TrafficHistory(limit: 0)
        XCTAssertEqual(history.limit, 2)
        for index in 0..<4 { history.append(sample(Double(index))) }
        XCTAssertEqual(history.count, 2)
    }

    func testHistoryResetClearsSamples() {
        var history = TrafficHistory(limit: 3)
        history.append(sample(10))
        history.reset()
        XCTAssertTrue(history.isEmpty)
        XCTAssertEqual(history.limit, 3)
    }

    // MARK: - Scale

    func testNiceCeilingRoundsToNiceValues() {
        XCTAssertEqual(TrafficChartScale.niceCeiling(0), 0)
        XCTAssertEqual(TrafficChartScale.niceCeiling(1), 1)
        XCTAssertEqual(TrafficChartScale.niceCeiling(1.5), 2)
        XCTAssertEqual(TrafficChartScale.niceCeiling(3), 5)
        XCTAssertEqual(TrafficChartScale.niceCeiling(7), 10)
        XCTAssertEqual(TrafficChartScale.niceCeiling(250), 500)
        XCTAssertEqual(TrafficChartScale.niceCeiling(1_024), 2_000)
    }

    func testNiceCeilingRejectsInvalidValues() {
        XCTAssertEqual(TrafficChartScale.niceCeiling(-1), 0)
        XCTAssertEqual(TrafficChartScale.niceCeiling(.infinity), 0)
        XCTAssertEqual(TrafficChartScale.niceCeiling(.nan), 0)
    }

    func testPeakIgnoresInvalidSamples() {
        let samples = [
            sample(100, 50),
            sample(.nan, 300),
            sample(-10, .infinity)
        ]
        XCTAssertEqual(TrafficChartScale.peak(for: samples), 300)
        XCTAssertEqual(TrafficChartScale.peak(for: []), 0)
    }

    func testScaleHasMinimumForIdleTunnel() {
        XCTAssertEqual(TrafficChartScale.scale(for: [], minimum: 1_024), 1_024)
        XCTAssertEqual(TrafficChartScale.scale(for: [sample(10)], minimum: 1_024), 1_024)
    }

    func testScaleFollowsPeak() {
        XCTAssertEqual(TrafficChartScale.scale(for: [sample(50_000)], minimum: 0), 50_000)
        XCTAssertEqual(TrafficChartScale.scale(for: [sample(1_200, 3_000)], minimum: 0), 5_000)
    }

    // MARK: - Geometry

    func testGeometryEmptyReturnsNoPoints() {
        XCTAssertTrue(TrafficChartGeometry.points(for: [], scale: 100).isEmpty)
    }

    func testGeometryNormalizesXFromZeroToOne() {
        let samples = [sample(1), sample(2), sample(3)]
        let points = TrafficChartGeometry.points(for: samples, scale: 100)
        XCTAssertEqual(points.map(\.x), [0, 0.5, 1])
        XCTAssertEqual(TrafficChartGeometry.points(for: [sample(1)], scale: 100).map(\.x), [0])
    }

    func testGeometryMapsValuesToY() {
        let points = TrafficChartGeometry.points(for: [sample(100, 0), sample(50, 25)], scale: 100)
        XCTAssertEqual(points[0].rxY, 0)
        XCTAssertEqual(points[0].txY, 1)
        XCTAssertEqual(points[1].rxY, 0.5)
        XCTAssertEqual(points[1].txY, 0.75)
    }

    func testGeometryClampsValuesAboveScale() {
        let points = TrafficChartGeometry.points(for: [sample(1_000)], scale: 100)
        XCTAssertEqual(points[0].rxY, 0)
    }

    func testGeometryHandlesInvalidScaleAndValues() {
        let points = TrafficChartGeometry.points(for: [sample(.nan, -5)], scale: 100)
        XCTAssertEqual(points[0].rxY, 1)
        XCTAssertEqual(points[0].txY, 1)
        let zeroScale = TrafficChartGeometry.points(for: [sample(50)], scale: 0)
        XCTAssertEqual(zeroScale[0].rxY, 1)
        let negativeScale = TrafficChartGeometry.points(for: [sample(50)], scale: -1)
        XCTAssertEqual(negativeScale[0].rxY, 1)
    }
}
