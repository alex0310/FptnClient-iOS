import XCTest

@testable import FptnCore

final class KeepaliveTests: XCTestCase {
    func testNoPingWhileTrafficFlows() {
        var keepalive = Keepalive(now: 0)
        for second in 1...10 {
            keepalive.sent(at: TimeInterval(second))
            XCTAssertEqual(keepalive.poll(at: TimeInterval(second)), .none)
        }
        XCTAssertEqual(keepalive.pings, 0)
    }

    func testPingsAfterIdleIntervalAndRepeats() {
        var keepalive = Keepalive(now: 0, pingIdle: 15)
        XCTAssertEqual(keepalive.poll(at: 14), .none)
        XCTAssertEqual(keepalive.poll(at: 15), .ping(idle: 15, sequence: 1))
        XCTAssertEqual(keepalive.poll(at: 29), .none)
        XCTAssertEqual(keepalive.poll(at: 30), .ping(idle: 15, sequence: 2))
        XCTAssertEqual(keepalive.pings, 2)
    }

    func testPongClearsUnansweredMarker() {
        var keepalive = Keepalive(now: 0)
        _ = keepalive.poll(at: 15)
        XCTAssertEqual(keepalive.unansweredFor(at: 20), 5)
        keepalive.received(at: 21, pong: true)
        XCTAssertNil(keepalive.unansweredFor(at: 22))
        XCTAssertEqual(keepalive.pongs, 1)
        XCTAssertEqual(keepalive.silentFor(at: 22), 1)
    }

    func testNonPongActivityCountsAsActivityButNotAnAnswer() {
        var keepalive = Keepalive(now: 0)
        _ = keepalive.poll(at: 15)
        keepalive.received(at: 30, pong: false)
        XCTAssertEqual(keepalive.silentFor(at: 30), 0)
        XCTAssertEqual(keepalive.pongs, 0)
        XCTAssertEqual(keepalive.unansweredFor(at: 31), 16)
    }

    func testSilenceBeyondWindowMeansDead() {
        var keepalive = Keepalive(now: 0, pingIdle: 15, deadAfter: 90)
        XCTAssertFalse(keepalive.isDead(at: 89))
        XCTAssertTrue(keepalive.isDead(at: 90))
        keepalive.received(at: 90, pong: true)
        XCTAssertFalse(keepalive.isDead(at: 90))
        XCTAssertFalse(keepalive.isDead(at: 179))
        XCTAssertTrue(keepalive.isDead(at: 180))
    }

    func testDeadWindowScalesWithCustomInterval() {
        XCTAssertEqual(Keepalive.deadAfter(for: 15), 90)
        XCTAssertEqual(Keepalive.deadAfter(for: 5), 60)
        XCTAssertEqual(Keepalive.deadAfter(for: 30), 180)
    }

    func testZeroIntervalDisablesEverything() {
        var keepalive = Keepalive(now: 0, pingIdle: 0, deadAfter: 0)
        XCTAssertFalse(keepalive.isEnabled)
        XCTAssertEqual(keepalive.poll(at: 600), .none)
        XCTAssertFalse(keepalive.isDead(at: 600))
        XCTAssertEqual(keepalive.pings, 0)
    }
}
