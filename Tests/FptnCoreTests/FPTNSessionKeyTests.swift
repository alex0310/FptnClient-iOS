import XCTest

@testable import FptnCore

final class FPTNSessionKeyTests: XCTestCase {
    private let timestamp: UInt32 = 1_700_000_000
    private let random = Array(repeating: UInt8(0x22), count: 32)

    func testGenerateMatchesKnownSHA1Prefix() {
        XCTAssertEqual(
            FPTNSessionKey.generate(timestamp: timestamp),
            [0xf1, 0x8b, 0x7f, 0xe9]
        )
    }

    func testRealSessionIDStampsLastFourBytes() throws {
        let sessionID = try FPTNSessionKey.realSessionID(random: random, timestamp: timestamp)
        XCTAssertEqual(Array(sessionID[28..<32]), FPTNSessionKey.generate(timestamp: timestamp))
        XCTAssertEqual(Array(sessionID[0..<28]), Array(random[0..<28]))
    }

    func testDecoySessionIDStampsOffsetFourteen() throws {
        let sessionID = try FPTNSessionKey.decoySessionID(random: random, timestamp: timestamp)
        XCTAssertEqual(Array(sessionID[14..<18]), FPTNSessionKey.generate(timestamp: timestamp))
        XCTAssertEqual(Array(sessionID[0..<14]), Array(random[0..<14]))
        XCTAssertEqual(Array(sessionID[18..<32]), Array(random[18..<32]))
    }

    func testStampedSessionIDRejectsInvalidRandomLength() {
        XCTAssertThrowsError(try FPTNSessionKey.realSessionID(
            random: Array(repeating: 0, count: 31),
            timestamp: timestamp
        ))
    }

    func testStampedSessionIDRejectsOutOfRangeOffset() {
        XCTAssertThrowsError(try FPTNSessionKey.stampedSessionID(
            random: random,
            timestamp: timestamp,
            offset: 29
        ))
        XCTAssertThrowsError(try FPTNSessionKey.stampedSessionID(
            random: random,
            timestamp: timestamp,
            offset: -1
        ))
    }

    func testMatchesAcceptsKeysInsideWindow() throws {
        let sessionID = try FPTNSessionKey.realSessionID(random: random, timestamp: timestamp)
        for shift in [-120, -1, 0, 1, 120] {
            XCTAssertTrue(FPTNSessionKey.matches(
                sessionID: sessionID,
                offset: 28,
                timestamp: UInt32(Int64(timestamp) + Int64(shift))
            ))
        }
    }

    func testMatchesRejectsKeysOutsideWindow() throws {
        let sessionID = try FPTNSessionKey.realSessionID(random: random, timestamp: timestamp)
        XCTAssertFalse(FPTNSessionKey.matches(
            sessionID: sessionID,
            offset: 28,
            timestamp: timestamp + 121
        ))
        XCTAssertFalse(FPTNSessionKey.matches(
            sessionID: sessionID,
            offset: 28,
            timestamp: timestamp - 121
        ))
    }

    func testMatchesRejectsShortSessionID() {
        XCTAssertFalse(FPTNSessionKey.matches(
            sessionID: Array(repeating: 0, count: 10),
            offset: 14,
            timestamp: timestamp
        ))
    }

    func testMatchesDetectsDecoyOffset() throws {
        let sessionID = try FPTNSessionKey.decoySessionID(random: random, timestamp: timestamp)
        XCTAssertTrue(FPTNSessionKey.matches(
            sessionID: sessionID,
            offset: FPTNSessionKey.decoyOffset,
            timestamp: timestamp
        ))
        XCTAssertFalse(FPTNSessionKey.matches(
            sessionID: sessionID,
            offset: 28,
            timestamp: timestamp
        ))
    }
}
