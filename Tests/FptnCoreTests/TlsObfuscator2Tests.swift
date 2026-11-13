import XCTest

@testable import FptnCore

final class TlsObfuscator2Tests: XCTestCase {
    private let now: UInt32 = 1_700_000_000

    private func makeRecord(
        payload: [UInt8],
        padding: [UInt8],
        timestamp: UInt32? = nil,
        xorKey: UInt8 = 0xaa,
        contentLengthOverride: Int? = nil,
        payloadLengthOverride: Int? = nil
    ) -> [UInt8] {
        let payloadLength = payloadLengthOverride ?? payload.count
        let contentLength = contentLengthOverride
            ?? (TlsObfuscator2.headerSize - 5 + payload.count + padding.count)
        var output: [UInt8] = [
            0x17, 0x03, 0x03,
            UInt8((contentLength >> 8) & 0xff),
            UInt8(contentLength & 0xff)
        ]
        output.append(contentsOf: [1, 2, 3, 4, 5, 6, 7, 8])
        let stamp = timestamp ?? now
        output.append(contentsOf: [
            UInt8((stamp >> 24) & 0xff),
            UInt8((stamp >> 16) & 0xff),
            UInt8((stamp >> 8) & 0xff),
            UInt8(stamp & 0xff)
        ])
        output.append(xorKey)
        output.append(UInt8((payloadLength >> 8) & 0xff))
        output.append(UInt8(payloadLength & 0xff))
        output.append(UInt8((padding.count >> 8) & 0xff))
        output.append(UInt8(padding.count & 0xff))
        output.append(contentsOf: payload.map { $0 ^ xorKey })
        output.append(contentsOf: padding)
        return output
    }

    func testEncodedHeaderLayout() throws {
        let payload = Array("handshake".utf8)
        let encoded = try TlsObfuscator2().encode(payload: payload, timestamp: now)
        XCTAssertEqual(Array(encoded.prefix(3)), [0x17, 0x03, 0x03])

        let contentLength = Int(encoded[3]) << 8 | Int(encoded[4])
        let payloadLength = Int(encoded[18]) << 8 | Int(encoded[19])
        let paddingLength = Int(encoded[20]) << 8 | Int(encoded[21])
        let timestamp = UInt32(encoded[13]) << 24
            | UInt32(encoded[14]) << 16
            | UInt32(encoded[15]) << 8
            | UInt32(encoded[16])
        XCTAssertEqual(contentLength, TlsObfuscator2.headerSize - 5 + payload.count + paddingLength)
        XCTAssertEqual(payloadLength, payload.count)
        XCTAssertEqual(timestamp, now)
        XCTAssertTrue((TlsObfuscator2.minimumPadding...TlsObfuscator2.maximumPadding).contains(paddingLength))
        XCTAssertEqual(encoded.count, TlsObfuscator2.headerSize + payload.count + paddingLength)
        XCTAssertEqual(contentLength, encoded.count - 5)
    }

    func testRoundTrip() throws {
        let payload = Array("hello fptn".utf8)
        let encoded = try TlsObfuscator2().encode(payload: payload, timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(encoded)
        XCTAssertEqual(decoder.nextPayload(now: now), payload)
        XCTAssertFalse(decoder.hasPendingData)
        XCTAssertNil(decoder.nextPayload(now: now))
    }

    func testEmptyPayloadRoundTrips() throws {
        let encoded = try TlsObfuscator2().encode(payload: [], timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(encoded)
        XCTAssertEqual(decoder.nextPayload(now: now), [])
    }

    func testSplitAcrossPushes() throws {
        let payload = Array("fragmented payload".utf8)
        let encoded = try TlsObfuscator2().encode(payload: payload, timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(Array(encoded.prefix(10)))
        XCTAssertNil(decoder.nextPayload(now: now))
        decoder.push(Array(encoded.dropFirst(10)))
        XCTAssertEqual(decoder.nextPayload(now: now), payload)
    }

    func testTwoRecordsInOnePush() throws {
        let first = try TlsObfuscator2().encode(payload: [1, 2], timestamp: now)
        let second = try TlsObfuscator2().encode(payload: [3, 4], timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(first + second)
        XCTAssertEqual(decoder.nextPayload(now: now), [1, 2])
        XCTAssertEqual(decoder.nextPayload(now: now), [3, 4])
        XCTAssertNil(decoder.nextPayload(now: now))
    }

    func testGarbagePrefixIsSkipped() throws {
        let payload = Array("valid".utf8)
        let encoded = try TlsObfuscator2().encode(payload: payload, timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push([0xff, 0x00, 0x01] + encoded)
        XCTAssertEqual(decoder.nextPayload(now: now), payload)
    }

    func testInvalidTimestampIsSkipped() throws {
        let record = makeRecord(
            payload: [1, 2, 3],
            padding: [0, 0],
            timestamp: now - 121
        )
        var decoder = TlsObfuscator2()
        decoder.push(record)
        XCTAssertNil(decoder.nextPayload(now: now))
    }

    func testTimestampWindowIsInclusive() throws {
        for offset in [-120, 120] {
            let record = makeRecord(
                payload: [1],
                padding: [0],
                timestamp: UInt32(Int64(now) + Int64(offset))
            )
            var decoder = TlsObfuscator2()
            decoder.push(record)
            XCTAssertEqual(decoder.nextPayload(now: now), [1])
        }
    }

    func testContentLengthTooLargeIsSkipped() throws {
        let record = makeRecord(
            payload: [1],
            padding: [0],
            contentLengthOverride: 16_385
        )
        var decoder = TlsObfuscator2()
        decoder.push(record)
        XCTAssertNil(decoder.nextPayload(now: now))
    }

    func testContentLengthSmallerThanPayloadIsSkipped() throws {
        let record = makeRecord(
            payload: [1, 2, 3],
            padding: [],
            contentLengthOverride: 17
        )
        var decoder = TlsObfuscator2()
        decoder.push(record)
        XCTAssertNil(decoder.nextPayload(now: now))
    }

    func testIncompleteRecordIsRetained() throws {
        let encoded = try TlsObfuscator2().encode(payload: [1, 2], timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(Array(encoded.dropLast()))
        XCTAssertNil(decoder.nextPayload(now: now))
        XCTAssertTrue(decoder.hasPendingData)
        decoder.push([encoded.last!])
        XCTAssertEqual(decoder.nextPayload(now: now), [1, 2])
    }

    func testResetClearsBufferedData() throws {
        var decoder = TlsObfuscator2()
        decoder.push([1, 2, 3])
        XCTAssertTrue(decoder.hasPendingData)
        decoder.reset()
        XCTAssertFalse(decoder.hasPendingData)
    }

    func testMaximumPayloadIsAccepted() throws {
        let payload = Array(repeating: UInt8(0x5a), count: 16_367)
        let encoded = try TlsObfuscator2().encode(payload: payload, timestamp: now)
        var decoder = TlsObfuscator2()
        decoder.push(encoded)
        XCTAssertEqual(decoder.nextPayload(now: now), payload)
    }

    func testOversizedPayloadIsRejected() {
        let payload = Array(repeating: UInt8(0x5a), count: 16_368)
        XCTAssertThrowsError(try TlsObfuscator2().encode(payload: payload, timestamp: now)) { error in
            XCTAssertEqual(error as? TlsObfuscatorError, .payloadTooLarge(16_368))
        }
    }
}
