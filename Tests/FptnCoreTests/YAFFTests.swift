import XCTest
@testable import FptnCore

final class YAFFTests: XCTestCase {
    private func bytes(_ string: String) -> [UInt8] {
        guard let value = Hex.decode(string) else {
            XCTFail("invalid hex fixture")
            return []
        }
        return value
    }

    func testIpAssignmentMatchesReferenceVector() {
        let ipv4: [UInt8] = [0x0a, 0x00, 0x00, 0x02]
        let ipv6: [UInt8] = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        ]
        let expected = bytes("""
            06 00 00 00 02 aa 1a 80 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00
            17 00 00 00 0a 0e 80 1f 00 00 00 0a 00 00 00 10 00 00 00 fd 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 02 00 04 00 00 00 0a 00 00 02 00
        """)
        XCTAssertEqual(YAFF.serializeIpAssignmentMessage(ipv4: ipv4, ipv6: ipv6), expected)
    }

    func testInnerIpPacketMatchesReferenceVector() {
        let expected = bytes("""
            05 00 00 00 aa 16 80 01 00 00 00 01 00 00 00 00 00 00 00 13 00 00 00
            02 0a 80 06 00 00 00 05 00 00 00 68 65 6c 6c 6f 00
        """)
        XCTAssertEqual(YAFF.serializeIpPacketMessage(payload: Array("hello".utf8)), expected)
    }

    func testSinglePacketBatchMatchesReferenceVector() {
        let expected = bytes("""
            06 00 00 00 0a aa 1e 80 01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 1b 00 00 00 02 0a 80 06 00 00 00 01 00 00 00 04 00 00 00
            28 00 00 00 05 00 00 00 aa 16 80 01 00 00 00 01 00 00 00 00 00 00 00
            13 00 00 00 02 0a 80 06 00 00 00 05 00 00 00 68 65 6c 6c 6f 00 00
        """)
        let frame = YAFF.serializeBatchMessage([.init(payload: Array("hello".utf8))])
        XCTAssertEqual(frame, expected)
    }

    func testTwoPacketBatchMatchesReferenceVector() {
        let expected = bytes("""
            06 00 00 00 0a aa 1e 80 01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 1b 00 00 00 02 0a 80 06 00 00 00 02 00 00 00 37 00 00 00
            08 00 00 00 2a 00 00 00 05 00 00 00 aa 16 80 01 00 00 00 01 00 00 00
            00 00 00 00 13 00 00 00 02 0a 80 06 00 00 00 07 00 00 00 77 6f 72 6c
            64 21 21 00 00 28 00 00 00 05 00 00 00 aa 16 80 01 00 00 00 01 00 00
            00 00 00 00 00 13 00 00 00 02 0a 80 06 00 00 00 05 00 00 00 68 65 6c
            6c 6f 00 00
        """)
        let frame = YAFF.serializeBatchMessage([
            .init(payload: Array("hello".utf8)),
            .init(payload: Array("world!!".utf8))
        ])
        XCTAssertEqual(frame, expected)
    }

    func testParseAssignmentMatchesReferenceVector() {
        let frame = bytes("""
            06 00 00 00 02 aa 1a 80 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00
            17 00 00 00 0a 0e 80 1f 00 00 00 0a 00 00 00 10 00 00 00 fd 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 02 00 04 00 00 00 0a 00 00 02 00
        """)
        XCTAssertEqual(
            YAFF.parseMessage(frame),
            .ipAssignment(
                ipv4: [0x0a, 0x00, 0x00, 0x02],
                ipv6: [
                    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
                ]
            )
        )
    }

    func testParseBatchMatchesReferenceVector() {
        let frame = bytes("""
            06 00 00 00 0a aa 1e 80 01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 1b 00 00 00 02 0a 80 06 00 00 00 01 00 00 00 04 00 00 00
            28 00 00 00 05 00 00 00 aa 16 80 01 00 00 00 01 00 00 00 00 00 00 00
            13 00 00 00 02 0a 80 06 00 00 00 05 00 00 00 68 65 6c 6c 6f 00 00
        """)
        XCTAssertEqual(YAFF.parseMessage(frame), .batch([Array("hello".utf8)]))
    }

    func testRoundTripPreservesPacketOrder() throws {
        let packets: [YAFF.IPPacketData] = [
            .init(payload: [0x45, 0x00, 0x00, 0x14]),
            .init(payload: Array("payload-two".utf8)),
            .init(payload: [0xff, 0x00, 0xaa])
        ]
        let frame = try XCTUnwrap(YAFF.serializeBatchMessage(packets))
        XCTAssertEqual(
            YAFF.parseMessage(frame),
            .batch(packets.map(\.payload))
        )
    }

    func testRoundTripPreservesPadding() throws {
        let packet = YAFF.IPPacketData(
            payload: Array("hello".utf8),
            paddingData: [0xde, 0xad, 0xbe, 0xef]
        )
        let frame = try XCTUnwrap(YAFF.serializeBatchMessage([packet]))
        XCTAssertEqual(YAFF.parseMessage(frame), .batch([packet.payload]))
    }

    func testBatchSkipsEmptyPayloads() {
        XCTAssertNil(YAFF.serializeBatchMessage([]))
        XCTAssertNil(YAFF.serializeBatchMessage([.init(payload: [])]))
    }

    func testMalformedFramesAreRejected() {
        XCTAssertNil(YAFF.parseMessage([]))
        XCTAssertNil(YAFF.parseMessage([0xff, 0xff, 0xff, 0xff]))
        XCTAssertNil(YAFF.parseMessage([0x00, 0x00, 0x00, 0x00]))
    }

    func testUnknownMessageTypeIsRejected() {
        var frame = bytes("""
            06 00 00 00 02 aa 1a 80 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00
            17 00 00 00 0a 0e 80 1f 00 00 00 0a 00 00 00 10 00 00 00 fd 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 02 00 04 00 00 00 0a 00 00 02 00
        """)
        // Root offset (4) + size mask (2) precede the message; msg_type is the
        // scalar at flat offset 4 (message bytes 6...9, frame bytes 12...15).
        frame[12] = 99
        XCTAssertNil(YAFF.parseMessage(frame))
    }
}
