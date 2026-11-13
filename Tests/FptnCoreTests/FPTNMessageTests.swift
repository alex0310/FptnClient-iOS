import XCTest

@testable import FptnCore

final class FPTNMessageTests: XCTestCase {
    private func hex(_ value: String) -> [UInt8] {
        let cleaned = value.split(whereSeparator: { $0.isWhitespace }).joined()
        var output: [UInt8] = []
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            output.append(UInt8(cleaned[index..<next], radix: 16)!)
            index = next
        }
        return output
    }

    func testParsesAssignmentReferenceVector() {
        let frame = hex(
            "06 00 00 00 02 aa 1a 80 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 "
            + "17 00 00 00 0a 0e 80 1f 00 00 00 0a 00 00 00 10 00 00 00 fd 00 00 00 "
            + "00 00 00 00 00 00 00 00 00 00 00 02 00 04 00 00 00 0a 00 00 02 00"
        )
        XCTAssertEqual(
            FPTNMessage.decode(frame),
            .ipAssignment(ipv4: "10.0.0.2", ipv6: "fd00::2")
        )
    }

    func testParsesBatchReferenceVector() {
        let frame = hex(
            "06 00 00 00 0a aa 1e 80 01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 "
            + "00 00 00 00 1b 00 00 00 02 0a 80 06 00 00 00 01 00 00 00 04 00 00 00 "
            + "28 00 00 00 05 00 00 00 aa 16 80 01 00 00 00 01 00 00 00 00 00 00 00 "
            + "13 00 00 00 02 0a 80 06 00 00 00 05 00 00 00 68 65 6c 6c 6f 00 00"
        )
        XCTAssertEqual(FPTNMessage.decode(frame), .batch([Array("hello".utf8)]))
    }

    func testBatchRoundTrip() {
        let packets = [Array("one".utf8), Array("two".utf8)]
        let frame = try? XCTUnwrap(FPTNMessage.encodeBatch(packets))
        XCTAssertEqual(FPTNMessage.decode(frame ?? []), .batch(packets))
    }

    func testAssignmentRoundTrip() {
        let frame = FPTNMessage.encodeAssignment(ipv4: "10.1.2.3", ipv6: "fd00::1")
        XCTAssertEqual(
            FPTNMessage.decode(frame),
            .ipAssignment(ipv4: "10.1.2.3", ipv6: "fd00::1")
        )
    }

    func testErrorRoundTrip() {
        let frame = FPTNMessage.encodeError(kind: .sessionExpired, message: "expired")
        XCTAssertEqual(
            FPTNMessage.decode(frame),
            .error(kind: .sessionExpired, message: "expired")
        )
    }

    func testUnknownErrorKindIsPreserved() {
        let frame = FPTNMessage.encodeError(kind: .unknown(99), message: "future")
        XCTAssertEqual(
            FPTNMessage.decode(frame),
            .error(kind: .unknown(99), message: "future")
        )
    }

    func testEmptyBatchIsRejected() {
        XCTAssertNil(FPTNMessage.encodeBatch([]))
        XCTAssertNil(FPTNMessage.encodeBatch([[]]))
    }

    func testMalformedFramesAreRejected() {
        XCTAssertNil(FPTNMessage.decode([]))
        XCTAssertNil(FPTNMessage.decode([0xff, 0xff, 0xff, 0xff]))
    }
}
