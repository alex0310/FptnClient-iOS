import XCTest

@testable import FptnCore

final class TLSHandshakeTests: XCTestCase {
    func testHandshakeMessageEncodesTypeAndUInt24Length() {
        let message = TLSHandshakeMessage(type: .finished, body: [0xaa, 0xbb])
        XCTAssertEqual(message.encoded(), [0x14, 0x00, 0x00, 0x02, 0xaa, 0xbb])
    }

    func testDecoderWaitsForCompleteHeader() throws {
        let decoder = TLSHandshakeDecoder()
        decoder.append([0x14, 0x00, 0x00])
        XCTAssertNil(try decoder.nextMessage())
        XCTAssertEqual(decoder.bufferedByteCount, 3)
    }

    func testDecoderWaitsForCompleteBody() throws {
        let decoder = TLSHandshakeDecoder()
        decoder.append([0x14, 0x00, 0x00, 0x04, 0x01, 0x02])
        XCTAssertNil(try decoder.nextMessage())
        decoder.append([0x03, 0x04])
        XCTAssertEqual(try decoder.nextMessage(), TLSHandshakeMessage(type: .finished, body: [1, 2, 3, 4]))
        XCTAssertNil(try decoder.nextMessage())
    }

    func testDecoderReassemblesMessageSplitAcrossRecords() throws {
        let encoded = TLSHandshakeMessage(type: .certificate, body: Array(repeating: 0x5a, count: 300)).encoded()
        let decoder = TLSHandshakeDecoder()
        decoder.append(Array(encoded.prefix(100)))
        XCTAssertNil(try decoder.nextMessage())
        decoder.append(Array(encoded[100..<250]))
        XCTAssertNil(try decoder.nextMessage())
        decoder.append(Array(encoded.dropFirst(250)))
        let message = try decoder.nextMessage()
        XCTAssertEqual(message?.type, .certificate)
        XCTAssertEqual(message?.body.count, 300)
    }

    func testDecoderReturnsMultipleMessages() throws {
        let first = TLSHandshakeMessage(type: .encryptedExtensions, body: [0, 0]).encoded()
        let second = TLSHandshakeMessage(type: .finished, body: [0xaa]).encoded()
        let decoder = TLSHandshakeDecoder()
        decoder.append(first + second)
        XCTAssertEqual(try decoder.nextMessage()?.type, .encryptedExtensions)
        XCTAssertEqual(try decoder.nextMessage()?.type, .finished)
        XCTAssertNil(try decoder.nextMessage())
    }

    func testDecoderRejectsUnknownType() {
        let decoder = TLSHandshakeDecoder()
        decoder.append([0xff, 0x00, 0x00, 0x00])
        XCTAssertThrowsError(try decoder.nextMessage()) { error in
            XCTAssertEqual(error as? TLSError, .invalidHandshakeType(0xff))
        }
    }

    func testDecoderRejectsOversizedMessage() {
        let decoder = TLSHandshakeDecoder(maxHandshakeSize: 2)
        decoder.append([0x14, 0x00, 0x00, 0x03])
        XCTAssertThrowsError(try decoder.nextMessage()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeTooLarge(3))
        }
    }

    func testExtensionRoundTrip() throws {
        let extensions = [
            TLSExtension(type: 0x002b, data: [0x03, 0x04]),
            TLSExtension(type: 0x0033, data: [0x00, 0x1d, 0x00, 0x20])
        ]
        let encoded = TLSExtensions.encode(extensions)
        let parsed = try TLSExtensions.parse(encoded)
        XCTAssertEqual(parsed[0x002b], [0x03, 0x04])
        XCTAssertEqual(parsed[0x0033], [0x00, 0x1d, 0x00, 0x20])
    }

    func testEmptyExtensionBlockRoundTrips() throws {
        XCTAssertEqual(try TLSExtensions.parse([0x00, 0x00]), [:])
    }

    func testExtensionParserRejectsDuplicateType() {
        var body = TLSExtension(type: 1, data: []).encoded()
        body.append(contentsOf: TLSExtension(type: 1, data: []).encoded())
        let encoded = [UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)] + body
        XCTAssertThrowsError(try TLSExtensions.parse(encoded)) { error in
            XCTAssertEqual(error as? TLSError, .invalidExtension(1))
        }
    }

    func testExtensionParserRejectsTrailingBytesAfterBlock() {
        XCTAssertThrowsError(try TLSExtensions.parse([0x00, 0x00, 0xff]))
    }

    func testExtensionParserRejectsTruncatedBlock() {
        XCTAssertThrowsError(try TLSExtensions.parse([0x00, 0x04, 0x00, 0x01]))
    }
}
