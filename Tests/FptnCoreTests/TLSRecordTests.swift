import XCTest

@testable import FptnCore

final class TLSRecordTests: XCTestCase {
    func testRecordEncodesHeaderAndFragment() {
        let record = TLSRecord(type: .handshake, version: 0x0301, fragment: [0x01, 0x02])
        XCTAssertEqual(record.encoded(), [0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x02])
    }

    func testRecordDefaultsToTLS12Version() {
        let record = TLSRecord(type: .applicationData, fragment: [])
        XCTAssertEqual(record.version, 0x0303)
        XCTAssertEqual(record.encoded(), [0x17, 0x03, 0x03, 0x00, 0x00])
    }

    func testDecoderWaitsForCompleteRecord() throws {
        let encoded = TLSRecord(type: .alert, fragment: [0x01, 0x00]).encoded()
        let decoder = TLSRecordDecoder()
        decoder.append(Array(encoded.prefix(3)))
        XCTAssertNil(try decoder.nextRecord())
        XCTAssertEqual(decoder.bufferedByteCount, 3)
        decoder.append(Array(encoded.dropFirst(3)))
        let record = try decoder.nextRecord()
        XCTAssertEqual(record?.type, .alert)
        XCTAssertEqual(record?.fragment, [0x01, 0x00])
        XCTAssertNil(try decoder.nextRecord())
    }

    func testDecoderReturnsMultipleRecordsInOrder() throws {
        let first = TLSRecord(type: .handshake, fragment: [0xaa]).encoded()
        let second = TLSRecord(type: .applicationData, fragment: [0xbb, 0xcc]).encoded()
        let decoder = TLSRecordDecoder()
        decoder.append(first + second)
        XCTAssertEqual(try decoder.nextRecord()?.fragment, [0xaa])
        XCTAssertEqual(try decoder.nextRecord()?.fragment, [0xbb, 0xcc])
        XCTAssertNil(try decoder.nextRecord())
    }

    func testDecoderRejectsUnknownRecordType() {
        let decoder = TLSRecordDecoder()
        decoder.append([0x99, 0x03, 0x03, 0x00, 0x00])
        XCTAssertThrowsError(try decoder.nextRecord()) { error in
            XCTAssertEqual(error as? TLSError, .invalidRecordType(0x99))
        }
    }

    func testDecoderRejectsOversizedRecord() {
        let decoder = TLSRecordDecoder(maxRecordSize: 4)
        decoder.append([0x16, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0])
        XCTAssertThrowsError(try decoder.nextRecord()) { error in
            XCTAssertEqual(error as? TLSError, .recordTooLarge(5))
        }
    }

    func testDecoderAcceptsMaximumCiphertextLength() throws {
        let size = TLSRecordDecoder.maximumCiphertextLength
        let fragment = Array(repeating: UInt8(0x5a), count: size)
        let decoder = TLSRecordDecoder()
        decoder.append(TLSRecord(type: .applicationData, fragment: fragment).encoded())
        XCTAssertEqual(try decoder.nextRecord()?.fragment.count, size)
    }

    func testDecoderDoesNotConsumeIncompleteRecord() throws {
        let encoded = TLSRecord(type: .handshake, fragment: [1, 2, 3]).encoded()
        let decoder = TLSRecordDecoder()
        decoder.append(Array(encoded.prefix(encoded.count - 1)))
        XCTAssertNil(try decoder.nextRecord())
        decoder.append([encoded.last!])
        XCTAssertEqual(try decoder.nextRecord()?.fragment, [1, 2, 3])
    }
}
