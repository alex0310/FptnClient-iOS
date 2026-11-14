import Foundation
import XCTest

@testable import FptnCore

final class DERTests: XCTestCase {
    func testParsesSimpleSequence() throws {
        let element = try DER.parse([0x30, 0x03, 0x02, 0x01, 0x05])
        XCTAssertEqual(element.tag, 0x30)
        XCTAssertEqual(element.content, [0x02, 0x01, 0x05])
        XCTAssertEqual(try element.children.map(\.tag), [0x02])
    }

    func testParsesLongFormLength() throws {
        let body = [UInt8](repeating: 0x41, count: 200)
        let encoded: [UInt8] = [0x04, 0x81, 0xc8] + body
        let element = try DER.parse(encoded)
        XCTAssertEqual(element.tag, 0x04)
        XCTAssertEqual(element.content, body)
    }

    func testRejectsTrailingData() {
        XCTAssertThrowsError(try DER.parse([0x30, 0x00, 0x00])) { error in
            XCTAssertEqual(error as? DERError, .trailingData)
        }
    }

    func testRejectsIndefiniteLength() {
        XCTAssertThrowsError(try DER.parse([0x30, 0x80, 0x00, 0x00])) { error in
            XCTAssertEqual(error as? DERError, .indefiniteLength)
        }
    }

    func testRejectsNonMinimalLength() {
        XCTAssertThrowsError(try DER.parse([0x30, 0x81, 0x01, 0x05])) { error in
            XCTAssertEqual(error as? DERError, .nonMinimalLength)
        }
    }

    func testRejectsTruncatedContent() {
        XCTAssertThrowsError(try DER.parse([0x04, 0x05, 0x01, 0x02])) { error in
            XCTAssertEqual(error as? DERError, .truncated)
        }
    }

    func testDecodesObjectIdentifiers() throws {
        let commonName = try DER.parse([0x06, 0x03, 0x55, 0x04, 0x03])
        XCTAssertEqual(try commonName.objectIdentifier, "2.5.4.3")
        let sha256WithRSA = try DER.parse([
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
        ])
        XCTAssertEqual(try sha256WithRSA.objectIdentifier, "1.2.840.113549.1.1.11")
    }

    func testRejectsTruncatedOID() throws {
        // The final base-128 component still has its continuation bit set.
        let element = try DER.parse([0x06, 0x02, 0x2a, 0x81])
        XCTAssertThrowsError(try element.objectIdentifier) { error in
            XCTAssertEqual(error as? DERError, .invalidOID)
        }
    }

    func testDecodesUTCTime() throws {
        // "261113174027Z" -> 2026-11-13 17:40:27 UTC
        let bytes: [UInt8] = [0x17, 0x0d] + Array("261113174027Z".utf8)
        let date = try DER.parse(bytes).dateValue
        let expected = Date(timeIntervalSince1970: 1_794_591_627)
        XCTAssertEqual(date, expected)
    }

    func testDecodesGeneralizedTime() throws {
        let bytes: [UInt8] = [0x18, 0x0f] + Array("20261113174027Z".utf8)
        let date = try DER.parse(bytes).dateValue
        XCTAssertEqual(date, Date(timeIntervalSince1970: 1_794_591_627))
    }

    func testRejectsNonUTCTime() {
        let bytes: [UInt8] = [0x17, 0x0d] + Array("261113174027+".utf8)
        XCTAssertThrowsError(try DER.parse(bytes).dateValue)
    }

    func testDecodesBitString() throws {
        let element = try DER.parse([0x03, 0x03, 0x00, 0xab, 0xcd])
        XCTAssertEqual(try element.bitStringBytes, [0xab, 0xcd])
    }

    func testAcceptsBitStringWithUnusedBits() throws {
        let element = try DER.parse([0x03, 0x02, 0x05, 0xa0])
        XCTAssertEqual(try element.bitStringBytes, [0xa0])
    }

    func testRejectsInvalidBitStringPadding() throws {
        let element = try DER.parse([0x03, 0x02, 0x08, 0xab])
        XCTAssertThrowsError(try element.bitStringBytes) { error in
            XCTAssertEqual(error as? DERError, .invalidBitString)
        }
    }

    func testDecodesBoolean() throws {
        XCTAssertTrue(try DER.parse([0x01, 0x01, 0xff]).booleanValue)
        XCTAssertFalse(try DER.parse([0x01, 0x01, 0x00]).booleanValue)
        XCTAssertThrowsError(try DER.parse([0x01, 0x01, 0x01]).booleanValue)
    }

    func testRequireTagReportsMismatch() {
        let element = try? DER.parse([0x30, 0x00])
        XCTAssertThrowsError(try element?.requireTag(0x31)) { error in
            XCTAssertEqual(error as? DERError, .unexpectedTag(expected: 0x31, actual: 0x30))
        }
    }
}
