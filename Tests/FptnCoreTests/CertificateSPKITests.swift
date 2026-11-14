import Foundation
import XCTest

@testable import FptnCore

final class CertificateSPKITests: XCTestCase {
    private func leaf() throws -> X509Certificate {
        try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
    }

    func testSHA256IsStableAndMatchesSPKIDER() throws {
        let certificate = try leaf()
        let digest = CertificateSPKI.sha256(of: certificate)
        XCTAssertEqual(digest.count, 64)
        XCTAssertEqual(digest, Hex.encode(Digests.sha256(certificate.subjectPublicKeyInfoDER)))
        XCTAssertEqual(CertificateSPKI.sha256(of: certificate), digest)
    }

    func testNormalizesHexAndBase64() throws {
        let certificate = try leaf()
        let hex = CertificateSPKI.sha256(of: certificate)
        XCTAssertEqual(CertificateSPKI.normalized(hex.uppercased()), hex)
        XCTAssertEqual(CertificateSPKI.normalized(hex), hex)

        let bytes = try XCTUnwrap(Data(hexString: hex))
        let base64 = bytes.base64EncodedString()
        XCTAssertEqual(CertificateSPKI.normalized(base64), hex)
    }

    func testNormalizedRejectsMalformedPins() {
        XCTAssertNil(CertificateSPKI.normalized("abc"))
        XCTAssertNil(CertificateSPKI.normalized(String(repeating: "z", count: 64)))
        XCTAssertNil(CertificateSPKI.normalized("not base64 !!"))
    }

    func testCorrectPinPasses() throws {
        let certificate = try leaf()
        let hex = CertificateSPKI.sha256(of: certificate)
        let bytes = try XCTUnwrap(Data(hexString: hex))
        XCTAssertNoThrow(
            try CertificateSPKI.verify(
                certificate: certificate,
                pins: [hex, bytes.base64EncodedString()]
            )
        )
    }

    func testWrongPinFails() throws {
        let certificate = try leaf()
        let wrong = String(repeating: "0", count: 64)
        XCTAssertThrowsError(
            try CertificateSPKI.verify(certificate: certificate, pins: [wrong])
        ) { error in
            guard case .pinMismatch = error as? CertificateSPKIError else {
                return XCTFail("Expected pinMismatch, got \(error)")
            }
        }
    }

    func testMalformedPinFails() throws {
        let certificate = try leaf()
        XCTAssertThrowsError(
            try CertificateSPKI.verify(certificate: certificate, pins: ["nope"])
        ) { error in
            XCTAssertEqual(error as? CertificateSPKIError, .malformedPin("nope"))
        }
    }

    func testEmptyPinsIsANoOp() throws {
        XCTAssertNoThrow(try CertificateSPKI.verify(certificate: leaf(), pins: []))
    }

    func testDifferentKeysHaveDifferentPins() throws {
        let leaf = try leaf()
        let root = try X509Certificate(der: CertificateFixtures.der("rsa-root"))
        XCTAssertNotEqual(
            CertificateSPKI.sha256(of: leaf),
            CertificateSPKI.sha256(of: root)
        )
    }

    func testTokenCarriesSPKIPin() throws {
        let pin = String(repeating: "a", count: 64)
        let json = """
        {"version":1,"username":"u","password":"p","servers":[{"name":"S","host":"h.example.com","port":443,"spki_sha256":"\(pin)"}]}
        """
        let encoded = Data(json.utf8).base64EncodedString()
        let token = try TokenParser.parse("fptn:" + encoded)
        XCTAssertEqual(token.servers[0].spkiSHA256, pin)
    }

    func testLegacyTokenHasNoSPKIPin() throws {
        let json = """
        {"username":"u","password":"p","servers":[{"name":"S","host":"h.example.com","port":443}]}
        """
        let token = try TokenParser.parse(Data(json.utf8).base64EncodedString())
        XCTAssertNil(token.servers[0].spkiSHA256)
    }

    func testAddingSPKIPinDoesNotDuplicate() {
        let pin = String(repeating: "b", count: 64)
        var options = CertificateSecurityOptions(spkiPins: [pin])
        options = options.addingSPKIPin(pin)
        XCTAssertEqual(options.spkiPins, [pin])
        XCTAssertEqual(
            CertificateSecurityOptions().addingSPKIPin(nil).spkiPins,
            []
        )
    }
}

private extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let value = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(value)
            index = next
        }
        self = Data(bytes)
    }
}
