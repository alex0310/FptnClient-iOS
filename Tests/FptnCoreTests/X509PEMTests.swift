import Foundation
import XCTest

@testable import FptnCore

final class X509PEMTests: XCTestCase {
    private func pem(_ der: [UInt8]) -> String {
        let base64 = Data(der).base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    func testDecodesSingleCertificate() throws {
        let der = try CertificateFixtures.der("rsa-root")
        XCTAssertEqual(try X509PEM.decodeCertificates(pem(der)), [der])
    }

    func testDecodesMultipleCertificates() throws {
        let root = try CertificateFixtures.der("rsa-root")
        let rogue = try CertificateFixtures.der("rsa-rogue")
        XCTAssertEqual(try X509PEM.decodeCertificates(pem(root) + pem(rogue)), [root, rogue])
    }

    func testIgnoresCommentsAndBlankLines() throws {
        let der = try CertificateFixtures.der("rsa-root")
        let noisy = "# CA bundle\n\n" + pem(der) + "# trailing comment\n"
        XCTAssertEqual(try X509PEM.decodeCertificates(noisy), [der])
    }

    func testEmptyInputReturnsNoCertificates() throws {
        XCTAssertTrue(try X509PEM.decodeCertificates("").isEmpty)
    }

    func testRejectsMissingEndMarker() {
        let broken = "-----BEGIN CERTIFICATE-----\nQUJD\n"
        XCTAssertThrowsError(try X509PEM.decodeCertificates(broken)) { error in
            XCTAssertEqual(error as? X509PEMError, .missingEndMarker)
        }
    }

    func testRejectsInvalidBase64() {
        let broken = "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n"
        XCTAssertThrowsError(try X509PEM.decodeCertificates(broken)) { error in
            XCTAssertEqual(error as? X509PEMError, .invalidBase64)
        }
    }
}
