import Foundation
import XCTest

@testable import FptnCore

final class X509CertificateTests: XCTestCase {
    func testParsesRSALeaf() throws {
        let certificate = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        XCTAssertEqual(certificate.commonName, "vpn.example.com")
        XCTAssertEqual(certificate.signatureAlgorithmOID, X509OID.sha256WithRSA)
        XCTAssertEqual(certificate.publicKeyAlgorithmOID, X509OID.rsaEncryption)
        XCTAssertNil(certificate.publicKeyCurveOID)
        XCTAssertFalse(certificate.publicKeyBytes.isEmpty)
        XCTAssertEqual(certificate.dnsNames, ["vpn.example.com", "*.wild.example.com"])
        XCTAssertFalse(certificate.isCA)
        XCTAssertTrue(certificate.supportsServerAuthentication)
        XCTAssertTrue(certificate.extendedKeyUsages.contains(X509OID.serverAuth))
        XCTAssertTrue(certificate.extensionOIDs.contains(X509OID.subjectAltName))
        XCTAssertTrue(certificate.extensionOIDs.contains(X509OID.basicConstraints))
        XCTAssertTrue(certificate.extensionOIDs.contains(X509OID.keyUsage))
        XCTAssertTrue(certificate.extensionOIDs.contains(X509OID.extKeyUsage))
        XCTAssertTrue(certificate.isValid(at: Date()))
    }

    func testParsesRSARootAsCA() throws {
        let root = try X509Certificate(der: CertificateFixtures.der("rsa-root"))
        XCTAssertEqual(root.commonName, "FPTN Test Root RSA")
        XCTAssertTrue(root.isCA)
        XCTAssertTrue(root.canSignCertificates)
        XCTAssertEqual(root.subjectDER, root.issuerDER)
    }

    func testParsesECDSAChain() throws {
        let root = try X509Certificate(der: CertificateFixtures.der("ec-root"))
        let leaf = try X509Certificate(der: CertificateFixtures.der("ec-leaf"))
        XCTAssertEqual(root.publicKeyAlgorithmOID, X509OID.ecPublicKey)
        XCTAssertEqual(root.publicKeyCurveOID, X509OID.secp256r1)
        XCTAssertEqual(leaf.signatureAlgorithmOID, X509OID.ecdsaWithSHA256)
        XCTAssertEqual(leaf.publicKeyAlgorithmOID, X509OID.ecPublicKey)
        XCTAssertEqual(leaf.publicKeyCurveOID, X509OID.secp256r1)
        XCTAssertEqual(leaf.dnsNames, ["vpn.example.com", "*.wild.example.com"])
    }

    func testParsesRealRFC8448Certificate() throws {
        let certificate = try X509Certificate(der: CertificateFixtures.rfc8448LeafDER())
        XCTAssertEqual(certificate.commonName, "rsa")
        XCTAssertEqual(certificate.signatureAlgorithmOID, X509OID.sha256WithRSA)
        XCTAssertEqual(certificate.publicKeyAlgorithmOID, X509OID.rsaEncryption)
        XCTAssertFalse(certificate.signature.isEmpty)
        XCTAssertTrue(certificate.isValid(at: Date(timeIntervalSince1970: 1_500_000_000)))
        XCTAssertFalse(certificate.isValid(at: Date(timeIntervalSince1970: 2_000_000_000)))
    }

    func testRejectsGarbageDER() {
        XCTAssertThrowsError(try X509Certificate(der: [0x30, 0x01, 0x00]))
    }

    func testValidityWindowBoundaries() throws {
        let certificate = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        XCTAssertTrue(certificate.isValid(at: certificate.notBefore))
        XCTAssertTrue(certificate.isValid(at: certificate.notAfter))
        XCTAssertFalse(certificate.isValid(at: certificate.notBefore.addingTimeInterval(-1)))
        XCTAssertFalse(certificate.isValid(at: certificate.notAfter.addingTimeInterval(1)))
    }

    func testSupportsServerAuthOnlyForMatchingEKU() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        XCTAssertTrue(leaf.supportsServerAuthentication)
    }
}
