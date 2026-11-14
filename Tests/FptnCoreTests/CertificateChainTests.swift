import Foundation
import XCTest

@testable import FptnCore

final class CertificateChainTests: XCTestCase {
    private let hostname = "vpn.example.com"

    private func anchors(_ names: [String] = ["rsa-root"]) throws -> X509TrustAnchors {
        try X509TrustAnchors(derRoots: names.map(CertificateFixtures.der))
    }

    private func chain(_ names: [String]) throws -> [[UInt8]] {
        try names.map(CertificateFixtures.der)
    }

    func testValidRSAChainToAnchor() throws {
        let leaf = try CertificateChainValidator.validate(
            chainDER: chain(["rsa-leaf", "rsa-root"]),
            hostname: hostname,
            anchors: anchors()
        )
        XCTAssertEqual(leaf.commonName, "vpn.example.com")
    }

    func testValidChainWithAnchorOutsideChain() throws {
        let leaf = try CertificateChainValidator.validate(
            chainDER: chain(["rsa-leaf"]),
            hostname: hostname,
            anchors: anchors()
        )
        XCTAssertEqual(leaf.dnsNames, ["vpn.example.com", "*.wild.example.com"])
    }

    func testValidECDSAChain() throws {
        let leaf = try CertificateChainValidator.validate(
            chainDER: chain(["ec-leaf", "ec-root"]),
            hostname: hostname,
            anchors: anchors(["ec-root"])
        )
        XCTAssertEqual(leaf.publicKeyAlgorithmOID, X509OID.ecPublicKey)
    }

    func testCertificateSignatureIsActuallyVerified() throws {
        let root = try X509Certificate(der: CertificateFixtures.der("rsa-root"))
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        XCTAssertTrue(try CertificateSignature.verify(certificate: leaf, issuer: root))

        let ecRoot = try X509Certificate(der: CertificateFixtures.der("ec-root"))
        let ecLeaf = try X509Certificate(der: CertificateFixtures.der("ec-leaf"))
        XCTAssertTrue(try CertificateSignature.verify(certificate: ecLeaf, issuer: ecRoot))
    }

    func testTamperedSignatureIsRejected() throws {
        var leafDER = try CertificateFixtures.der("rsa-leaf")
        leafDER[leafDER.count - 1] ^= 0xff
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: [leafDER],
                hostname: hostname,
                anchors: anchors()
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .invalidSignature)
        }
    }

    func testWrongHostnameIsRejected() throws {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-leaf"]),
                hostname: "other.example.com",
                anchors: anchors()
            )
        ) { error in
            guard case .hostnameMismatch = error as? CertificateChainError else {
                return XCTFail("Expected hostnameMismatch, got \(error)")
            }
        }
    }

    func testWrongSANCertificateIsRejectedForOurHost() throws {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-wrong"]),
                hostname: hostname,
                anchors: anchors()
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .hostnameMismatch(
                expected: hostname, present: ["other.example.com"]
            ))
        }
    }

    func testRogueAnchorIsRejected() throws {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-leaf", "rsa-root"]),
                hostname: hostname,
                anchors: anchors(["rsa-rogue"])
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .brokenChain)
        }
    }

    func testNoAnchorsFailsClosed() {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-leaf"]),
                hostname: hostname,
                anchors: .empty
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .noTrustAnchor)
        }
    }

    func testExpiredAndNotYetValidChainsAreRejected() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let future = leaf.notAfter.addingTimeInterval(1)
        let past = leaf.notBefore.addingTimeInterval(-1)
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-leaf"]),
                hostname: hostname,
                anchors: anchors(),
                now: future
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .expired)
        }
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: chain(["rsa-leaf"]),
                hostname: hostname,
                anchors: anchors(),
                now: past
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .notYetValid)
        }
    }

    func testEmptyChainIsRejected() {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: [],
                hostname: hostname,
                anchors: anchors()
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .emptyChain)
        }
    }

    func testMalformedCertificateIsRejected() {
        XCTAssertThrowsError(
            try CertificateChainValidator.validate(
                chainDER: [[0x30, 0x00]],
                hostname: hostname,
                anchors: anchors()
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .malformedCertificate)
        }
    }

    // MARK: - Hostname matching

    func testExactAndWildcardHostnames() {
        XCTAssertTrue(CertificateHostname.matches(pattern: "vpn.example.com", hostname: "VPN.Example.COM"))
        XCTAssertTrue(CertificateHostname.matches(pattern: "*.wild.example.com", hostname: "a.wild.example.com"))
        XCTAssertFalse(CertificateHostname.matches(pattern: "*.wild.example.com", hostname: "wild.example.com"))
        XCTAssertFalse(CertificateHostname.matches(pattern: "*.wild.example.com", hostname: "a.b.wild.example.com"))
        XCTAssertFalse(CertificateHostname.matches(pattern: "f*.example.com", hostname: "foo.example.com"))
        XCTAssertTrue(CertificateHostname.matches(pattern: "vpn.example.com.", hostname: "vpn.example.com"))
    }

    // MARK: - Policy dispatch

    func testPinnedMD5PolicyStillWorks() throws {
        let leafDER = try CertificateFixtures.der("rsa-leaf")
        let pin = CertificateFingerprint.md5(of: leafDER)
        let leaf = try CertificateAuthenticator.verify(
            chainDER: [leafDER],
            hostname: hostname,
            policy: .pinnedMD5(pin)
        )
        XCTAssertNil(leaf)
    }

    func testNilPinFailsClosed() throws {
        XCTAssertThrowsError(
            try CertificateAuthenticator.verify(
                chainDER: chain(["rsa-leaf"]),
                hostname: hostname,
                policy: .pinnedMD5(nil)
            )
        ) { error in
            XCTAssertEqual(error as? TLSError, .missingServerAuthentication)
        }
    }

    func testStrictPolicyReturnsLeafForCertificateVerify() throws {
        let leaf = try CertificateAuthenticator.verify(
            chainDER: chain(["rsa-leaf"]),
            hostname: hostname,
            policy: .strictChain(anchors())
        )
        XCTAssertEqual(leaf?.commonName, "vpn.example.com")
    }
}
