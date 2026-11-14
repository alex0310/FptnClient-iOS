import Foundation
import XCTest

@testable import FptnCore

final class CertificateRevocationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_794_591_627)  // 2026-11-13

    private func issuer() throws -> X509Certificate {
        try X509Certificate(der: CertificateFixtures.der("rsa-root"))
    }

    private func leaf() throws -> X509Certificate {
        try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
    }

    // MARK: - CRL

    func testParsesSignedCRL() throws {
        let root = try issuer()
        let der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [[0x01, 0x02, 0x03]],
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let info = try CertificateCRL.parse(der)
        XCTAssertEqual(info.issuerDER, root.subjectDER)
        XCTAssertEqual(info.revokedSerials, [[0x01, 0x02, 0x03]])
        XCTAssertNotNil(info.nextUpdate)
        XCTAssertEqual(info.signatureAlgorithmOID, X509OID.sha256WithRSA)
    }

    func testValidGoodCRLPasses() throws {
        let root = try issuer()
        let der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [[0x01]],
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let info = try CertificateCRL.parse(der)
        XCTAssertNoThrow(
            try CertificateCRL.verify(info, certificate: leaf(), issuer: root, now: now)
        )
    }

    func testRevokedSerialIsRejected() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [leaf.serialNumber],
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let info = try CertificateCRL.parse(der)
        XCTAssertThrowsError(
            try CertificateCRL.verify(info, certificate: leaf, issuer: root, now: now)
        ) { error in
            XCTAssertEqual(error as? CertificateCRLError, .revoked)
        }
    }

    func testExpiredCRLIsRejected() throws {
        let root = try issuer()
        let der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [],
            thisUpdate: now.addingTimeInterval(-7200),
            nextUpdate: now.addingTimeInterval(-3600)
        )
        let info = try CertificateCRL.parse(der)
        XCTAssertThrowsError(
            try CertificateCRL.verify(info, certificate: leaf(), issuer: root, now: now)
        ) { error in
            guard case .expired = error as? CertificateCRLError else {
                return XCTFail("Expected expired, got \(error)")
            }
        }
    }

    func testTamperedCRLSignatureIsRejected() throws {
        let root = try issuer()
        var der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [],
            thisUpdate: now.addingTimeInterval(-3600)
        )
        der[der.count - 1] ^= 0xff
        let info = try CertificateCRL.parse(der)
        XCTAssertThrowsError(
            try CertificateCRL.verify(info, certificate: leaf(), issuer: root, now: now)
        ) { error in
            XCTAssertEqual(error as? CertificateCRLError, .invalidSignature)
        }
    }

    // MARK: - OCSP

    func testParsesGoodOCSPResponse() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let infos = try CertificateOCSP.parse(der)
        XCTAssertEqual(infos.count, 1)
        XCTAssertEqual(infos[0].status, .good)
        XCTAssertEqual(infos[0].serialNumber, leaf.serialNumber)
    }

    func testGoodOCSPStatusPasses() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let infos = try CertificateOCSP.parse(der)
        XCTAssertNoThrow(
            try CertificateOCSP.verify(infos, certificate: leaf, issuer: root, now: now)
        )
    }

    func testRevokedOCSPStatusIsRejected() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0xa1,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let infos = try CertificateOCSP.parse(der)
        XCTAssertThrowsError(
            try CertificateOCSP.verify(infos, certificate: leaf, issuer: root, now: now)
        ) { error in
            XCTAssertEqual(error as? CertificateOCSPError, .revoked)
        }
    }

    func testUnknownOCSPStatusIsRejected() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x82,
            thisUpdate: now.addingTimeInterval(-3600)
        )
        let infos = try CertificateOCSP.parse(der)
        XCTAssertThrowsError(
            try CertificateOCSP.verify(infos, certificate: leaf, issuer: root, now: now)
        ) { error in
            XCTAssertEqual(error as? CertificateOCSPError, .unknownStatus)
        }
    }

    func testStaleOCSPStatusIsRejected() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-7200),
            nextUpdate: now.addingTimeInterval(-3600)
        )
        let infos = try CertificateOCSP.parse(der)
        XCTAssertThrowsError(
            try CertificateOCSP.verify(infos, certificate: leaf, issuer: root, now: now)
        ) { error in
            guard case .expired = error as? CertificateOCSPError else {
                return XCTFail("Expected expired, got \(error)")
            }
        }
    }

    func testTamperedOCSPSignatureIsRejected() throws {
        let root = try issuer()
        let leaf = try leaf()
        var der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-3600)
        )
        der[der.count - 1] ^= 0xff
        let infos = try CertificateOCSP.parse(der)
        XCTAssertThrowsError(
            try CertificateOCSP.verify(infos, certificate: leaf, issuer: root, now: now)
        ) { error in
            XCTAssertEqual(error as? CertificateOCSPError, .invalidSignature)
        }
    }

    // MARK: - Policy

    func testPolicyAcceptsFreshOCSPStatus() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let policy = RevocationPolicy(ocspDERs: [der], requireStatus: true)
        XCTAssertTrue(
            try CertificateRevocation.verify(
                certificate: leaf, issuer: root, policy: policy, now: now
            )
        )
    }

    func testPolicyAcceptsFreshCRL() throws {
        let root = try issuer()
        let leaf = try leaf()
        let der = try CertificateSecurityFixtures.crl(
            issuer: root,
            revokedSerials: [],
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        let policy = RevocationPolicy(crlDERs: [der], requireStatus: true)
        XCTAssertTrue(
            try CertificateRevocation.verify(
                certificate: leaf, issuer: root, policy: policy, now: now
            )
        )
    }

    func testPolicyFailsClosedWithoutDataWhenRequired() throws {
        let root = try issuer()
        let policy = RevocationPolicy(requireStatus: true)
        XCTAssertThrowsError(
            try CertificateRevocation.verify(
                certificate: leaf(), issuer: root, policy: policy, now: now
            )
        ) { error in
            XCTAssertEqual(error as? CertificateRevocationError, .noRevocationData)
        }
    }

    func testDisabledPolicyIsANoOp() throws {
        XCTAssertFalse(
            try CertificateRevocation.verify(
                certificate: leaf(), issuer: nil, policy: .disabled, now: now
            )
        )
    }
}
