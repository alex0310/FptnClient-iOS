import Foundation
import XCTest

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

final class CertificateTransparencyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_794_591_627)
    private let timestamp: UInt64 = 1_794_591_000_000

    private func makeLog() throws -> (P256.Signing.PrivateKey, CTLog) {
        let key = P256.Signing.PrivateKey()
        let keyBytes = [UInt8](key.publicKey.rawRepresentation)
        let log = CTLog.trusted(keyBytes: keyBytes, algorithm: .ecdsaP256)
        return (key, log)
    }

    func testParsesSCTList() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: timestamp, key: key
        )
        let scts = try SCTList.parse(list)
        XCTAssertEqual(scts.count, 1)
        XCTAssertEqual(scts[0].logID, log.logID)
        XCTAssertEqual(scts[0].timestamp, timestamp)
        XCTAssertEqual(scts[0].hashAlgorithm, 4)
        XCTAssertEqual(scts[0].signatureAlgorithm, 3)
        XCTAssertFalse(scts[0].signature.isEmpty)
    }

    func testSignedDataLayout() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let sct = SignedCertificateTimestamp(
            version: 0,
            logID: [UInt8](repeating: 0x11, count: 32),
            timestamp: timestamp,
            extensions: [0xaa, 0xbb],
            hashAlgorithm: 4,
            signatureAlgorithm: 3,
            signature: []
        )
        let signed = SCTList.signedData(for: sct, certificateDER: der)
        XCTAssertEqual(Array(signed.prefix(2)), [0x00, 0x00])
        XCTAssertEqual(Array(signed[10..<12]), [0x00, 0x00])
        XCTAssertEqual(Array(signed.suffix(2)), [0xaa, 0xbb])
        XCTAssertEqual(
            Array(signed[15..<(15 + der.count)]),
            der
        )
    }

    func testValidSCTPasses() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: timestamp, key: key
        )
        let policy = CTPolicy(trustedLogs: [log], minimumValidSCTs: 1)
        XCTAssertEqual(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: list, embeddedSCTList: nil,
                certificateDER: der, policy: policy, now: now
            ),
            1
        )
    }

    func testDisabledPolicyIsANoOp() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        XCTAssertEqual(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: nil, embeddedSCTList: nil,
                certificateDER: der, policy: .disabled, now: now
            ),
            0
        )
    }

    func testMissingSCTFails() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (_, log) = try makeLog()
        let policy = CTPolicy(trustedLogs: [log], minimumValidSCTs: 1)
        XCTAssertThrowsError(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: nil, embeddedSCTList: nil,
                certificateDER: der, policy: policy, now: now
            )
        ) { error in
            XCTAssertEqual(error as? CertificateTransparencyError, .missingSCT)
        }
    }

    func testUntrustedLogFails() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, _) = try makeLog()
        let (_, otherLog) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: otherLog.logID, timestamp: timestamp, key: key
        )
        let policy = CTPolicy(trustedLogs: [otherLog], minimumValidSCTs: 1)
        // otherLog's key differs from `key`, so the signature must fail.
        XCTAssertThrowsError(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: list, embeddedSCTList: nil,
                certificateDER: der, policy: policy, now: now
            )
        ) { error in
            XCTAssertEqual(error as? CertificateTransparencyError, .invalidSignature)
        }
    }

    func testFutureTimestampFails() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let future = UInt64(now.addingTimeInterval(3600).timeIntervalSince1970 * 1_000)
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: future, key: key
        )
        let policy = CTPolicy(
            trustedLogs: [log], minimumValidSCTs: 1, timestampSkew: 10
        )
        XCTAssertThrowsError(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: list, embeddedSCTList: nil,
                certificateDER: der, policy: policy, now: now
            )
        ) { error in
            XCTAssertEqual(error as? CertificateTransparencyError, .futureTimestamp)
        }
    }

    func testEmbeddedSCTListIsAlsoAccepted() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: timestamp, key: key
        )
        let policy = CTPolicy(trustedLogs: [log], minimumValidSCTs: 1)
        XCTAssertEqual(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: nil, embeddedSCTList: list,
                certificateDER: der, policy: policy, now: now
            ),
            1
        )
    }

    func testParseEmbeddedDERWrappedList() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: timestamp, key: key
        )
        let wrapped = DERTestBuilder.octetString(list)
        XCTAssertEqual(try SCTList.parseEmbedded(wrapped).count, 1)
    }

    func testInsufficientSCTCountFails() throws {
        let der = try CertificateFixtures.der("rsa-leaf")
        let (key, log) = try makeLog()
        let list = try CertificateSecurityFixtures.sctList(
            certificateDER: der, logID: log.logID, timestamp: timestamp, key: key
        )
        let policy = CTPolicy(trustedLogs: [log], minimumValidSCTs: 2)
        XCTAssertThrowsError(
            try CertificateTransparencyVerifier.verify(
                tlsSCTList: list, embeddedSCTList: nil,
                certificateDER: der, policy: policy, now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .insufficientSCTs(valid: 1, required: 2)
            )
        }
    }
}
