import Foundation
import XCTest
import _CryptoExtras

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

/// End-to-end checks that SPKI pins, stapled OCSP and TLS SCT extensions are
/// actually consumed by the handshake, not just by unit-level parsers.
final class CertificateSecurityIntegrationTests: XCTestCase {
    /// Handshake checks use the real clock, so revocation fixtures must be
    /// relative to it rather than to a frozen unit-test date.
    private var now: Date { Date() }
    private var timestamp: UInt64 { UInt64(Date().timeIntervalSince1970 * 1_000) - 60_000 }

    private func anchors() throws -> X509TrustAnchors {
        try X509TrustAnchors(derRoots: [CertificateFixtures.der("rsa-root")])
    }

    private func makeServer() throws -> SimulatedTLSServer {
        let server = SimulatedTLSServer()
        server.certificateChainDER = [
            try CertificateFixtures.der("rsa-leaf"),
            try CertificateFixtures.der("rsa-root")
        ]
        server.certificateVerifyScheme = 0x0804
        let privateKey = try _RSA.Signing.PrivateKey(
            pemRepresentation: CertificateFixtures.pem("rsa-leaf-key")
        )
        server.certificateVerifySigner = { content in
            let signature = try privateKey.signature(
                for: SHA256.hash(data: Data(content)),
                padding: .PSS
            )
            return Array(signature.rawRepresentation)
        }
        return server
    }

    private func makeClient(security: CertificateSecurityOptions) throws -> TLSClientSession {
        try TLSClientSession(
            configuration: TLSClientConfiguration(
                serverName: "vpn.example.com",
                certificatePolicy: .strictChain(anchors()),
                certificateSecurity: security
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: 1_700_000_000
        )
    }

    private func handshake(
        security: CertificateSecurityOptions
    ) throws -> (client: TLSClientSession, server: SimulatedTLSServer) {
        let client = try makeClient(security: security)
        let server = try makeServer()
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        _ = try client.receive(flight)
        return (client, server)
    }

    func testMatchingSPKIPinPasses() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let pin = CertificateSPKI.sha256(of: leaf)
        let security = CertificateSecurityOptions(spkiPins: [pin])
        let result = try handshake(security: security)
        XCTAssertTrue(result.client.isConnected)
    }

    func testWrongSPKIPinRejectsHandshake() throws {
        let security = CertificateSecurityOptions(
            spkiPins: [String(repeating: "0", count: 64)]
        )
        XCTAssertThrowsError(try handshake(security: security)) { error in
            guard case .pinMismatch = error as? CertificateSPKIError else {
                return XCTFail("Expected pinMismatch, got \(error)")
            }
        }
    }

    func testStapledGoodOCSPPasses() throws {
        let root = try X509Certificate(der: CertificateFixtures.der("rsa-root"))
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let ocsp = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0x80,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        var statusData: [UInt8] = [0x01]
        statusData += [
            UInt8((ocsp.count >> 16) & 0xff),
            UInt8((ocsp.count >> 8) & 0xff),
            UInt8(ocsp.count & 0xff)
        ]
        statusData += ocsp

        let server = try makeServer()
        server.certificateEntryExtensions = [
            TLSCertificateEntryExtensions.statusRequest: statusData
        ]
        let client = try makeClient(
            security: CertificateSecurityOptions(
                revocation: RevocationPolicy(requireStatus: true)
            )
        )
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertNoThrow(try client.receive(flight))
        XCTAssertTrue(client.isConnected)
    }

    func testStapledRevokedOCSPRejectsHandshake() throws {
        let root = try X509Certificate(der: CertificateFixtures.der("rsa-root"))
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let ocsp = try CertificateSecurityFixtures.ocsp(
            issuer: root,
            serialNumber: leaf.serialNumber,
            statusTag: 0xa1,
            thisUpdate: now.addingTimeInterval(-3600),
            nextUpdate: now.addingTimeInterval(3600)
        )
        var statusData: [UInt8] = [0x01]
        statusData += [
            UInt8((ocsp.count >> 16) & 0xff),
            UInt8((ocsp.count >> 8) & 0xff),
            UInt8(ocsp.count & 0xff)
        ]
        statusData += ocsp

        let server = try makeServer()
        server.certificateEntryExtensions = [
            TLSCertificateEntryExtensions.statusRequest: statusData
        ]
        let client = try makeClient(
            security: CertificateSecurityOptions(
                revocation: RevocationPolicy(requireStatus: true)
            )
        )
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? CertificateOCSPError, .revoked)
        }
    }

    func testTLSSCTExtensionIsVerified() throws {
        let leafDER = try CertificateFixtures.der("rsa-leaf")
        let key = P256.Signing.PrivateKey()
        let keyBytes = [UInt8](key.publicKey.rawRepresentation)
        let log = CTLog.trusted(keyBytes: keyBytes, algorithm: .ecdsaP256)
        let sctList = try CertificateSecurityFixtures.sctList(
            certificateDER: leafDER,
            logID: log.logID,
            timestamp: timestamp,
            key: key
        )
        let server = try makeServer()
        server.certificateEntryExtensions = [
            TLSCertificateEntryExtensions.signedCertificateTimestamp: sctList
        ]
        let client = try makeClient(
            security: CertificateSecurityOptions(
                transparency: CTPolicy(trustedLogs: [log], minimumValidSCTs: 1)
            )
        )
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertNoThrow(try client.receive(flight))
        XCTAssertTrue(client.isConnected)
    }

    func testMissingSCTRejectsHandshake() throws {
        let key = P256.Signing.PrivateKey()
        let log = CTLog.trusted(
            keyBytes: [UInt8](key.publicKey.rawRepresentation),
            algorithm: .ecdsaP256
        )
        XCTAssertThrowsError(
            try handshake(
                security: CertificateSecurityOptions(
                    transparency: CTPolicy(
                        trustedLogs: [log], minimumValidSCTs: 1
                    )
                )
            )
        ) { error in
            XCTAssertEqual(error as? CertificateTransparencyError, .missingSCT)
        }
    }
}
