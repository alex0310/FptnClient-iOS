import Foundation
import XCTest
import _CryptoExtras

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

/// End-to-end proof that `.strictChain` is actually wired into the TLS 1.3
/// handshake: certificate path validation plus a real CertificateVerify.
final class StrictChainHandshakeTests: XCTestCase {
    private func makeServer(signCertificateVerify: Bool) throws -> SimulatedTLSServer {
        let server = SimulatedTLSServer()
        server.certificateChainDER = [
            try CertificateFixtures.der("rsa-leaf"),
            try CertificateFixtures.der("rsa-root")
        ]
        server.certificateVerifyScheme = 0x0804  // rsa_pss_rsae_sha256
        if signCertificateVerify {
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
        }
        return server
    }

    private func makeClient(anchors: X509TrustAnchors) throws -> TLSClientSession {
        try TLSClientSession(
            configuration: TLSClientConfiguration(
                serverName: "vpn.example.com",
                certificatePolicy: .strictChain(anchors)
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: 1_700_000_000
        )
    }

    func testStrictChainHandshakeSucceeds() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-root")]
        )
        let client = try makeClient(anchors: anchors)
        let server = try makeServer(signCertificateVerify: true)

        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        let step = try client.receive(flight)

        XCTAssertTrue(client.isConnected)
        XCTAssertTrue(step.events.contains(.handshakeCompleted))
    }

    func testStrictChainRejectsFakeCertificateVerify() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-root")]
        )
        let client = try makeClient(anchors: anchors)
        let server = try makeServer(signCertificateVerify: false)

        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? TLSError, .certificateVerifyMismatch)
        }
        XCTAssertEqual(client.state, .failed)
    }

    func testStrictChainRejectsUntrustedRoot() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-rogue")]
        )
        let client = try makeClient(anchors: anchors)
        let server = try makeServer(signCertificateVerify: true)

        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? CertificateChainError, .brokenChain)
        }
    }

    func testStrictChainRejectsWrongHostname() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-root")]
        )
        let client = try TLSClientSession(
            configuration: TLSClientConfiguration(
                serverName: "other.example.com",
                certificatePolicy: .strictChain(anchors)
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: 1_700_000_000
        )
        let server = try makeServer(signCertificateVerify: true)

        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            guard case .hostnameMismatch = error as? CertificateChainError else {
                return XCTFail("Expected hostnameMismatch, got \(error)")
            }
        }
    }
}
