import Foundation
import XCTest

/// Production plumbing for the strict policy lives in files that the Linux
/// test suite does not compile as part of a handshake. These guards keep the
/// configuration path connected.
final class CertificatePolicyWiringTests: XCTestCase {
    private func source(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnCoreTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    func testTLSClientSessionUsesAuthenticatorAndCertificateVerify() throws {
        let session = try source("Sources/FptnCore/TLS/TLSClientSession.swift")
        XCTAssertTrue(session.contains("CertificateAuthenticator.verify"))
        XCTAssertTrue(session.contains("TLSCertificateVerifyValidation.verify"))
        XCTAssertFalse(session.contains("Signature verification is intentionally skipped"))
        let validation = try source(
            "Sources/FptnCore/TLS/TLSCertificateVerifyValidation.swift"
        )
        XCTAssertTrue(validation.contains("CertificateSignature.verifyCertificateVerify"))
    }

    func testConnectionConfigurationForwardsPolicy() throws {
        let connection = try source("Sources/FptnCore/Transport/TLSConnection.swift")
        XCTAssertTrue(connection.contains("certificatePolicy: configuration.certificatePolicy"))
    }

    func testFPTNClientForwardsPolicyToBothTransports() throws {
        let client = try source("Sources/FptnCore/Tunnel/FPTNClient.swift")
        XCTAssertTrue(client.contains("certificatePolicy: configuration.certificatePolicy"))
        let tunnel = try source("Sources/FptnCore/Tunnel/FPTNTunnel.swift")
        XCTAssertTrue(tunnel.contains("certificatePolicy: certificatePolicy"))
        let api = try source("Sources/FptnCore/Transport/FPTNAPITransport.swift")
        XCTAssertTrue(api.contains("certificatePolicy: certificatePolicy"))
    }

    func testMissingPinFailsClosed() throws {
        let pinner = try source("Sources/FptnCore/TLS/TLSCertificate.swift")
        XCTAssertTrue(pinner.contains("TLSError.missingServerAuthentication"))
        XCTAssertFalse(pinner.contains("guard let expected = expectedFingerprint else { return }"))
    }

    func testSystemTrustIsWired() throws {
        let types = try source("Sources/FptnCore/TLS/TLSClientTypes.swift")
        XCTAssertTrue(types.contains(".systemTrust"), "no-pin connections must use system trust")
        let policy = try source("Sources/FptnCore/TLS/CertificateChainPolicy.swift")
        XCTAssertTrue(policy.contains("case .systemTrust"))
        let trust = try source("Sources/FptnCore/TLS/SystemTrust.swift")
        XCTAssertTrue(trust.contains("SecTrustEvaluateWithError"))
        XCTAssertTrue(trust.contains("ca-certificates.crt"))
    }

    func testCertificateSecurityOptionsAreWired() throws {
        let session = try source("Sources/FptnCore/TLS/TLSClientSession.swift")
        XCTAssertTrue(session.contains("certificateSecurity"))
        XCTAssertTrue(session.contains("TLSCertificateEntryExtensions.parse"))
        let tunnel = try source("Sources/FptnCore/Tunnel/FPTNTunnel.swift")
        XCTAssertTrue(tunnel.contains("certificateSecurity"))
        let api = try source("Sources/FptnCore/Transport/FPTNAPITransport.swift")
        XCTAssertTrue(api.contains("certificateSecurity"))
        let client = try source("Sources/FptnCore/Tunnel/FPTNClient.swift")
        XCTAssertTrue(client.contains("certificateSecurity"))
        let token = try source("Sources/FptnCore/Protocol/FPTNToken.swift")
        XCTAssertTrue(token.contains("spki_sha256"))
    }
}
