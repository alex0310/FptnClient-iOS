import Foundation
import XCTest

@testable import FptnCore

final class SystemTrustTests: XCTestCase {
    private func pem(_ der: [UInt8]) -> String {
        let base64 = Data(der).base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    private func writeBundle(_ ders: [[UInt8]]) throws -> String {
        let text = ders.map(pem).joined()
        let path = NSTemporaryDirectory() + "fptn-roots-\(UUID().uuidString).pem"
        try text.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    func testLoadsCARootsFromInjectedPEMBundle() throws {
        let root = try CertificateFixtures.der("rsa-root")
        let rogue = try CertificateFixtures.der("rsa-rogue")
        let path = try writeBundle([root, rogue])
        defer { try? FileManager.default.removeItem(atPath: path) }

        let anchors = SystemTrustAnchors.load(paths: [path])
        XCTAssertEqual(anchors.certificates.count, 2)
        XCTAssertTrue(anchors.certificates.allSatisfy(\.isCA))
    }

    func testMissingPathsReturnEmptyAnchors() {
        XCTAssertTrue(
            SystemTrustAnchors.load(paths: ["/definitely/not/a/ca-bundle.pem"]).isEmpty
        )
    }

    func testOperatingSystemBundleProvidesUsableRoots() throws {
        // CI runners and normal Linux/macOS installations ship an OS CA bundle.
        // Every root must be a parseable CA certificate with a valid signature.
        let anchors = SystemTrustAnchors.shared
        XCTAssertFalse(anchors.isEmpty)
        XCTAssertGreaterThan(anchors.certificates.count, 20)
        XCTAssertTrue(anchors.certificates.allSatisfy(\.isCA))
        // Our verifier intentionally supports a subset of signature
        // algorithms; roots outside that subset fail closed instead of being
        // trusted. At least some OS roots must be verifiable with it.
        var verified = 0
        for root in anchors.certificates.prefix(20) {
            if (try? CertificateSignature.verify(certificate: root, issuer: root)) == true {
                verified += 1
            }
        }
        XCTAssertGreaterThan(verified, 0)
    }

    // MARK: - Policy

    func testSystemTrustPolicyUsesInjectedAnchors() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-root")]
        )
        let leaf = try CertificateAuthenticator.verify(
            chainDER: [
                try CertificateFixtures.der("rsa-leaf"),
                try CertificateFixtures.der("rsa-root")
            ],
            hostname: "vpn.example.com",
            policy: .systemTrust,
            systemAnchors: anchors
        )
        XCTAssertEqual(leaf?.commonName, "vpn.example.com")
    }

    func testSystemTrustPolicyRejectsUntrustedRoot() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-rogue")]
        )
        XCTAssertThrowsError(
            try CertificateAuthenticator.verify(
                chainDER: [
                    try CertificateFixtures.der("rsa-leaf"),
                    try CertificateFixtures.der("rsa-root")
                ],
                hostname: "vpn.example.com",
                policy: .systemTrust,
                systemAnchors: anchors
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .brokenChain)
        }
    }

    func testSystemTrustPolicyFailsClosedWithNoAnchors() throws {
        XCTAssertThrowsError(
            try CertificateAuthenticator.verify(
                chainDER: [try CertificateFixtures.der("rsa-leaf")],
                hostname: "vpn.example.com",
                policy: .systemTrust,
                systemAnchors: .empty
            )
        ) { error in
            XCTAssertEqual(error as? CertificateChainError, .noTrustAnchor)
        }
    }

    // MARK: - Defaults

    func testNoPinDefaultsToSystemTrust() {
        XCTAssertEqual(
            TLSClientConfiguration(serverName: "vpn.example.com").certificatePolicy,
            .systemTrust
        )
    }

    func testPinIsStillTheDefaultWhenPresent() {
        let pin = "0123456789abcdef0123456789abcdef"
        XCTAssertEqual(
            TLSClientConfiguration(
                serverName: "vpn.example.com",
                expectedCertificateMD5: pin
            ).certificatePolicy,
            .pinnedMD5(pin)
        )
    }

    func testExplicitPolicyWins() throws {
        let anchors = try X509TrustAnchors(
            derRoots: [CertificateFixtures.der("rsa-root")]
        )
        XCTAssertEqual(
            TLSClientConfiguration(
                serverName: "vpn.example.com",
                expectedCertificateMD5: "0123456789abcdef0123456789abcdef",
                certificatePolicy: .strictChain(anchors)
            ).certificatePolicy,
            .strictChain(anchors)
        )
    }
}
