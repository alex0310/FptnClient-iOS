import Foundation
import XCTest
import _CryptoExtras

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

final class CertificateVerifyTests: XCTestCase {
    private let transcriptHash = [UInt8](repeating: 0xab, count: 32)

    func testSignedContentLayout() {
        let content = CertificateVerifyContext.signedContent(transcriptHash: transcriptHash)
        let label = Array("TLS 1.3, server CertificateVerify".utf8)
        XCTAssertEqual(content.count, 64 + label.count + 1 + transcriptHash.count)
        XCTAssertEqual(Array(content.prefix(64)), [UInt8](repeating: 0x20, count: 64))
        XCTAssertEqual(Array(content[64..<(64 + label.count)]), label)
        XCTAssertEqual(content[64 + label.count], 0x00)
        XCTAssertEqual(Array(content.suffix(transcriptHash.count)), transcriptHash)

        let client = CertificateVerifyContext.signedContent(
            transcriptHash: transcriptHash,
            isServer: false
        )
        XCTAssertNotEqual(content, client)
    }

    func testRSAPSSCertificateVerifySignature() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let privateKey = try _RSA.Signing.PrivateKey(
            pemRepresentation: CertificateFixtures.pem("rsa-leaf-key")
        )
        let content = CertificateVerifyContext.signedContent(transcriptHash: transcriptHash)
        let signature = try privateKey.signature(
            for: SHA256.hash(data: Data(content)),
            padding: .PSS
        )
        XCTAssertTrue(
            try CertificateSignature.verifyCertificateVerify(
                signature: Array(signature.rawRepresentation),
                scheme: .rsaPSSSHA256,
                signedContent: content,
                leaf: leaf
            )
        )
    }

    func testCertificateVerifyRejectsTamperedContent() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        let privateKey = try _RSA.Signing.PrivateKey(
            pemRepresentation: CertificateFixtures.pem("rsa-leaf-key")
        )
        let content = CertificateVerifyContext.signedContent(transcriptHash: transcriptHash)
        let signature = try privateKey.signature(
            for: SHA256.hash(data: Data(content)),
            padding: .PSS
        )
        var tampered = content
        tampered[70] ^= 0xff
        XCTAssertFalse(
            try CertificateSignature.verifyCertificateVerify(
                signature: Array(signature.rawRepresentation),
                scheme: .rsaPSSSHA256,
                signedContent: tampered,
                leaf: leaf
            )
        )
    }

    func testCertificateVerifyRejectsWrongKeyType() throws {
        let leaf = try X509Certificate(der: CertificateFixtures.der("rsa-leaf"))
        XCTAssertThrowsError(
            try CertificateSignature.verifyCertificateVerify(
                signature: [UInt8](repeating: 0, count: 64),
                scheme: .ecdsaP256SHA256,
                signedContent: [0x01],
                leaf: leaf
            )
        ) { error in
            XCTAssertEqual(
                error as? CertificateSignatureError,
                .unsupportedKey(X509OID.rsaEncryption)
            )
        }
    }

    func testSignatureSchemeMapping() {
        XCTAssertEqual(TLSSignatureScheme(rawValue: 0x0804), .rsaPSSSHA256)
        XCTAssertEqual(TLSSignatureScheme(rawValue: 0x0403), .ecdsaP256SHA256)
        XCTAssertNil(TLSSignatureScheme(rawValue: 0xffff))
    }
}
