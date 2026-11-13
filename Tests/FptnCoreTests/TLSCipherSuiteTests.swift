import XCTest
@testable import FptnCore

final class TLSCipherSuiteTests: XCTestCase {
    // RFC 8448 section 5 server handshake traffic keys and record.
    private let serverKey = hex("3fce516009c21727d0f2e4e86ee403bc")
    private let serverIV = hex("5d313eb2671276ee13000b30")
    // RFC 8448 section 5 client handshake traffic keys and Finished record.
    private let clientKey = hex("dbfaa693d1762c5b666af5d950258d01")
    private let clientIV = hex("5bd3c71b836e0b76bb73265f")

    func testDecryptsRFC8448ServerHandshakeRecord() throws {
        let record = RFC8448.serverHandshakeRecord
        XCTAssertEqual(record.count, 679)
        let header = Array(record[0..<5])
        let ciphertext = Array(record[5...])
        let plaintext = try TLSCipherSuite.aes128GcmSha256.open(
            key: serverKey,
            nonce: serverIV,
            ciphertext: ciphertext,
            additionalData: header
        )
        XCTAssertEqual(plaintext, RFC8448.serverHandshakePayload + [0x16])
    }

    func testSealsRFC8448ServerHandshakeRecordExactly() throws {
        let record = RFC8448.serverHandshakeRecord
        let header = Array(record[0..<5])
        let sealed = try TLSCipherSuite.aes128GcmSha256.seal(
            key: serverKey,
            nonce: serverIV,
            plaintext: RFC8448.serverHandshakePayload + [0x16],
            additionalData: header
        )
        XCTAssertEqual(sealed, Array(record[5...]))
    }

    func testDecryptsRFC8448ClientFinishedRecord() throws {
        let record = RFC8448.clientFinishedRecord
        XCTAssertEqual(record.count, 58)
        let plaintext = try TLSCipherSuite.aes128GcmSha256.open(
            key: clientKey,
            nonce: clientIV,
            ciphertext: Array(record[5...]),
            additionalData: Array(record[0..<5])
        )
        XCTAssertEqual(plaintext, RFC8448.clientFinished + [0x16])
    }

    func testAES256GCMRoundTrip() throws {
        let suite = TLSCipherSuite.aes256GcmSha384
        let key = [UInt8](repeating: 0x42, count: 32)
        let nonce = [UInt8](repeating: 0x24, count: 12)
        let plaintext = Array("fptn tunnel payload".utf8)
        let aad: [UInt8] = [0x17, 0x03, 0x03, 0x00, 0x10]
        let sealed = try suite.seal(key: key, nonce: nonce, plaintext: plaintext, additionalData: aad)
        XCTAssertEqual(sealed.count, plaintext.count + suite.tagLength)
        let opened = try suite.open(key: key, nonce: nonce, ciphertext: sealed, additionalData: aad)
        XCTAssertEqual(opened, plaintext)
    }

    func testChaCha20Poly1305RoundTrip() throws {
        let suite = TLSCipherSuite.chacha20Poly1305Sha256
        let key = [UInt8](repeating: 0x11, count: 32)
        let nonce = [UInt8](repeating: 0x22, count: 12)
        let plaintext = Array("quic-like record".utf8)
        let aad: [UInt8] = [0x17, 0x03, 0x03, 0x00, 0x0f]
        let sealed = try suite.seal(key: key, nonce: nonce, plaintext: plaintext, additionalData: aad)
        XCTAssertEqual(
            try suite.open(key: key, nonce: nonce, ciphertext: sealed, additionalData: aad),
            plaintext
        )
    }

    func testChaCha20Poly1305RFC8439Vector() throws {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = hex("070000004041424344454647")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Array(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8
        )
        let expectedCiphertext = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116" +
            "1ae10b594f09e26a7e902ecbd0600691"
        )
        let sealed = try TLSCipherSuite.chacha20Poly1305Sha256.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            additionalData: aad
        )
        XCTAssertEqual(sealed, expectedCiphertext)
        XCTAssertEqual(
            try TLSCipherSuite.chacha20Poly1305Sha256.open(
                key: key,
                nonce: nonce,
                ciphertext: sealed,
                additionalData: aad
            ),
            plaintext
        )
    }

    func testTamperedCiphertextFailsAuthentication() throws {
        let suite = TLSCipherSuite.aes128GcmSha256
        let key = [UInt8](repeating: 0x07, count: 16)
        let nonce = [UInt8](repeating: 0x08, count: 12)
        let sealed = try suite.seal(key: key, nonce: nonce, plaintext: [1, 2, 3], additionalData: [])
        var tampered = sealed
        tampered[0] ^= 0xff
        XCTAssertThrowsError(
            try suite.open(key: key, nonce: nonce, ciphertext: tampered, additionalData: [])
        ) { error in
            XCTAssertEqual(error as? TLSCipherSuiteError, .authenticationFailed)
        }
    }

    func testTamperedTagFailsAuthentication() throws {
        let suite = TLSCipherSuite.chacha20Poly1305Sha256
        let key = [UInt8](repeating: 0x07, count: 32)
        let nonce = [UInt8](repeating: 0x08, count: 12)
        let sealed = try suite.seal(key: key, nonce: nonce, plaintext: [1, 2, 3], additionalData: [9])
        var tampered = sealed
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(
            try suite.open(key: key, nonce: nonce, ciphertext: tampered, additionalData: [9])
        ) { error in
            XCTAssertEqual(error as? TLSCipherSuiteError, .authenticationFailed)
        }
    }

    func testWrongAdditionalDataFailsAuthentication() throws {
        let suite = TLSCipherSuite.aes256GcmSha384
        let key = [UInt8](repeating: 0x07, count: 32)
        let nonce = [UInt8](repeating: 0x08, count: 12)
        let sealed = try suite.seal(key: key, nonce: nonce, plaintext: [1, 2, 3], additionalData: [1, 2, 3])
        XCTAssertThrowsError(
            try suite.open(key: key, nonce: nonce, ciphertext: sealed, additionalData: [1, 2, 4])
        )
    }

    func testRejectsInvalidKeyLength() {
        XCTAssertThrowsError(
            try TLSCipherSuite.aes128GcmSha256.seal(
                key: [0, 0], nonce: [UInt8](repeating: 0, count: 12), plaintext: [], additionalData: []
            )
        ) { error in
            XCTAssertEqual(error as? TLSCipherSuiteError, .invalidKeyLength)
        }
    }

    func testRejectsInvalidNonceLength() {
        XCTAssertThrowsError(
            try TLSCipherSuite.aes128GcmSha256.seal(
                key: [UInt8](repeating: 0, count: 16), nonce: [0, 0], plaintext: [], additionalData: []
            )
        ) { error in
            XCTAssertEqual(error as? TLSCipherSuiteError, .invalidNonceLength)
        }
    }

    func testRejectsCiphertextShorterThanTag() {
        XCTAssertThrowsError(
            try TLSCipherSuite.aes128GcmSha256.open(
                key: [UInt8](repeating: 0, count: 16),
                nonce: [UInt8](repeating: 0, count: 12),
                ciphertext: [0, 0],
                additionalData: []
            )
        ) { error in
            XCTAssertEqual(error as? TLSCipherSuiteError, .authenticationFailed)
        }
    }

    func testSuitePropertiesAndLookup() {
        XCTAssertEqual(TLSCipherSuite.aes128GcmSha256.hash, .sha256)
        XCTAssertEqual(TLSCipherSuite.aes256GcmSha384.hash, .sha384)
        XCTAssertEqual(TLSCipherSuite.chacha20Poly1305Sha256.hash, .sha256)
        XCTAssertEqual(TLSCipherSuite.aes128GcmSha256.keyLength, 16)
        XCTAssertEqual(TLSCipherSuite.aes256GcmSha384.keyLength, 32)
        XCTAssertEqual(TLSCipherSuite.chacha20Poly1305Sha256.keyLength, 32)
        XCTAssertEqual(TLSCipherSuite.from(0x1301), .aes128GcmSha256)
        XCTAssertEqual(TLSCipherSuite.from(0x1302), .aes256GcmSha384)
        XCTAssertEqual(TLSCipherSuite.from(0x1303), .chacha20Poly1305Sha256)
        XCTAssertNil(TLSCipherSuite.from(0x1304))
        XCTAssertEqual(TLSCipherSuite.allCases.count, 3)
    }

    func testErrorDescriptionsAreUserReadable() {
        XCTAssertNotNil(TLSCipherSuiteError.unsupportedSuite(0x1304).errorDescription)
        XCTAssertNotNil(TLSCipherSuiteError.invalidKeyLength.errorDescription)
        XCTAssertNotNil(TLSCipherSuiteError.invalidNonceLength.errorDescription)
        XCTAssertNotNil(TLSCipherSuiteError.authenticationFailed.errorDescription)
    }
}
