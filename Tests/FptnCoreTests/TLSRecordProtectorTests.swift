import XCTest

@testable import FptnCore

final class TLSRecordProtectorTests: XCTestCase {
    private func makeProtector(
        _ suite: TLSCipherSuite = .aes128GcmSha256,
        keyByte: UInt8 = 0x11
    ) throws -> TLSRecordProtector {
        try TLSRecordProtector(
            suite: suite,
            key: Array(repeating: keyByte, count: suite.keyLength),
            iv: Array(repeating: UInt8(0x22), count: 12)
        )
    }

    private func makePair(
        _ suite: TLSCipherSuite = .aes128GcmSha256
    ) throws -> (sender: TLSRecordProtector, receiver: TLSRecordProtector) {
        (try makeProtector(suite), try makeProtector(suite))
    }

    func testRoundTripForEveryCipherSuite() throws {
        for suite in TLSCipherSuite.allCases {
            let pair = try makePair(suite)
            let plaintext = Array("hello, fptn".utf8)
            let sealed = try pair.sender.seal(contentType: .applicationData, plaintext: plaintext)
            let opened = try pair.receiver.open(fragment: Array(sealed.dropFirst(5)))
            XCTAssertEqual(opened.contentType, .applicationData)
            XCTAssertEqual(opened.plaintext, plaintext)
        }
    }

    func testSealUsesApplicationDataOuterTypeAndTLS12Version() throws {
        let protector = try makeProtector()
        let sealed = try protector.seal(contentType: .handshake, plaintext: [0x01])
        XCTAssertEqual(Array(sealed.prefix(3)), [0x17, 0x03, 0x03])
    }

    func testOpenReturnsInnerContentType() throws {
        let pair = try makePair()
        for type in [TLSContentType.handshake, .alert, .applicationData] {
            let sealed = try pair.sender.seal(contentType: type, plaintext: [0xaa])
            let opened = try pair.receiver.open(fragment: Array(sealed.dropFirst(5)))
            XCTAssertEqual(opened.contentType, type)
        }
    }

    func testSequenceNumbersProduceDifferentCiphertexts() throws {
        let protector = try makeProtector()
        let first = try protector.seal(contentType: .applicationData, plaintext: [0x01])
        let second = try protector.seal(contentType: .applicationData, plaintext: [0x01])
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(protector.sequence, 2)
    }

    func testResetRewindsSequence() throws {
        let protector = try makeProtector()
        let first = try protector.seal(contentType: .applicationData, plaintext: [0x01])
        try protector.reset(
            suite: .aes128GcmSha256,
            key: Array(repeating: UInt8(0x11), count: 16),
            iv: Array(repeating: UInt8(0x22), count: 12)
        )
        XCTAssertEqual(protector.sequence, 0)
        let second = try protector.seal(contentType: .applicationData, plaintext: [0x01])
        XCTAssertEqual(first, second)
    }

    func testTamperedCiphertextIsRejected() throws {
        let pair = try makePair()
        let clean = try pair.sender.seal(contentType: .applicationData, plaintext: [0x01, 0x02])
        XCTAssertEqual(
            try pair.receiver.open(fragment: Array(clean.dropFirst(5))).plaintext,
            [0x01, 0x02]
        )

        var tampered = try pair.sender.seal(contentType: .applicationData, plaintext: [0x03])
        tampered[tampered.count - 1] ^= 0xff
        XCTAssertThrowsError(try pair.receiver.open(fragment: Array(tampered.dropFirst(5))))
    }

    func testWrongKeyIsRejected() throws {
        let sender = try makeProtector()
        let receiver = try makeProtector(keyByte: 0x33)
        let sealed = try sender.seal(contentType: .applicationData, plaintext: [0x01])
        XCTAssertThrowsError(try receiver.open(fragment: Array(sealed.dropFirst(5))))
    }

    func testTruncatedFragmentIsRejected() throws {
        let protector = try makeProtector()
        XCTAssertThrowsError(try protector.open(fragment: [0x00]))
    }

    func testNonApplicationDataOuterTypeIsRejected() throws {
        let pair = try makePair()
        let sealed = try pair.sender.seal(contentType: .applicationData, plaintext: [0x01])
        XCTAssertThrowsError(try pair.receiver.open(
            fragment: Array(sealed.dropFirst(5)),
            type: .handshake
        ))
    }

    func testMaximumPlaintextLengthIsAccepted() throws {
        let pair = try makePair()
        let plaintext = Array(
            repeating: UInt8(0x5a),
            count: TLSRecordProtector.maximumPlaintextLength
        )
        let sealed = try pair.sender.seal(contentType: .applicationData, plaintext: plaintext)
        let opened = try pair.receiver.open(fragment: Array(sealed.dropFirst(5)))
        XCTAssertEqual(opened.plaintext, plaintext)
    }

    func testOversizedPlaintextIsRejected() throws {
        let protector = try makeProtector()
        let plaintext = Array(
            repeating: UInt8(0x5a),
            count: TLSRecordProtector.maximumPlaintextLength + 1
        )
        XCTAssertThrowsError(try protector.seal(contentType: .applicationData, plaintext: plaintext))
    }

    func testPlaintextWithTrailingZerosRoundTrips() throws {
        let pair = try makePair()
        let plaintext: [UInt8] = [0x01, 0x00, 0x00, 0x00]
        let sealed = try pair.sender.seal(contentType: .applicationData, plaintext: plaintext)
        let opened = try pair.receiver.open(fragment: Array(sealed.dropFirst(5)))
        XCTAssertEqual(opened.plaintext, plaintext)
    }

    func testEmptyPlaintextRoundTrips() throws {
        let pair = try makePair()
        let sealed = try pair.sender.seal(contentType: .applicationData, plaintext: [])
        let opened = try pair.receiver.open(fragment: Array(sealed.dropFirst(5)))
        XCTAssertEqual(opened.contentType, .applicationData)
        XCTAssertEqual(opened.plaintext, [])
    }

    func testInvalidKeyAndNonceLengthsAreRejected() {
        XCTAssertThrowsError(try TLSRecordProtector(
            suite: .aes128GcmSha256,
            key: [0x00],
            iv: Array(repeating: 0, count: 12)
        ))
        XCTAssertThrowsError(try TLSRecordProtector(
            suite: .aes128GcmSha256,
            key: Array(repeating: 0, count: 16),
            iv: [0x00]
        ))
    }
}
