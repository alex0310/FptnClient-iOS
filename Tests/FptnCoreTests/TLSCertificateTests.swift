import XCTest

@testable import FptnCore

final class TLSCertificateTests: XCTestCase {
    private let leaf = Array("leaf-certificate".utf8)
    private let intermediate = Array("intermediate-certificate".utf8)

    private func certificateMessage(entries: [[UInt8]]) -> TLSHandshakeMessage {
        var body = ByteWriter()
        body.writeLengthPrefixed8([])
        var list = ByteWriter()
        for entry in entries {
            var encoded = ByteWriter()
            encoded.writeLengthPrefixed24(entry)
            encoded.writeLengthPrefixed16([])
            list.write(contentsOf: encoded.bytes)
        }
        body.writeLengthPrefixed24(list.bytes)
        return TLSHandshakeMessage(type: .certificate, body: body.bytes)
    }

    func testParsesChainAndExtractsLeaf() throws {
        let message = certificateMessage(entries: [leaf, intermediate])
        let entries = try TLSCertificateMessage.parse(message)
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].der, leaf)
        XCTAssertEqual(entries[1].der, intermediate)
        XCTAssertEqual(try TLSCertificateMessage.leafDER(from: message), leaf)
    }

    func testEmptyChainIsRejected() {
        let message = certificateMessage(entries: [])
        XCTAssertThrowsError(try TLSCertificateMessage.parse(message)) { error in
            XCTAssertEqual(error as? TLSError, .emptyCertificateChain)
        }
    }

    func testWrongMessageTypeIsRejected() {
        let message = TLSHandshakeMessage(type: .finished, body: [])
        XCTAssertThrowsError(try TLSCertificateMessage.parse(message))
    }

    func testTruncatedCertificateBodyIsRejected() {
        let message = TLSHandshakeMessage(type: .certificate, body: [0x00, 0x00, 0x05, 0x01])
        XCTAssertThrowsError(try TLSCertificateMessage.parse(message))
    }

    func testMD5FingerprintOfEmptyDataMatchesKnownVector() {
        XCTAssertEqual(
            CertificateFingerprint.md5(of: []),
            "d41d8cd98f00b204e9800998ecf8427e"
        )
    }

    func testFingerprintNormalizationAcceptsCommonFormats() {
        XCTAssertEqual(
            CertificateFingerprint.normalized("AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"),
            "abcdef0123456789abcdef0123456789"
        )
        XCTAssertEqual(
            CertificateFingerprint.normalized("abcdef0123456789abcdef0123456789"),
            "abcdef0123456789abcdef0123456789"
        )
    }

    func testPinnerAcceptsMatchingFingerprint() throws {
        let fingerprint = CertificateFingerprint.md5(of: leaf)
        let pinner = CertificatePinner(expectedFingerprint: fingerprint.uppercased())
        XCTAssertNoThrow(try pinner.verify(leafDER: leaf))
    }

    func testPinnerRejectsMismatch() {
        let pinner = CertificatePinner(expectedFingerprint: String(repeating: "0", count: 32))
        XCTAssertThrowsError(try pinner.verify(leafDER: leaf)) { error in
            guard case let TLSError.certificatePinMismatch(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, String(repeating: "0", count: 32))
            XCTAssertEqual(actual, CertificateFingerprint.md5(of: leaf))
        }
    }

    func testPinnerSkipsCheckWhenFingerprintIsNil() {
        let pinner = CertificatePinner(expectedFingerprint: nil)
        XCTAssertNoThrow(try pinner.verify(leafDER: leaf))
    }

    func testPinnerRejectsMalformedFingerprint() {
        let pinner = CertificatePinner(expectedFingerprint: "abc")
        XCTAssertThrowsError(try pinner.verify(leafDER: leaf))
    }
}
