import XCTest

@testable import FptnCore

final class TLSServerHelloTests: XCTestCase {
    private let sessionID = Array(repeating: UInt8(0x22), count: 32)
    private let serverKey = Array(repeating: UInt8(0x44), count: 32)

    private func makeHello(
        random: [UInt8] = Array(repeating: UInt8(0x55), count: 32),
        extensions: [UInt16: [UInt8]]? = nil
    ) -> TLSServerHello {
        TLSServerHello(
            legacyVersion: 0x0303,
            random: random,
            sessionID: sessionID,
            cipherSuite: TLSCipherSuite.aes128GcmSha256.rawValue,
            compressionMethod: 0,
            extensions: extensions ?? [
                TLSExtensionType.supportedVersions: [0x03, 0x04],
                TLSExtensionType.keyShare: [0x00, 0x1d, 0x00, 0x20] + serverKey
            ]
        )
    }

    func testParseExtractsFieldsAndExtensions() throws {
        let message = TLSHandshakeMessage(
            type: .serverHello,
            body: Array(makeHello().encoded().dropFirst(4))
        )
        let hello = try TLSServerHello.parse(message)
        XCTAssertEqual(hello.legacyVersion, 0x0303)
        XCTAssertEqual(hello.sessionID, sessionID)
        XCTAssertEqual(hello.cipherSuite, 0x1301)
        XCTAssertEqual(hello.compressionMethod, 0)
        XCTAssertEqual(hello.selectedVersion, 0x0304)
        XCTAssertEqual(hello.keyShare?.group, 0x001d)
        XCTAssertEqual(hello.keyShare?.key, serverKey)
        XCTAssertFalse(hello.isHelloRetryRequest)
    }

    func testHelloRetryRequestIsDetected() throws {
        let hello = makeHello(random: TLSServerHello.helloRetryRequestRandom)
        XCTAssertTrue(hello.isHelloRetryRequest)
        let parsed = try TLSServerHello.parse(
            TLSHandshakeMessage(type: .serverHello, body: Array(hello.encoded().dropFirst(4)))
        )
        XCTAssertTrue(parsed.isHelloRetryRequest)
    }

    func testMissingSupportedVersionsReturnsNil() {
        let hello = makeHello(extensions: [:])
        XCTAssertNil(hello.selectedVersion)
    }

    func testMalformedKeyShareReturnsNil() {
        let hello = makeHello(extensions: [
            TLSExtensionType.keyShare: [0x00, 0x1d, 0x00, 0x20, 0x01]
        ])
        XCTAssertNil(hello.keyShare)
    }

    func testEncodedRoundTrip() throws {
        let hello = makeHello()
        let reparsed = try TLSServerHello.parse(
            TLSHandshakeMessage(type: .serverHello, body: Array(hello.encoded().dropFirst(4)))
        )
        XCTAssertEqual(reparsed, hello)
    }

    func testParserRejectsWrongHandshakeType() {
        XCTAssertThrowsError(try TLSServerHello.parse(
            TLSHandshakeMessage(type: .clientHello, body: [])
        ))
    }

    func testParserRejectsTruncatedBody() {
        let message = TLSHandshakeMessage(type: .serverHello, body: [0x03, 0x03, 0x00])
        XCTAssertThrowsError(try TLSServerHello.parse(message))
    }
}
