import XCTest

@testable import FptnCore

final class TLSClientHelloTests: XCTestCase {
    private let random = Array(repeating: UInt8(0x11), count: 32)
    private let sessionID = Array(repeating: UInt8(0x22), count: 32)
    private let keyShare = Array(repeating: UInt8(0x33), count: 32)

    private func makeBuilder(
        serverName: String = "vpn.example.com",
        suites: [TLSCipherSuite] = [.aes128GcmSha256, .chacha20Poly1305Sha256]
    ) -> TLSClientHelloBuilder {
        TLSClientHelloBuilder(
            serverName: serverName,
            random: random,
            sessionID: sessionID,
            keyShare: keyShare,
            cipherSuites: suites
        )
    }

    func testBuilderEncodesExpectedFields() throws {
        let message = try makeBuilder().build()
        XCTAssertEqual(message.type, .clientHello)
        let hello = try TLSClientHello.parse(message)
        XCTAssertEqual(hello.legacyVersion, 0x0303)
        XCTAssertEqual(hello.random, random)
        XCTAssertEqual(hello.sessionID, sessionID)
        XCTAssertEqual(hello.cipherSuites, [0x1301, 0x1303])
        XCTAssertEqual(hello.compressionMethods, [0])
    }

    func testBuilderIncludesSNI() throws {
        let hello = try TLSClientHello.parse(try makeBuilder(serverName: "example.org").build())
        let sni = try XCTUnwrap(hello.extensions[TLSExtensionType.serverName])
        XCTAssertEqual(Array(sni.prefix(2)), [0x00, 0x0e])
        XCTAssertEqual(Array(sni[2..<5]), [0x00, 0x00, 0x0b])
        XCTAssertEqual(Array(sni.dropFirst(5)), Array("example.org".utf8))
    }

    func testBuilderAdvertisesTLS13AndKeyShare() throws {
        let hello = try TLSClientHello.parse(try makeBuilder().build())
        XCTAssertEqual(hello.extensions[TLSExtensionType.supportedVersions], [2, 0x03, 0x04])
        let keyShare = try XCTUnwrap(hello.extensions[TLSExtensionType.keyShare])
        XCTAssertEqual(Array(keyShare.prefix(4)), [0x00, 0x24, 0x00, 0x1d])
        XCTAssertEqual(Array(keyShare.suffix(32)), self.keyShare)
        XCTAssertEqual(hello.extensions[TLSExtensionType.sessionTicket], [])
    }

    func testBuilderStampsFPTNKeyIntoLastFourSessionIDBytes() throws {
        let stamped = try FPTNSessionKey.realSessionID(
            random: sessionID,
            timestamp: 1_700_000_000
        )
        var builder = makeBuilder()
        builder.sessionID = stamped
        let hello = try TLSClientHello.parse(try builder.build())
        let expected = FPTNSessionKey.generate(timestamp: 1_700_000_000)
        XCTAssertEqual(Array(hello.sessionID[28..<32]), expected)
        XCTAssertEqual(Array(hello.sessionID[0..<28]), Array(sessionID[0..<28]))
    }

    func testBuilderRejectsInvalidRandomLength() {
        var builder = makeBuilder()
        builder.random = Array(repeating: 0, count: 31)
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error as? TLSError, .invalidConfiguration("ClientHello random must be 32 bytes"))
        }
    }

    func testBuilderRejectsOversizedSessionID() {
        var builder = makeBuilder()
        builder.sessionID = Array(repeating: 0, count: 33)
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error as? TLSError, .invalidConfiguration("ClientHello session id must be at most 32 bytes"))
        }
    }

    func testBuilderRejectsWrongKeyShareLength() {
        var builder = makeBuilder()
        builder.keyShare = [0x01]
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error as? TLSError, .invalidConfiguration("x25519 key share must be 32 bytes"))
        }
    }

    func testBuilderRejectsEmptyServerName() {
        var builder = makeBuilder()
        builder.serverName = ""
        XCTAssertThrowsError(try builder.build())
    }

    func testBuilderRejectsEmptyCipherSuiteList() {
        var builder = makeBuilder()
        builder.cipherSuites = []
        XCTAssertThrowsError(try builder.build())
    }

    func testEncodedHelloRoundTrips() throws {
        let hello = try TLSClientHello.parse(try makeBuilder().build())
        let reparsed = try TLSClientHello.parse(
            TLSHandshakeMessage(type: .clientHello, body: Array(hello.encoded().dropFirst(4)))
        )
        XCTAssertEqual(reparsed, hello)
    }

    func testParserRejectsWrongHandshakeType() {
        let message = TLSHandshakeMessage(type: .serverHello, body: [])
        XCTAssertThrowsError(try TLSClientHello.parse(message))
    }

    func testParserRejectsOddCipherSuiteLength() {
        var body: [UInt8] = [0x03, 0x03]
        body.append(contentsOf: random)
        body.append(0)
        body.append(contentsOf: [0x00, 0x03, 0x13])
        body.append(contentsOf: [1, 0, 0x00, 0x00])
        let message = TLSHandshakeMessage(type: .clientHello, body: body)
        XCTAssertThrowsError(try TLSClientHello.parse(message))
    }
}
