import XCTest

@testable import FptnCore

final class TLSConnectionTests: XCTestCase {
    private let timestamp: UInt32 = 1_700_000_000

    private var fingerprint: String {
        CertificateFingerprint.md5(of: SimulatedTLSServer.testCertificateDER)
    }

    private func makeConnection(
        mode: FPTNSecurityMode,
        transport: ScriptedTLSTransport,
        expectedFingerprint: String? = nil
    ) throws -> TLSConnection {
        try TLSConnection(
            transport: transport,
            configuration: TLSConnectionConfiguration(
                serverName: "vpn.example.com",
                expectedCertificateMD5: expectedFingerprint ?? fingerprint,
                securityMode: mode,
                handshakeTimeout: 2,
                readTimeout: 2,
                writeTimeout: 2,
                postHandshakeDelay: 0,
                realityDecoyTimeout: 1,
                realityQuietPeriod: 0.01,
                realityHandshakeDelay: 0
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: timestamp,
            sleeper: { _ in },
            timestampProvider: { self.timestamp }
        )
    }

    private func roundTrip(mode: FPTNSecurityMode) throws {
        let transport = ScriptedTLSTransport(mode: mode, timestamp: timestamp)
        let connection = try makeConnection(mode: mode, transport: transport)
        try connection.connect()
        XCTAssertTrue(connection.isConnected)
        XCTAssertTrue(connection.handshakeEvents.contains(.handshakeCompleted))

        let request = Array("hello server".utf8)
        try connection.write(request)
        XCTAssertEqual(transport.receivedApplicationData, request)

        let response = Array("hello client".utf8)
        try transport.queueServerApplicationData(response)
        XCTAssertEqual(try connection.read(maxBytes: 64), response)

        connection.close()
        XCTAssertTrue(transport.isClosed)
        XCTAssertEqual(transport.receivedAlert, [1, 0])
    }

    func testPlainHandshakeAndApplicationData() throws {
        try roundTrip(mode: .plain)
    }

    func testObfuscatedHandshakeAndApplicationData() throws {
        try roundTrip(mode: .obfuscated)
    }

    func testRealityHandshakeAndApplicationData() throws {
        try roundTrip(mode: .reality)
    }

    func testHandshakeSurvivesFragmentedServerFlight() throws {
        let transport = ScriptedTLSTransport(mode: .obfuscated, timestamp: timestamp)
        transport.readChunkSize = 1
        let connection = try makeConnection(mode: .obfuscated, transport: transport)
        try connection.connect()
        XCTAssertTrue(connection.isConnected)
        try connection.write([1, 2, 3])
        XCTAssertEqual(transport.receivedApplicationData, [1, 2, 3])
    }

    func testCertificatePinMismatchFailsConnect() throws {
        let transport = ScriptedTLSTransport(mode: .plain, timestamp: timestamp)
        let connection = try makeConnection(
            mode: .plain,
            transport: transport,
            expectedFingerprint: String(repeating: "0", count: 32)
        )
        XCTAssertThrowsError(try connection.connect()) { error in
            guard case TLSError.certificatePinMismatch = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
        XCTAssertFalse(connection.isConnected)
    }

    func testRealityModeFailsWhenDecoyDoesNotAnswer() throws {
        let transport = EmptyTransport()
        let connection = try TLSConnection(
            transport: transport,
            configuration: TLSConnectionConfiguration(
                serverName: "vpn.example.com",
                expectedCertificateMD5: fingerprint,
                securityMode: .reality,
                realityDecoyTimeout: 0.01,
                realityQuietPeriod: 0.001
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: timestamp,
            sleeper: { _ in },
            timestampProvider: { self.timestamp }
        )
        XCTAssertThrowsError(try connection.connect()) { error in
            XCTAssertEqual(error as? TLSConnectionError, .realityDecoyMissing)
        }
    }

    func testReadAndWriteBeforeConnectAreRejected() throws {
        let transport = ScriptedTLSTransport(mode: .plain, timestamp: timestamp)
        let connection = try makeConnection(mode: .plain, transport: transport)
        XCTAssertThrowsError(try connection.read(maxBytes: 1)) { error in
            XCTAssertEqual(error as? TLSConnectionError, .notConnected)
        }
        XCTAssertThrowsError(try connection.write([1])) { error in
            XCTAssertEqual(error as? TLSConnectionError, .notConnected)
        }
    }

    func testLargeApplicationDataIsSplitAndReassembled() throws {
        let transport = ScriptedTLSTransport(mode: .plain, timestamp: timestamp)
        let connection = try makeConnection(mode: .plain, transport: transport)
        try connection.connect()

        let payload = (0..<40_000).map { UInt8($0 & 0xff) }
        try connection.write(payload)
        XCTAssertEqual(transport.receivedApplicationData, payload)

        try transport.queueServerApplicationData(payload)
        var received: [UInt8] = []
        while received.count < payload.count {
            received.append(contentsOf: try connection.read(maxBytes: 97))
        }
        XCTAssertEqual(received, payload)
    }

    func testCloseIsIdempotent() throws {
        let transport = ScriptedTLSTransport(mode: .plain, timestamp: timestamp)
        let connection = try makeConnection(mode: .plain, transport: transport)
        try connection.connect()
        connection.close()
        connection.close()
        XCTAssertTrue(transport.isClosed)
    }
}

private final class EmptyTransport: ByteTransport {
    func read(maxBytes: Int) throws -> [UInt8] {
        throw TransportError.timeout
    }

    func write(_ bytes: [UInt8]) throws {}
    func close() {}
    func setReadTimeout(_ seconds: TimeInterval) throws {}
    func setWriteTimeout(_ seconds: TimeInterval) throws {}
}
