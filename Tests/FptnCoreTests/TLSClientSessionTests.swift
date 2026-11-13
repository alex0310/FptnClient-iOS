import XCTest

@testable import FptnCore

final class TLSClientSessionTests: XCTestCase {
    private struct Handshake {
        let client: TLSClientSession
        let server: SimulatedTLSServer
        let clientStep: TLSClientStep
    }

    private func makeClient(
        suites: [TLSCipherSuite] = TLSCipherSuite.allCases,
        fingerprint: String? = nil,
        serverName: String = "vpn.example.com"
    ) throws -> TLSClientSession {
        let expected = fingerprint ?? CertificateFingerprint.md5(
            of: SimulatedTLSServer.testCertificateDER
        )
        return try TLSClientSession(
            configuration: TLSClientConfiguration(
                serverName: serverName,
                cipherSuites: suites,
                expectedCertificateMD5: expected
            ),
            clientRandom: Array(repeating: 0x11, count: 32),
            sessionIDRandom: Array(repeating: 0x22, count: 32),
            timestamp: 1_700_000_000
        )
    }

    private func handshake(
        suites: [TLSCipherSuite] = TLSCipherSuite.allCases,
        serverSuite: TLSCipherSuite = .aes128GcmSha256,
        fingerprint: String? = nil,
        configure: (SimulatedTLSServer) -> Void = { _ in }
    ) throws -> Handshake {
        let client = try makeClient(suites: suites, fingerprint: fingerprint)
        let server = SimulatedTLSServer(suite: serverSuite)
        configure(server)
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        let step = try client.receive(flight)
        return Handshake(client: client, server: server, clientStep: step)
    }

    func testFullHandshakeAndBidirectionalApplicationData() throws {
        let result = try handshake()
        XCTAssertEqual(result.client.state, .connected)
        XCTAssertTrue(result.client.isConnected)
        XCTAssertEqual(result.client.negotiatedCipherSuite, .aes128GcmSha256)
        XCTAssertTrue(result.clientStep.events.contains(.handshakeCompleted))
        XCTAssertFalse(result.clientStep.output.isEmpty)
        XCTAssertEqual(result.server.clientSessionID, result.client.sessionID)

        try result.server.receiveClientFinished(result.clientStep.output)
        XCTAssertTrue(result.server.clientFinishedReceived)

        let request = Array("GET / HTTP/1.1\r\n\r\n".utf8)
        let ciphertext = try result.client.encryptApplicationData(request)
        XCTAssertEqual(try result.server.openApplicationData(ciphertext), request)

        let response = Array("HTTP/1.1 204 No Content\r\n\r\n".utf8)
        let serverCiphertext = try result.server.sealApplicationData(response)
        let step = try result.client.receive(serverCiphertext)
        XCTAssertEqual(step.events, [.applicationData(response)])
        XCTAssertTrue(step.output.isEmpty)
    }

    func testHandshakeSurvivesArbitraryFragmentation() throws {
        let client = try makeClient()
        let server = SimulatedTLSServer()
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)

        var output: [UInt8] = []
        var events: [TLSClientEvent] = []
        var offset = 0
        let sizes = [1, 2, 3, 5, 8, 13, 21, 34]
        var index = 0
        while offset < flight.count {
            let size = sizes[index % sizes.count]
            let end = min(offset + size, flight.count)
            let step = try client.receive(Array(flight[offset..<end]))
            output.append(contentsOf: step.output)
            events.append(contentsOf: step.events)
            offset = end
            index += 1
        }
        XCTAssertEqual(client.state, .connected)
        XCTAssertTrue(events.contains(.handshakeCompleted))
        try server.receiveClientFinished(output)
        XCTAssertTrue(server.clientFinishedReceived)
    }

    func testCertificatePinMismatchFailsHandshake() throws {
        let client = try makeClient(fingerprint: String(repeating: "0", count: 32))
        let server = SimulatedTLSServer()
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            guard case let TLSError.certificatePinMismatch(_, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(
                actual,
                CertificateFingerprint.md5(of: SimulatedTLSServer.testCertificateDER)
            )
        }
        XCTAssertEqual(client.state, .failed)
    }

    func testUnsupportedServerCipherSuiteIsRejected() throws {
        let client = try makeClient(suites: [.chacha20Poly1305Sha256])
        let server = SimulatedTLSServer(suite: .aes128GcmSha256)
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? TLSError, .unsupportedCipherSuite(0x1301))
        }
        XCTAssertEqual(client.state, .failed)
    }

    func testSessionIDMismatchIsRejected() throws {
        let client = try makeClient()
        let server = SimulatedTLSServer()
        server.sessionIDOverride = Array(repeating: 0x7f, count: 32)
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? TLSError, .sessionIDMismatch)
        }
    }

    func testCorruptedServerFinishedIsRejected() throws {
        let client = try makeClient()
        let server = SimulatedTLSServer()
        server.corruptServerFinished = true
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight)) { error in
            XCTAssertEqual(error as? TLSError, .serverFinishedMismatch)
        }
        XCTAssertEqual(client.state, .failed)
    }

    func testHelloRetryRequestIsRejected() throws {
        let client = try makeClient()
        let server = SimulatedTLSServer()
        server.sendHelloRetryRequest = true
        let start = try client.start()
        let flight = try server.accept(clientOutput: start.output)
        XCTAssertThrowsError(try client.receive(flight))
    }

    func testKeyUpdateRotatesBothDirections() throws {
        let result = try handshake()
        try result.server.receiveClientFinished(result.clientStep.output)

        let update = try result.server.sendKeyUpdate(requestUpdate: true)
        let response = try result.client.receive(update)
        XCTAssertFalse(response.output.isEmpty)
        try result.server.receiveClientKeyUpdate(response.output)

        let fromServer = Array("after update".utf8)
        let serverCiphertext = try result.server.sealApplicationData(fromServer)
        XCTAssertEqual(
            try result.client.receive(serverCiphertext).events,
            [.applicationData(fromServer)]
        )

        let fromClient = Array("client after update".utf8)
        let clientCiphertext = try result.client.encryptApplicationData(fromClient)
        XCTAssertEqual(try result.server.openApplicationData(clientCiphertext), fromClient)
    }

    func testCloseSendsCloseNotifyAlert() throws {
        let result = try handshake()
        try result.server.receiveClientFinished(result.clientStep.output)
        let alert = try result.client.close()
        let opened = try result.server.openClientRecord(alert)
        XCTAssertEqual(opened.contentType, .alert)
        XCTAssertEqual(opened.plaintext, [1, 0])
        XCTAssertEqual(result.client.state, .closed)
        XCTAssertThrowsError(try result.client.receive([]))
    }

    func testLargeApplicationDataIsSplitIntoRecords() throws {
        let result = try handshake()
        try result.server.receiveClientFinished(result.clientStep.output)
        let payload = (0..<40_000).map { UInt8($0 & 0xff) }
        let ciphertext = try result.client.encryptApplicationData(payload)
        XCTAssertGreaterThan(ciphertext.count, payload.count)
        XCTAssertEqual(try result.server.openApplicationData(ciphertext), payload)
    }

    func testApplicationDataBeforeHandshakeIsRejected() throws {
        let client = try makeClient()
        XCTAssertThrowsError(try client.encryptApplicationData([1, 2, 3]))
        XCTAssertThrowsError(try client.receive([]))
    }

    func testStartTwiceIsRejected() throws {
        let client = try makeClient()
        _ = try client.start()
        XCTAssertThrowsError(try client.start())
    }
}
