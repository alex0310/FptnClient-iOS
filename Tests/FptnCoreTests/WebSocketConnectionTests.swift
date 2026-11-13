import XCTest

@testable import FptnCore

final class WebSocketConnectionTests: XCTestCase {
    private let key = "dGhlIHNhbXBsZSBub25jZQ=="

    private func upgradeResponse() -> [UInt8] {
        let text = "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: \(WebSocketHandshake.expectedAccept(for: key))\r\n"
            + "\r\n"
        return Array(text.utf8)
    }

    func testRFC6455AcceptVector() {
        XCTAssertEqual(
            WebSocketHandshake.expectedAccept(for: key),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
    }

    func testUpgradeRequestContainsRequiredHeaders() {
        let request = WebSocketHandshake.makeRequest(
            hostHeader: "vpn.example.com:443",
            token: "jwt",
            clientAgent: "FptnClient(iOS/1.0.0)",
            key: key,
            sessionID: "session",
            sendDurationMilliseconds: 60_000,
            ttlMilliseconds: 600_000
        )
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.target, "/api/v1/fptn")
        XCTAssertEqual(request.header("Host"), "vpn.example.com:443")
        XCTAssertEqual(request.header("Upgrade"), "websocket")
        XCTAssertEqual(request.header("Connection"), "Upgrade")
        XCTAssertEqual(request.header("Sec-WebSocket-Key"), key)
        XCTAssertEqual(request.header("Sec-WebSocket-Version"), "13")
        XCTAssertEqual(request.header("Authorization"), "Bearer jwt")
        XCTAssertEqual(request.header("X-Serializer"), "yaff")
        XCTAssertEqual(request.header("Client-Agent"), "FptnClient(iOS/1.0.0)")
        XCTAssertEqual(request.header("SessionID"), "session")
        XCTAssertEqual(request.header("X-Send-Duration"), "60000")
        XCTAssertEqual(request.header("X-Ttl"), "600000")
        XCTAssertNil(request.header("Accept-Encoding"))
    }

    func testOptionalHeadersAreOmittedWhenEmpty() {
        let request = WebSocketHandshake.makeRequest(
            hostHeader: "h:1",
            token: "t",
            clientAgent: "a",
            key: key,
            sessionID: "",
            sendDurationMilliseconds: 0,
            ttlMilliseconds: 0
        )
        XCTAssertNil(request.header("SessionID"))
        XCTAssertNil(request.header("X-Send-Duration"))
        XCTAssertNil(request.header("X-Ttl"))
    }

    func testValidateRejectsWrongStatus() {
        let response = HTTPResponse(
            statusCode: 200,
            reason: "OK",
            headers: [],
            body: []
        )
        XCTAssertThrowsError(try WebSocketHandshake.validate(response: response, key: key)) { error in
            XCTAssertEqual(error as? WebSocketHandshakeError, .unexpectedStatus(200))
        }
    }

    func testValidateRejectsMissingUpgrade() {
        let response = HTTPResponse(
            statusCode: 101,
            reason: "Switching Protocols",
            headers: [HTTPHeader(name: "Sec-WebSocket-Accept", value: WebSocketHandshake.expectedAccept(for: key))],
            body: []
        )
        XCTAssertThrowsError(try WebSocketHandshake.validate(response: response, key: key)) { error in
            XCTAssertEqual(error as? WebSocketHandshakeError, .missingUpgradeHeader)
        }
    }

    func testValidateRejectsWrongAccept() {
        let response = HTTPResponse(
            statusCode: 101,
            reason: "Switching Protocols",
            headers: [
                HTTPHeader(name: "Upgrade", value: "websocket"),
                HTTPHeader(name: "Sec-WebSocket-Accept", value: "wrong")
            ],
            body: []
        )
        XCTAssertThrowsError(try WebSocketHandshake.validate(response: response, key: key)) { error in
            XCTAssertEqual(error as? WebSocketHandshakeError, .invalidAcceptHeader)
        }
    }

    func testUpgradePreservesFramesSentWithResponse() throws {
        let frame: [UInt8] = [0x82, 0x03, 1, 2, 3]
        let connection = MockHTTPConnection(response: upgradeResponse() + frame)
        let ws = try WebSocketHandshake.upgrade(
            connection: connection,
            hostHeader: "vpn.example.com:443",
            token: "jwt",
            clientAgent: "agent",
            key: key
        )
        XCTAssertEqual(try ws.receiveFrame(), .binary([1, 2, 3]))
    }

    func testSendBinaryMasksPayload() throws {
        let connection = MockHTTPConnection(response: [])
        let ws = WebSocketConnection(connection: connection)
        try ws.sendBinary([1, 2, 3])
        let bytes = connection.written
        XCTAssertEqual(bytes[0], 0x82)
        XCTAssertEqual(bytes[1], 0x80 | 3)
        let mask = Array(bytes[2..<6])
        let payload = (0..<3).map { bytes[6 + $0] ^ mask[$0 & 3] }
        XCTAssertEqual(payload, [1, 2, 3])
    }

    func testReceiveBinaryFromLeftover() throws {
        let ws = WebSocketConnection(
            connection: MockHTTPConnection(response: []),
            leftover: [0x82, 0x03, 9, 8, 7]
        )
        XCTAssertEqual(try ws.receiveFrame(), .binary([9, 8, 7]))
    }

    func testReceiveFragmentedBinary() throws {
        let ws = WebSocketConnection(
            connection: MockHTTPConnection(response: []),
            leftover: [0x02, 0x01, 1, 0x80, 0x01, 2]
        )
        XCTAssertEqual(try ws.receiveFrame(), .binary([1, 2]))
    }

    func testReceivePingAndClose() throws {
        let ping = WebSocketConnection(
            connection: MockHTTPConnection(response: []),
            leftover: [0x89, 0x02, 0xaa, 0xbb]
        )
        XCTAssertEqual(try ping.receiveFrame(), .ping([0xaa, 0xbb]))

        let close = WebSocketConnection(
            connection: MockHTTPConnection(response: []),
            leftover: [0x88, 0x02, 0x03, 0xe8]
        )
        XCTAssertEqual(try close.receiveFrame(), .close(code: 1000, reason: ""))
    }

    func testReceiveReadsFromUnderlyingConnection() throws {
        let ws = WebSocketConnection(
            connection: MockHTTPConnection(response: [0x82, 0x01, 0x2a], chunkSize: 2)
        )
        XCTAssertEqual(try ws.receiveFrame(), .binary([0x2a]))
    }

    func testReceiveClosedConnectionThrows() {
        let ws = WebSocketConnection(connection: MockHTTPConnection(response: []))
        XCTAssertThrowsError(try ws.receiveFrame()) { error in
            XCTAssertEqual(error as? TransportError, .closed)
        }
    }

    func testSendControlFrames() throws {
        let connection = MockHTTPConnection(response: [])
        let ws = WebSocketConnection(connection: connection)
        try ws.sendPing([1])
        try ws.sendPong([2])
        try ws.sendClose(code: 1000, reason: "bye")
        XCTAssertEqual(connection.written[0], 0x89)
        XCTAssertEqual(connection.written[7], 0x8a)
    }
}
