import Foundation

public enum WebSocketHandshakeError: Error, Equatable, LocalizedError {
    case unexpectedStatus(Int)
    case missingUpgradeHeader
    case invalidAcceptHeader
    case missingSecWebSocketKey

    public var errorDescription: String? {
        switch self {
        case let .unexpectedStatus(status): return "WebSocket upgrade returned HTTP \(status)."
        case .missingUpgradeHeader: return "WebSocket upgrade response has no Upgrade header."
        case .invalidAcceptHeader: return "WebSocket upgrade response has an invalid Sec-WebSocket-Accept header."
        case .missingSecWebSocketKey: return "WebSocket upgrade request has no Sec-WebSocket-Key."
        }
    }
}

public enum WebSocketHandshake {
    public static let acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    public static let path = "/api/v1/fptn"

    /// RFC 6455 section 4.2.2 accept value.
    public static func expectedAccept(for key: String) -> String {
        Base64Codec.encode(Digests.sha1(Array((key + acceptGUID).utf8)))
    }

    public static func makeRequest(
        hostHeader: String,
        token: String,
        clientAgent: String,
        key: String,
        sessionID: String? = nil,
        sendDurationMilliseconds: Int? = nil,
        ttlMilliseconds: Int? = nil,
        extraHeaders: [HTTPHeader] = []
    ) -> HTTPRequest {
        var headers: [HTTPHeader] = [
            HTTPHeader(name: "Host", value: hostHeader),
            HTTPHeader(name: "Upgrade", value: "websocket"),
            HTTPHeader(name: "Connection", value: "Upgrade"),
            HTTPHeader(name: "Sec-WebSocket-Key", value: key),
            HTTPHeader(name: "Sec-WebSocket-Version", value: "13"),
            HTTPHeader(name: "Authorization", value: "Bearer \(token)"),
            HTTPHeader(name: "X-Serializer", value: "yaff"),
            HTTPHeader(name: "Client-Agent", value: clientAgent)
        ]
        if let sessionID, !sessionID.isEmpty {
            headers.append(HTTPHeader(name: "SessionID", value: sessionID))
        }
        if let sendDurationMilliseconds, sendDurationMilliseconds > 0 {
            headers.append(HTTPHeader(
                name: "X-Send-Duration",
                value: String(sendDurationMilliseconds)
            ))
        }
        if let ttlMilliseconds, ttlMilliseconds > 0 {
            headers.append(HTTPHeader(name: "X-Ttl", value: String(ttlMilliseconds)))
        }
        headers.append(contentsOf: BrowserHeaders.make())
        headers.append(contentsOf: extraHeaders)
        return HTTPRequest(method: "GET", target: path, headers: headers)
    }

    public static func validate(
        response: HTTPResponse,
        key: String
    ) throws {
        guard response.statusCode == 101 else {
            throw WebSocketHandshakeError.unexpectedStatus(response.statusCode)
        }
        guard let upgrade = response.header("Upgrade"),
              upgrade.lowercased().contains("websocket") else {
            throw WebSocketHandshakeError.missingUpgradeHeader
        }
        guard let accept = response.header("Sec-WebSocket-Accept"),
              accept == expectedAccept(for: key) else {
            throw WebSocketHandshakeError.invalidAcceptHeader
        }
    }

    /// Performs the upgrade and returns a frame-level connection. Any frames
    /// that arrived together with the `101` response are preserved.
    public static func upgrade(
        connection: HTTPConnection,
        hostHeader: String,
        token: String,
        clientAgent: String,
        key: String = Base64Codec.encode(SecureRandom.bytes(16)),
        sessionID: String? = nil,
        sendDurationMilliseconds: Int? = nil,
        ttlMilliseconds: Int? = nil
    ) throws -> WebSocketConnection {
        let request = makeRequest(
            hostHeader: hostHeader,
            token: token,
            clientAgent: clientAgent,
            key: key,
            sessionID: sessionID,
            sendDurationMilliseconds: sendDurationMilliseconds,
            ttlMilliseconds: ttlMilliseconds
        )
        let result = try HTTPClient.upgrade(request, over: connection)
        try validate(response: result.response, key: key)
        return WebSocketConnection(connection: connection, leftover: result.leftover)
    }
}

/// Frame-level WebSocket client. It intentionally does not implement automatic
/// ping handling; the relay decides whether to answer pings or use them as
/// liveness evidence.
public final class WebSocketConnection {
    public let connection: HTTPConnection
    private let decoder: WebSocketFrameDecoder

    public init(
        connection: HTTPConnection,
        leftover: [UInt8] = [],
        maxFrameSize: Int = 16 * 1024 * 1024
    ) {
        self.connection = connection
        self.decoder = WebSocketFrameDecoder(maxFrameSize: maxFrameSize)
        if !leftover.isEmpty {
            decoder.append(leftover)
        }
    }

    public func send(_ frame: WebSocketFrame) throws {
        try connection.write(WebSocketFrameEncoder.encode(frame))
    }

    public func sendBinary(_ payload: [UInt8]) throws {
        try send(.binary(payload))
    }

    public func sendText(_ text: String) throws {
        try send(.text(text))
    }

    public func sendPing(_ payload: [UInt8] = []) throws {
        try send(.ping(payload))
    }

    public func sendPong(_ payload: [UInt8] = []) throws {
        try send(.pong(payload))
    }

    public func sendClose(code: UInt16? = 1000, reason: String = "") throws {
        try send(.close(code: code, reason: reason))
    }

    /// Reads until a complete frame is available. Throws `TransportError.closed`
    /// when the peer closes the underlying connection.
    public func receiveFrame() throws -> WebSocketFrame {
        while true {
            if let frame = try decoder.nextFrame() {
                return frame
            }
            let chunk = try connection.read(maxBytes: 16_384)
            if chunk.isEmpty { throw TransportError.closed }
            decoder.append(chunk)
        }
    }

    public func close() {
        connection.close()
    }
}
