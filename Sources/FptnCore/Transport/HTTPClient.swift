import Foundation

/// Blocking HTTP/1.1 client used for the FPTN API and the WebSocket upgrade.
public enum HTTPClient {
    public static let defaultMaximumResponseSize = 16 * 1024 * 1024

    /// Performs a request and reads a complete response. The request should
    /// include `Connection: close` when the server does not send a
    /// `Content-Length` header.
    public static func perform(
        _ request: HTTPRequest,
        over connection: HTTPConnection,
        maximumResponseSize: Int = defaultMaximumResponseSize
    ) throws -> HTTPResponse {
        let parser = HTTPResponseParser()
        try connection.write(request.encoded())
        var received = 0
        while true {
            if let response = try parser.nextResponse() {
                return response
            }
            do {
                let chunk = try connection.read(maxBytes: 16_384)
                if chunk.isEmpty {
                    parser.markEndOfStream()
                } else {
                    received += chunk.count
                    guard received <= maximumResponseSize else {
                        throw HTTPError.responseTooLarge(received)
                    }
                    parser.append(chunk)
                }
            } catch TransportError.closed {
                parser.markEndOfStream()
            }
            if parser.isEndOfStream {
                if let response = try parser.nextResponse() {
                    return response
                }
                throw HTTPError.unexpectedEndOfStream
            }
        }
    }

    /// Sends an upgrade request and returns the response plus any bytes that
    /// arrived after the response head (the first WebSocket frames).
    public static func upgrade(
        _ request: HTTPRequest,
        over connection: HTTPConnection,
        maximumResponseSize: Int = defaultMaximumResponseSize
    ) throws -> (response: HTTPResponse, leftover: [UInt8]) {
        let parser = HTTPResponseParser()
        try connection.write(request.encoded())
        var received = 0
        while true {
            if let response = try parser.nextResponse() {
                return (response, parser.takeBufferedBytes())
            }
            do {
                let chunk = try connection.read(maxBytes: 16_384)
                if chunk.isEmpty {
                    parser.markEndOfStream()
                } else {
                    received += chunk.count
                    guard received <= maximumResponseSize else {
                        throw HTTPError.responseTooLarge(received)
                    }
                    parser.append(chunk)
                }
            } catch TransportError.closed {
                parser.markEndOfStream()
            }
            if parser.isEndOfStream {
                if let response = try parser.nextResponse() {
                    return (response, parser.takeBufferedBytes())
                }
                throw HTTPError.unexpectedEndOfStream
            }
        }
    }
}
