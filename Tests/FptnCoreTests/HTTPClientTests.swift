import XCTest

@testable import FptnCore

final class HTTPClientTests: XCTestCase {
    private func response(
        _ status: Int,
        headers: [HTTPHeader] = [],
        body: String = ""
    ) -> [UInt8] {
        var text = "HTTP/1.1 \(status) OK\r\n"
        for header in headers {
            text += "\(header.name): \(header.value)\r\n"
        }
        text += "\r\n"
        return Array(text.utf8) + Array(body.utf8)
    }

    private func request() -> HTTPRequest {
        HTTPRequest(
            method: "GET",
            target: "/api/v1/dns",
            headers: [HTTPHeader(name: "Host", value: "vpn.example.com")]
        )
    }

    func testPerformReadsContentLengthBody() throws {
        let connection = MockHTTPConnection(
            response: response(
                200,
                headers: [HTTPHeader(name: "Content-Length", value: "5")],
                body: "hello"
            ),
            chunkSize: 3
        )
        let result = try HTTPClient.perform(request(), over: connection)
        XCTAssertEqual(result.statusCode, 200)
        XCTAssertEqual(result.text, "hello")
        XCTAssertEqual(
            String(decoding: connection.written, as: UTF8.self),
            "GET /api/v1/dns HTTP/1.1\r\nHost: vpn.example.com\r\n\r\n"
        )
    }

    func testPerformReadsConnectionCloseBody() throws {
        let connection = MockHTTPConnection(
            response: response(200, body: "until close"),
            chunkSize: 2
        )
        XCTAssertEqual(
            try HTTPClient.perform(request(), over: connection).text,
            "until close"
        )
    }

    func testUpgradeReturnsLeftoverBytes() throws {
        let raw = response(
            101,
            headers: [HTTPHeader(name: "Upgrade", value: "websocket")]
        ) + [0x81, 0x00]
        let connection = MockHTTPConnection(response: raw)
        let result = try HTTPClient.upgrade(request(), over: connection)
        XCTAssertEqual(result.response.statusCode, 101)
        XCTAssertEqual(result.leftover, [0x81, 0x00])
    }

    func testTransportTimeoutPropagates() {
        let connection = FailingHTTPConnection(error: TransportError.timeout)
        XCTAssertThrowsError(try HTTPClient.perform(request(), over: connection)) { error in
            XCTAssertEqual(error as? TransportError, .timeout)
        }
    }

    func testOversizedResponseIsRejected() {
        let connection = MockHTTPConnection(
            response: response(
                200,
                headers: [HTTPHeader(name: "Content-Length", value: "100")],
                body: String(repeating: "a", count: 100)
            )
        )
        XCTAssertThrowsError(try HTTPClient.perform(
            request(),
            over: connection,
            maximumResponseSize: 10
        )) { error in
            guard case .responseTooLarge = error as? HTTPError else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testTruncatedResponseThrows() {
        let raw = Array("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".utf8)
        let connection = MockHTTPConnection(response: raw)
        XCTAssertThrowsError(try HTTPClient.perform(request(), over: connection)) { error in
            XCTAssertEqual(error as? HTTPError, .unexpectedEndOfStream)
        }
    }
}
