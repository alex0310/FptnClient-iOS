import XCTest

@testable import FptnCore

final class HTTPMessageTests: XCTestCase {
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

    func testRequestEncodesStartLineHeadersAndBody() {
        let request = HTTPRequest(
            method: "POST",
            target: "/api/v1/login",
            headers: [
                HTTPHeader(name: "Host", value: "vpn.example.com"),
                HTTPHeader(name: "Content-Type", value: "application/json")
            ],
            body: Array("{}".utf8)
        )
        let text = String(decoding: request.encoded(), as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("POST /api/v1/login HTTP/1.1\r\n"))
        XCTAssertTrue(text.contains("Host: vpn.example.com\r\n"))
        XCTAssertTrue(text.contains("Content-Type: application/json\r\n"))
        XCTAssertTrue(text.contains("Content-Length: 2\r\n"))
        XCTAssertTrue(text.hasSuffix("\r\n\r\n{}"))
    }

    func testRequestDoesNotDuplicateContentLength() {
        let request = HTTPRequest(
            method: "POST",
            target: "/",
            headers: [HTTPHeader(name: "content-length", value: "2")],
            body: [1, 2]
        )
        let text = String(decoding: request.encoded(), as: UTF8.self)
        XCTAssertEqual(text.lowercased().components(separatedBy: "content-length").count - 1, 1)
    }

    func testResponseWithContentLength() throws {
        let parser = HTTPResponseParser()
        parser.append(response(
            200,
            headers: [HTTPHeader(name: "Content-Length", value: "5")],
            body: "hello"
        ))
        let parsed = try XCTUnwrap(try parser.nextResponse())
        XCTAssertEqual(parsed.statusCode, 200)
        XCTAssertEqual(parsed.reason, "OK")
        XCTAssertEqual(parsed.body, Array("hello".utf8))
        XCTAssertEqual(parsed.text, "hello")
    }

    func testHeaderLookupIsCaseInsensitive() throws {
        let parser = HTTPResponseParser()
        parser.append(response(
            200,
            headers: [
                HTTPHeader(name: "X-Test", value: "yes"),
                HTTPHeader(name: "Content-Length", value: "0")
            ],
            body: ""
        ))
        let parsed = try XCTUnwrap(try parser.nextResponse())
        XCTAssertEqual(parsed.header("x-test"), "yes")
        XCTAssertNil(parsed.header("missing"))
    }

    func testFragmentedResponseIsBuffered() throws {
        let parser = HTTPResponseParser()
        let full = response(
            200,
            headers: [HTTPHeader(name: "Content-Length", value: "11")],
            body: "hello world"
        )
        for byte in full.dropLast(3) {
            parser.append([byte])
        }
        XCTAssertNil(try parser.nextResponse())
        parser.append(Array(full.suffix(3)))
        XCTAssertEqual(try parser.nextResponse()?.text, "hello world")
    }

    func testChunkedResponse() throws {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        let parser = HTTPResponseParser()
        parser.append(Array(raw.utf8))
        let parsed = try XCTUnwrap(try parser.nextResponse())
        XCTAssertEqual(parsed.text, "hello world")
    }

    func testChunkedResponseWithExtensionAndTrailer() throws {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "5;name=value\r\nhello\r\n0\r\nX-Trailer: yes\r\n\r\n"
        let parser = HTTPResponseParser()
        parser.append(Array(raw.utf8))
        XCTAssertEqual(try parser.nextResponse()?.text, "hello")
    }

    func testChunkedResponseFragmented() throws {
        let raw = Array(
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "5\r\nhello\r\n0\r\n\r\n").utf8
        )
        let parser = HTTPResponseParser()
        parser.append(Array(raw.prefix(10)))
        XCTAssertNil(try parser.nextResponse())
        parser.append(Array(raw.dropFirst(10)))
        XCTAssertEqual(try parser.nextResponse()?.text, "hello")
    }

    func testBodylessStatuses() throws {
        for status in [101, 204, 304] {
            let parser = HTTPResponseParser()
            parser.append(response(status))
            let parsed = try XCTUnwrap(try parser.nextResponse())
            XCTAssertEqual(parsed.statusCode, status)
            XCTAssertEqual(parsed.body, [])
        }
    }

    func testUpgradeResponseLeavesLeftoverBytes() throws {
        let parser = HTTPResponseParser()
        parser.append(response(101, headers: [
            HTTPHeader(name: "Upgrade", value: "websocket")
        ]) + [0x81, 0x00])
        let parsed = try XCTUnwrap(try parser.nextResponse())
        XCTAssertEqual(parsed.statusCode, 101)
        XCTAssertEqual(parser.bufferedByteCount, 2)
    }

    func testEndOfStreamDelimitedBody() throws {
        let parser = HTTPResponseParser()
        parser.append(response(200, body: "until close"))
        XCTAssertNil(try parser.nextResponse())
        parser.markEndOfStream()
        XCTAssertEqual(try parser.nextResponse()?.text, "until close")
    }

    func testMultipleResponsesAreParsedInOrder() throws {
        let parser = HTTPResponseParser()
        parser.append(
            response(200, headers: [HTTPHeader(name: "Content-Length", value: "1")], body: "a")
                + response(201, headers: [HTTPHeader(name: "Content-Length", value: "1")], body: "b")
        )
        XCTAssertEqual(try parser.nextResponse()?.body, [0x61])
        XCTAssertEqual(try parser.nextResponse()?.statusCode, 201)
        XCTAssertNil(try parser.nextResponse())
    }

    func testMalformedStatusLineIsRejected() {
        let parser = HTTPResponseParser()
        parser.append(Array("NOT HTTP\r\n\r\n".utf8))
        XCTAssertThrowsError(try parser.nextResponse()) { error in
            XCTAssertEqual(error as? HTTPError, .malformedStatusLine)
        }
    }

    func testMalformedHeaderIsRejected() {
        let parser = HTTPResponseParser()
        parser.append(Array("HTTP/1.1 200 OK\r\nBrokenHeader\r\n\r\n".utf8))
        XCTAssertThrowsError(try parser.nextResponse()) { error in
            XCTAssertEqual(error as? HTTPError, .malformedHeader)
        }
    }

    func testOversizedHeadersAreRejected() {
        let parser = HTTPResponseParser(maxHeaderSize: 8)
        parser.append(Array("HTTP/1.1 200 OK\r\nX: y\r\n\r\n".utf8))
        XCTAssertThrowsError(try parser.nextResponse())
    }

    func testInvalidChunkSizeIsRejected() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
        let parser = HTTPResponseParser()
        parser.append(Array(raw.utf8))
        XCTAssertThrowsError(try parser.nextResponse()) { error in
            XCTAssertEqual(error as? HTTPError, .malformedChunk)
        }
    }

    func testMissingContentLengthWaitsForEndOfStream() throws {
        let parser = HTTPResponseParser()
        parser.append(response(200, body: "body"))
        XCTAssertNil(try parser.nextResponse())
        parser.markEndOfStream()
        XCTAssertEqual(try parser.nextResponse()?.text, "body")
    }

    func testTruncatedContentLengthAtEndOfStreamThrows() {
        let parser = HTTPResponseParser()
        parser.append(response(200, headers: [HTTPHeader(name: "Content-Length", value: "10")], body: "short"))
        parser.markEndOfStream()
        XCTAssertThrowsError(try parser.nextResponse()) { error in
            XCTAssertEqual(error as? HTTPError, .unexpectedEndOfStream)
        }
    }

    func testBrowserHeadersDoNotAdvertiseCompression() {
        let headers = BrowserHeaders.make()
        XCTAssertNotNil(headers.first { $0.name == "User-Agent" })
        XCTAssertNil(headers.first { $0.name == "Accept-Encoding" })
    }
}
