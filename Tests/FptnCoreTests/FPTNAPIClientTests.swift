import XCTest

@testable import FptnCore

final class FPTNAPIClientTests: XCTestCase {
    private let server = FPTNServer(
        name: "Test",
        host: "vpn.example.com",
        port: 443,
        md5Fingerprint: "abc",
        countryCode: "NL",
        isCensoredZone: false
    )

    private func response(
        _ status: Int,
        body: String
    ) -> HTTPResponse {
        HTTPResponse(
            statusCode: status,
            reason: "OK",
            headers: [HTTPHeader(name: "Content-Type", value: "application/json")],
            body: Array(body.utf8)
        )
    }

    func testLoginBuildsRequestAndReturnsToken() throws {
        var captured: HTTPRequest?
        let client = FPTNAPIClient { request, _ in
            captured = request
            return self.response(200, body: #"{"access_token":"jwt-token"}"#)
        }
        let token = try client.login(server: server, username: "alice", password: "secret")
        XCTAssertEqual(token, "jwt-token")

        let request = try XCTUnwrap(captured)
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.target, "/api/v1/login")
        XCTAssertEqual(request.header("Host"), "vpn.example.com:443")
        XCTAssertEqual(request.header("Client-Agent"), "FptnClient(iOS/1.0.0)")
        XCTAssertEqual(request.header("Content-Type"), "application/json")
        XCTAssertEqual(request.header("Connection"), "close")
        XCTAssertNil(request.header("Accept-Encoding"))
        let body = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: String]
        )
        XCTAssertEqual(body["username"], "alice")
        XCTAssertEqual(body["password"], "secret")
    }

    func testLoginEscapesJSONSpecialCharacters() throws {
        var captured: HTTPRequest?
        let client = FPTNAPIClient { request, _ in
            captured = request
            return self.response(200, body: #"{"access_token":"t"}"#)
        }
        _ = try client.login(server: server, username: "a\"b", password: "c\\d\n")
        let request = try XCTUnwrap(captured)
        let body = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: String]
        )
        XCTAssertEqual(body["username"], "a\"b")
        XCTAssertEqual(body["password"], "c\\d\n")
    }

    func testLoginRejectsEmptyCredentials() {
        let client = FPTNAPIClient { _, _ in self.response(200, body: "{}") }
        XCTAssertThrowsError(try client.login(server: server, username: "", password: "x")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .emptyUsername)
        }
        XCTAssertThrowsError(try client.login(server: server, username: "x", password: "")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .emptyPassword)
        }
    }

    func testLoginRejectsNon200() {
        let client = FPTNAPIClient { _, _ in self.response(401, body: "denied") }
        XCTAssertThrowsError(try client.login(server: server, username: "a", password: "b")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .httpStatus(401, "denied"))
        }
    }

    func testLoginRejectsInvalidJSON() {
        let client = FPTNAPIClient { _, _ in self.response(200, body: "not json") }
        XCTAssertThrowsError(try client.login(server: server, username: "a", password: "b")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .invalidJSON)
        }
    }

    func testLoginRejectsMissingToken() {
        let client = FPTNAPIClient { _, _ in self.response(200, body: #"{"x":1}"#) }
        XCTAssertThrowsError(try client.login(server: server, username: "a", password: "b")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .missingAccessToken)
        }
    }

    func testDNSBuildsAuthorizedRequest() throws {
        var captured: HTTPRequest?
        let client = FPTNAPIClient { request, _ in
            captured = request
            return self.response(
                200,
                body: #"{"dns":"8.8.8.8","dns_ipv6":"2001:4860:4860::8888"}"#
            )
        }
        let settings = try client.dns(server: server, token: "jwt")
        XCTAssertEqual(settings.dns, "8.8.8.8")
        XCTAssertEqual(settings.dnsIPv6, "2001:4860:4860::8888")

        let request = try XCTUnwrap(captured)
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.target, "/api/v1/dns")
        XCTAssertEqual(request.header("Authorization"), "Bearer jwt")
        XCTAssertEqual(request.header("Connection"), "close")
        XCTAssertTrue(request.body.isEmpty)
    }

    func testDNSAllowsMissingIPv6() throws {
        let client = FPTNAPIClient { _, _ in
            self.response(200, body: #"{"dns":"1.1.1.1"}"#)
        }
        let settings = try client.dns(server: server, token: "jwt")
        XCTAssertEqual(settings.dns, "1.1.1.1")
        XCTAssertNil(settings.dnsIPv6)
    }

    func testDNSRejectsMissingServer() {
        let client = FPTNAPIClient { _, _ in self.response(200, body: #"{"x":"y"}"#) }
        XCTAssertThrowsError(try client.dns(server: server, token: "jwt")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .missingDNS)
        }
    }

    func testDNSRejectsMalformedJSON() {
        let client = FPTNAPIClient { _, _ in self.response(200, body: "[]") }
        XCTAssertThrowsError(try client.dns(server: server, token: "jwt")) { error in
            XCTAssertEqual(error as? FPTNAPIError, .invalidJSON)
        }
    }
}
