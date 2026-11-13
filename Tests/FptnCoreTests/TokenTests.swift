import XCTest
@testable import FptnCore

final class TokenTests: XCTestCase {
    private let plainToken = """
        eyJ2ZXJzaW9uIjoxLCJzZXJ2aWNlX25hbWUiOiJGUFROIiwidXNlcm5hbWUiOiJhbGljZSIsInBhc3N3b3JkIjoiczNjcmV0Iiwic2VydmVycyI6W3sibmFtZSI6IkFtc3RlcmRhbSIsImhvc3QiOiJhbXMuZXhhbXBsZS5jb20iLCJwb3J0Ijo0NDMsIm1kNV9maW5nZXJwcmludCI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwiY291bnRyeV9jb2RlIjoiTkwifV0sImNlbnNvcmVkX3pvbmVfc2VydmVycyI6W3sibmFtZSI6IkNlbnNvcmVkIiwiaG9zdCI6ImMuZXhhbXBsZS5jb20iLCJwb3J0Ijo4NDQzLCJtZDVfZmluZ2VycHJpbnQiOiJmZmVlZGRjY2JiYWE5OTg4Nzc2NjU1NDQzMzIyMTEwMCIsImNvdW50cnlfY29kZSI6IkRFIn1dfQ==
        """

    // Produced by Node.js zlib.brotliCompressSync for the same JSON document.
    private let brotliToken = """
        G3EBYJwFdlvLvyEJzQkjr2gUa5E9KqdmzaV8xpdAsuqDcAeblLhZdLr66uiIfBy03kV8dOuuA2YFht9X8C1pC49BEOC3vMwCy4oxndsIECjE+w0vwagl5E7RADSHA4X2/4FWAWpmnSAeu4N+QtzyEtx0Rl74x2J7XrnZbASCoZrtcb6RmHGs+PO4dVWajWP1eAgpRfvqMbJ6VvctWHpACAQ5hQPr+e18ANmf4xZWJz5Tm0sVY8g5YkXO/dzuDFhrTJ5LuzPd7J2MIN3N1g0f
        """

    func testParsesPlainToken() throws {
        let token = try TokenParser.parse(plainToken)
        XCTAssertEqual(token.version, 1)
        XCTAssertEqual(token.serviceName, "FPTN")
        XCTAssertEqual(token.username, "alice")
        XCTAssertEqual(token.password, "s3cret")
        XCTAssertEqual(token.servers.count, 2)
        XCTAssertEqual(token.servers[0].name, "Amsterdam")
        XCTAssertEqual(token.servers[0].host, "ams.example.com")
        XCTAssertEqual(token.servers[0].port, 443)
        XCTAssertEqual(token.servers[0].md5Fingerprint, "0123456789abcdef0123456789abcdef")
        XCTAssertEqual(token.servers[0].countryCode, "NL")
        XCTAssertFalse(token.servers[0].isCensoredZone)
        XCTAssertEqual(token.servers[1].name, "Censored")
        XCTAssertTrue(token.servers[1].isCensoredZone)
    }

    func testParsesBrotliToken() throws {
        let token = try TokenParser.parse("fptnb:" + brotliToken)
        XCTAssertEqual(token.username, "alice")
        XCTAssertEqual(token.servers.count, 2)
    }

    func testStripsKnownPrefixesAndWhitespace() throws {
        let withPrefix = "fptn://" + plainToken
        XCTAssertEqual(try TokenParser.parse(withPrefix).username, "alice")
        XCTAssertEqual(try TokenParser.parse("fptn:" + plainToken).username, "alice")
        let folded = plainToken.enumerated().map { index, character in
            index.isMultiple(of: 30) ? "\n\(character)" : String(character)
        }.joined()
        XCTAssertEqual(try TokenParser.parse(folded).username, "alice")
    }

    func testAcceptsURLSafeBase64() throws {
        let standard = Base64Codec.encode(Array("{\"username\":\"u\",\"password\":\"p\",\"servers\":[{\"name\":\"n\",\"host\":\"h\",\"port\":443}]}".utf8))
        let urlSafe = standard.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let token = try TokenParser.parse(urlSafe)
        XCTAssertEqual(token.username, "u")
    }

    func testRejectsInvalidToken() {
        XCTAssertThrowsError(try TokenParser.parse("")) { error in
            XCTAssertEqual(error as? TokenError, .emptyToken)
        }
        XCTAssertThrowsError(try TokenParser.parse("!!!!")) { error in
            XCTAssertEqual(error as? TokenError, .invalidBase64)
        }
        XCTAssertThrowsError(try TokenParser.parse("Zm9v")) { error in
            XCTAssertEqual(error as? TokenError, .invalidJSON)
        }
    }

    func testTokenValidationRules() {
        func token(_ json: String) -> String {
            Base64Codec.encode(Array(json.utf8))
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"password":"p","servers":[{"name":"n","host":"h","port":1}]}"#))) {
            XCTAssertEqual($0 as? TokenError, .missingUsername)
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"username":"u","servers":[{"name":"n","host":"h","port":1}]}"#))) {
            XCTAssertEqual($0 as? TokenError, .missingPassword)
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"username":"u","password":"p"}"#))) {
            XCTAssertEqual($0 as? TokenError, .noServers)
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"username":"u","password":"p","servers":[{"name":"","host":"h","port":1}]}"#))) {
            XCTAssertEqual($0 as? TokenError, .invalidServerName(index: 0))
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"username":"u","password":"p","servers":[{"name":"n","host":"","port":1}]}"#))) {
            XCTAssertEqual($0 as? TokenError, .invalidServerHost(index: 0))
        }
        XCTAssertThrowsError(try TokenParser.parse(token(#"{"username":"u","password":"p","servers":[{"name":"n","host":"h","port":70000}]}"#))) {
            XCTAssertEqual($0 as? TokenError, .invalidServerPort(index: 0))
        }
    }

    func testInvalidBrotliPayload() {
        XCTAssertThrowsError(try TokenParser.parse("fptnb:Zm9v")) { error in
            XCTAssertEqual(error as? TokenError, .brotliDecompressionFailed)
        }
    }

    func testServerIdentityAndCountryCode() {
        let server = FPTNServer(
            name: "Test",
            host: "example.com",
            port: 443,
            md5Fingerprint: nil,
            countryCode: "nl",
            isCensoredZone: false
        )
        XCTAssertEqual(server.id, "example.com:443")
        XCTAssertEqual(server.displayCountryCode, "NL")
    }
}
