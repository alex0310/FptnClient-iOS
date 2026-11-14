import Foundation
import XCTest

@testable import FptnCore

/// Test-only X.509 material. `rsa-leaf-key.pem` is a throwaway key generated
/// for these tests; it is never used in production or shipped in the app.
enum CertificateFixtures {
    static func der(_ name: String) throws -> [UInt8] {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "der", subdirectory: "Fixtures"),
            "Missing fixture \(name).der"
        )
        return [UInt8](try Data(contentsOf: url))
    }

    static func pem(_ name: String) throws -> String {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"),
            "Missing fixture \(name).pem"
        )
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// The real RFC 8448 section 5 certificate, extracted from the embedded
    /// handshake fixture.
    static func rfc8448LeafDER() throws -> [UInt8] {
        let body = Array(RFC8448.certificate.dropFirst(4))
        let entries = try TLSCertificateMessage.parse(
            TLSHandshakeMessage(type: .certificate, body: body)
        )
        return try XCTUnwrap(entries.first?.der)
    }
}
