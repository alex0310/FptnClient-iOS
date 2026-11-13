import Foundation

/// Parses the TLS 1.3 Certificate message and extracts the leaf certificate.
public enum TLSCertificateMessage {
    public struct Entry: Equatable, Sendable {
        public let der: [UInt8]
        public let extensions: [UInt8]

        public init(der: [UInt8], extensions: [UInt8]) {
            self.der = der
            self.extensions = extensions
        }
    }

    public static func parse(_ message: TLSHandshakeMessage) throws -> [Entry] {
        guard message.type == .certificate else {
            throw TLSError.unexpectedMessage("Certificate expected")
        }
        var reader = ByteReader(message.body)
        _ = try reader.readLengthPrefixed8() // certificate_request_context
        let list = try reader.readLengthPrefixed24()
        var listReader = ByteReader(list)
        var entries: [Entry] = []
        while !listReader.isAtEnd {
            let der = try listReader.readLengthPrefixed24()
            let extensions = try listReader.readLengthPrefixed16()
            entries.append(Entry(der: der, extensions: extensions))
        }
        guard !entries.isEmpty else { throw TLSError.emptyCertificateChain }
        return entries
    }

    public static func leafDER(from message: TLSHandshakeMessage) throws -> [UInt8] {
        guard let first = try parse(message).first else { throw TLSError.emptyCertificateChain }
        return first.der
    }
}

public enum CertificateFingerprint {
    /// FPTN pins certificates by the lowercase MD5 fingerprint of the DER leaf.
    public static func md5(of der: [UInt8]) -> String {
        Hex.encode(Digests.md5(der))
    }

    public static func normalized(_ fingerprint: String) -> String {
        fingerprint
            .lowercased()
            .filter { $0.isHexDigit }
    }
}

public struct CertificatePinner: Sendable {
    public let expectedFingerprint: String?

    public init(expectedFingerprint: String?) {
        self.expectedFingerprint = expectedFingerprint
    }

    public func verify(leafDER: [UInt8]) throws {
        guard let expected = expectedFingerprint else { return }
        let normalizedExpected = CertificateFingerprint.normalized(expected)
        guard normalizedExpected.count == 32 else {
            throw TLSError.invalidConfiguration("certificate fingerprint must be 32 hex digits")
        }
        let actual = CertificateFingerprint.md5(of: leafDER)
        guard Digests.constantTimeEquals(Array(normalizedExpected.utf8), Array(actual.utf8)) else {
            throw TLSError.certificatePinMismatch(expected: normalizedExpected, actual: actual)
        }
    }
}
