import Foundation

/// Encrypts and decrypts TLS 1.3 records for one direction of a connection.
public final class TLSRecordProtector {
    public static let maximumPlaintextLength = 16_384

    public private(set) var suite: TLSCipherSuite
    public private(set) var sequence: UInt64 = 0
    private var key: [UInt8]
    private var iv: [UInt8]

    public init(suite: TLSCipherSuite, key: [UInt8], iv: [UInt8]) throws {
        guard key.count == suite.keyLength else { throw TLSCipherSuiteError.invalidKeyLength }
        guard iv.count == 12 else { throw TLSCipherSuiteError.invalidNonceLength }
        self.suite = suite
        self.key = key
        self.iv = iv
    }

    public func reset(suite: TLSCipherSuite, key: [UInt8], iv: [UInt8]) throws {
        guard key.count == suite.keyLength else { throw TLSCipherSuiteError.invalidKeyLength }
        guard iv.count == 12 else { throw TLSCipherSuiteError.invalidNonceLength }
        self.suite = suite
        self.key = key
        self.iv = iv
        self.sequence = 0
    }

    public func seal(contentType: TLSContentType, plaintext: [UInt8]) throws -> [UInt8] {
        guard plaintext.count <= Self.maximumPlaintextLength else {
            throw TLSError.recordTooLarge(plaintext.count)
        }
        var inner = plaintext
        inner.append(contentType.rawValue)
        let cipherLength = inner.count + suite.tagLength
        let header: [UInt8] = [
            TLSRecordType.applicationData.rawValue,
            0x03, 0x03,
            UInt8((cipherLength >> 8) & 0xff),
            UInt8(cipherLength & 0xff)
        ]
        let nonce = try makeNonce()
        let ciphertext = try suite.seal(
            key: key,
            nonce: nonce,
            plaintext: inner,
            additionalData: header
        )
        try advanceSequence()
        return header + ciphertext
    }

    public func open(
        fragment: [UInt8],
        type: TLSRecordType = .applicationData,
        version: UInt16 = 0x0303
    ) throws -> (contentType: TLSContentType, plaintext: [UInt8]) {
        guard type == .applicationData else {
            throw TLSError.unexpectedMessage("encrypted record expected")
        }
        guard fragment.count >= suite.tagLength + 1 else {
            throw TLSError.truncatedRecord
        }
        let header: [UInt8] = [
            type.rawValue,
            UInt8((version >> 8) & 0xff),
            UInt8(version & 0xff),
            UInt8((fragment.count >> 8) & 0xff),
            UInt8(fragment.count & 0xff)
        ]
        let nonce = try makeNonce()
        let inner = try suite.open(
            key: key,
            nonce: nonce,
            ciphertext: fragment,
            additionalData: header
        )
        var end = inner.count
        while end > 0 && inner[end - 1] == 0 { end -= 1 }
        guard end > 0 else { throw TLSError.unexpectedMessage("empty inner plaintext") }
        let rawType = inner[end - 1]
        guard let contentType = TLSContentType(rawValue: rawType) else {
            throw TLSError.unexpectedMessage("invalid inner content type \(rawType)")
        }
        try advanceSequence()
        return (contentType, Array(inner[0..<(end - 1)]))
    }

    private func makeNonce() throws -> [UInt8] {
        var nonce = iv
        var value = sequence
        for index in stride(from: 11, through: 4, by: -1) {
            nonce[index] ^= UInt8(value & 0xff)
            value >>= 8
        }
        return nonce
    }

    private func advanceSequence() throws {
        guard sequence < UInt64.max else { throw TLSError.sequenceNumberOverflow }
        sequence += 1
    }
}

public enum TLSContentType: UInt8, Sendable {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
}
