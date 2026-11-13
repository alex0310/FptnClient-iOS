import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum TLSCipherSuiteError: Error, Equatable, LocalizedError {
    case unsupportedSuite(UInt16)
    case invalidKeyLength
    case invalidNonceLength
    case authenticationFailed

    public var errorDescription: String? {
        switch self {
        case let .unsupportedSuite(value): return String(format: "Unsupported TLS cipher suite 0x%04x.", value)
        case .invalidKeyLength: return "Invalid TLS traffic key length."
        case .invalidNonceLength: return "Invalid TLS nonce length."
        case .authenticationFailed: return "TLS record authentication failed."
        }
    }
}

public enum TLSCipherSuite: UInt16, CaseIterable, Sendable {
    case aes128GcmSha256 = 0x1301
    case aes256GcmSha384 = 0x1302
    case chacha20Poly1305Sha256 = 0x1303

    public var hash: TLSHash {
        self == .aes256GcmSha384 ? .sha384 : .sha256
    }

    public var keyLength: Int {
        self == .aes128GcmSha256 ? 16 : 32
    }

    public var tagLength: Int { 16 }

    public func seal(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        additionalData: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == keyLength else { throw TLSCipherSuiteError.invalidKeyLength }
        guard nonce.count == 12 else { throw TLSCipherSuiteError.invalidNonceLength }
        let symmetricKey = SymmetricKey(data: Data(key))
        do {
            switch self {
            case .aes128GcmSha256, .aes256GcmSha384:
                let box = try AES.GCM.seal(
                    Data(plaintext),
                    using: symmetricKey,
                    nonce: AES.GCM.Nonce(data: Data(nonce)),
                    authenticating: Data(additionalData)
                )
                return Array(box.ciphertext) + Array(box.tag)
            case .chacha20Poly1305Sha256:
                let box = try ChaChaPoly.seal(
                    Data(plaintext),
                    using: symmetricKey,
                    nonce: ChaChaPoly.Nonce(data: Data(nonce)),
                    authenticating: Data(additionalData)
                )
                return Array(box.ciphertext) + Array(box.tag)
            }
        } catch {
            throw TLSCipherSuiteError.authenticationFailed
        }
    }

    public func open(
        key: [UInt8],
        nonce: [UInt8],
        ciphertext: [UInt8],
        additionalData: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == keyLength else { throw TLSCipherSuiteError.invalidKeyLength }
        guard nonce.count == 12 else { throw TLSCipherSuiteError.invalidNonceLength }
        guard ciphertext.count >= tagLength else { throw TLSCipherSuiteError.authenticationFailed }
        let tagStart = ciphertext.count - tagLength
        let body = Data(ciphertext[0..<tagStart])
        let tag = Data(ciphertext[tagStart...])
        let symmetricKey = SymmetricKey(data: Data(key))
        do {
            switch self {
            case .aes128GcmSha256, .aes256GcmSha384:
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: Data(nonce)),
                    ciphertext: body,
                    tag: tag
                )
                return Array(try AES.GCM.open(box, using: symmetricKey, authenticating: Data(additionalData)))
            case .chacha20Poly1305Sha256:
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: Data(nonce)),
                    ciphertext: body,
                    tag: tag
                )
                return Array(try ChaChaPoly.open(box, using: symmetricKey, authenticating: Data(additionalData)))
            }
        } catch {
            throw TLSCipherSuiteError.authenticationFailed
        }
    }

    public static func from(_ rawValue: UInt16) -> TLSCipherSuite? {
        TLSCipherSuite(rawValue: rawValue)
    }
}
