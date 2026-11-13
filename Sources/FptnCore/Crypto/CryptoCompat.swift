import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum CryptoError: Error, Equatable, LocalizedError {
    case invalidKeyLength
    case invalidNonce
    case authenticationFailed

    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength: return "Invalid cryptographic key length."
        case .invalidNonce: return "Invalid cryptographic nonce length."
        case .authenticationFailed: return "Cryptographic authentication failed."
        }
    }
}

public enum Digests {
    public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(bytes)))
    }

    public static func sha384(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA384.hash(data: Data(bytes)))
    }

    public static func sha1(_ bytes: [UInt8]) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: Data(bytes)))
    }

    public static func md5(_ bytes: [UInt8]) -> [UInt8] {
        Array(Insecure.MD5.hash(data: Data(bytes)))
    }

    public static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<lhs.count {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}

public enum TLSHash: Sendable {
    case sha256
    case sha384

    public var length: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        }
    }

    public func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .sha256: return Digests.sha256(bytes)
        case .sha384: return Digests.sha384(bytes)
        }
    }

    public func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: Data(key))
        switch self {
        case .sha256:
            return Array(HMAC<SHA256>.authenticationCode(for: Data(data), using: symmetricKey))
        case .sha384:
            return Array(HMAC<SHA384>.authenticationCode(for: Data(data), using: symmetricKey))
        }
    }
}

public enum HKDF {
    public static func extract(hash: TLSHash, salt: [UInt8], inputKeyMaterial: [UInt8]) -> [UInt8] {
        let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: hash.length) : salt
        return hash.hmac(key: effectiveSalt, data: inputKeyMaterial)
    }

    public static func expand(hash: TLSHash, pseudorandomKey: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        precondition(length >= 0)
        precondition(length <= 255 * hash.length)
        var output: [UInt8] = []
        output.reserveCapacity(length)
        var previous: [UInt8] = []
        var counter: UInt8 = 1
        while output.count < length {
            var input = previous
            input.append(contentsOf: info)
            input.append(counter)
            previous = hash.hmac(key: pseudorandomKey, data: input)
            output.append(contentsOf: previous)
            counter &+= 1
        }
        return Array(output.prefix(length))
    }

    /// RFC 8446 section 7.1 `HKDF-Expand-Label`.
    public static func expandLabel(
        hash: TLSHash,
        secret: [UInt8],
        label: String,
        context: [UInt8],
        length: Int
    ) -> [UInt8] {
        let fullLabel = Array(("tls13 " + label).utf8)
        var info: [UInt8] = []
        info.reserveCapacity(4 + fullLabel.count + context.count)
        info.append(UInt8((length >> 8) & 0xff))
        info.append(UInt8(length & 0xff))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(UInt8(context.count))
        info.append(contentsOf: context)
        return expand(hash: hash, pseudorandomKey: secret, info: info, length: length)
    }

    /// RFC 8446 section 7.1 `Derive-Secret`.
    public static func deriveSecret(
        hash: TLSHash,
        secret: [UInt8],
        label: String,
        transcriptHash: [UInt8]
    ) -> [UInt8] {
        expandLabel(hash: hash, secret: secret, label: label, context: transcriptHash, length: hash.length)
    }
}
