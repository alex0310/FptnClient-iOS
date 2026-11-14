import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

/// Algorithms and key material for signatures that are not X.509 certificates
/// (Certificate Transparency SCTs, in particular).
public enum RawSignatureHash: UInt8, Equatable, Sendable {
    case sha1 = 2
    case sha256 = 4
    case sha384 = 5
}

public enum RawSignatureAlgorithm: Equatable, Sendable {
    case rsa
    case ecdsaP256
    case ecdsaP384
}

public struct RawSignatureKey: Equatable, Sendable {
    public let algorithm: RawSignatureAlgorithm
    /// SPKI DER for RSA, X9.63 or raw `X || Y` for ECDSA.
    public let bytes: [UInt8]

    public init(algorithm: RawSignatureAlgorithm, bytes: [UInt8]) {
        self.algorithm = algorithm
        self.bytes = bytes
    }
}

public enum RawSignature {
    /// Verifies a TLS `DigitallySigned`-style signature over `signedData`.
    public static func verify(
        signedData: [UInt8],
        signature: [UInt8],
        hash: RawSignatureHash,
        key: RawSignatureKey
    ) throws -> Bool {
        let data = Data(signedData)
        switch key.algorithm {
        case .rsa:
            let publicKey: _RSA.Signing.PublicKey
            do {
                publicKey = try _RSA.Signing.PublicKey(derRepresentation: key.bytes)
            } catch {
                throw CertificateSignatureError.invalidPublicKey
            }
            let rsaSignature = _RSA.Signing.RSASignature(
                rawRepresentation: Data(signature)
            )
            switch hash {
            case .sha1:
                return publicKey.isValidSignature(
                    rsaSignature,
                    for: Insecure.SHA1.hash(data: data),
                    padding: .insecurePKCS1v1_5
                )
            case .sha256:
                return publicKey.isValidSignature(
                    rsaSignature,
                    for: SHA256.hash(data: data),
                    padding: .insecurePKCS1v1_5
                )
            case .sha384:
                return publicKey.isValidSignature(
                    rsaSignature,
                    for: SHA384.hash(data: data),
                    padding: .insecurePKCS1v1_5
                )
            }
        case .ecdsaP256:
            let publicKey = try makeP256Key(normalizedECPoint(key.bytes))
            let ecdsa = try P256.Signing.ECDSASignature(
                derRepresentation: Data(signature)
            )
            switch hash {
            case .sha1:
                return publicKey.isValidSignature(ecdsa, for: Insecure.SHA1.hash(data: data))
            case .sha256:
                return publicKey.isValidSignature(ecdsa, for: SHA256.hash(data: data))
            case .sha384:
                return publicKey.isValidSignature(ecdsa, for: SHA384.hash(data: data))
            }
        case .ecdsaP384:
            let publicKey = try makeP384Key(normalizedECPoint(key.bytes))
            let ecdsa = try P384.Signing.ECDSASignature(
                derRepresentation: Data(signature)
            )
            switch hash {
            case .sha1:
                return publicKey.isValidSignature(ecdsa, for: Insecure.SHA1.hash(data: data))
            case .sha256:
                return publicKey.isValidSignature(ecdsa, for: SHA256.hash(data: data))
            case .sha384:
                return publicKey.isValidSignature(ecdsa, for: SHA384.hash(data: data))
            }
        }
    }

    private static func normalizedECPoint(_ bytes: [UInt8]) -> [UInt8] {
        bytes.count == 65 && bytes.first == 0x04 ? Array(bytes.dropFirst()) : bytes
    }

    private static func makeP256Key(_ bytes: [UInt8]) throws -> P256.Signing.PublicKey {
        do { return try P256.Signing.PublicKey(rawRepresentation: bytes) }
        catch { throw CertificateSignatureError.invalidPublicKey }
    }

    private static func makeP384Key(_ bytes: [UInt8]) throws -> P384.Signing.PublicKey {
        do { return try P384.Signing.PublicKey(rawRepresentation: bytes) }
        catch { throw CertificateSignatureError.invalidPublicKey }
    }
}
