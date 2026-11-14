import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

public enum CertificateSignatureError: Error, Equatable, LocalizedError {
    case unsupportedAlgorithm(String)
    case unsupportedKey(String)
    case invalidPublicKey
    case invalidSignature

    public var errorDescription: String? {
        switch self {
        case let .unsupportedAlgorithm(oid): return "Unsupported certificate signature algorithm: \(oid)."
        case let .unsupportedKey(oid): return "Unsupported public key algorithm: \(oid)."
        case .invalidPublicKey: return "Certificate public key is invalid."
        case .invalidSignature: return "Certificate signature is malformed."
        }
    }
}

/// Signature verification for X.509 certificates and TLS 1.3
/// `CertificateVerify`. All verification is pure Swift and works identically
/// on Linux and Apple platforms.
public enum CertificateSignature {
    /// Verifies `certificate.signature` over `certificate.tbsDER` with the
    /// issuer's public key. Returns `false` for a bad signature and throws for
    /// an algorithm/key we deliberately refuse to accept.
    public static func verify(
        certificate: X509Certificate,
        issuer: X509Certificate
    ) throws -> Bool {
        let oid = certificate.signatureAlgorithmOID
        guard X509OID.isSupportedCertificateSignature(oid) else {
            throw CertificateSignatureError.unsupportedAlgorithm(oid)
        }
        switch issuer.publicKeyAlgorithmOID {
        case X509OID.rsaEncryption:
            return try verifyRSA(
                signedData: Data(certificate.tbsDER),
                signature: certificate.signature,
                publicKeyDER: issuer.subjectPublicKeyInfoDER,
                algorithmOID: oid,
                padding: .insecurePKCS1v1_5
            )
        case X509OID.ecPublicKey:
            return try verifyECDSA(
                signedData: Data(certificate.tbsDER),
                signature: certificate.signature,
                publicKeyBytes: issuer.publicKeyBytes,
                curveOID: issuer.publicKeyCurveOID,
                algorithmOID: oid
            )
        case X509OID.ed25519:
            return try verifyEd25519(
                signedData: Data(certificate.tbsDER),
                signature: certificate.signature,
                publicKeyBytes: issuer.publicKeyBytes
            )
        default:
            throw CertificateSignatureError.unsupportedKey(issuer.publicKeyAlgorithmOID)
        }
    }

    /// Verifies a TLS 1.3 `CertificateVerify` signature with the leaf key.
    public static func verifyCertificateVerify(
        signature: [UInt8],
        scheme: TLSSignatureScheme,
        signedContent: [UInt8],
        leaf: X509Certificate
    ) throws -> Bool {
        switch scheme {
        case .rsaPSSSHA256, .rsaPSSSHA384, .rsaPKCS1SHA256:
            guard leaf.publicKeyAlgorithmOID == X509OID.rsaEncryption else {
                throw CertificateSignatureError.unsupportedKey(leaf.publicKeyAlgorithmOID)
            }
            let padding: _RSA.Signing.Padding = scheme == .rsaPKCS1SHA256
                ? .insecurePKCS1v1_5
                : .PSS
            let oid = scheme == .rsaPSSSHA384
                ? X509OID.sha384WithRSA
                : X509OID.sha256WithRSA
            return try verifyRSA(
                signedData: Data(signedContent),
                signature: signature,
                publicKeyDER: leaf.subjectPublicKeyInfoDER,
                algorithmOID: oid,
                padding: padding
            )
        case .ecdsaP256SHA256, .ecdsaP384SHA384:
            guard leaf.publicKeyAlgorithmOID == X509OID.ecPublicKey else {
                throw CertificateSignatureError.unsupportedKey(leaf.publicKeyAlgorithmOID)
            }
            let oid = scheme == .ecdsaP384SHA384
                ? X509OID.ecdsaWithSHA384
                : X509OID.ecdsaWithSHA256
            return try verifyECDSA(
                signedData: Data(signedContent),
                signature: signature,
                publicKeyBytes: leaf.publicKeyBytes,
                curveOID: leaf.publicKeyCurveOID,
                algorithmOID: oid
            )
        case .ed25519:
            return try verifyEd25519(
                signedData: Data(signedContent),
                signature: signature,
                publicKeyBytes: leaf.publicKeyBytes
            )
        }
    }

    // MARK: - Algorithm implementations

    private static func verifyRSA(
        signedData: Data,
        signature: [UInt8],
        publicKeyDER: [UInt8],
        algorithmOID: String,
        padding: _RSA.Signing.Padding
    ) throws -> Bool {
        let key: _RSA.Signing.PublicKey
        do {
            key = try _RSA.Signing.PublicKey(derRepresentation: publicKeyDER)
        } catch {
            throw CertificateSignatureError.invalidPublicKey
        }
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: Data(signature))
        switch algorithmOID {
        case X509OID.sha1WithRSA:
            return key.isValidSignature(rsaSignature, for: Insecure.SHA1.hash(data: signedData), padding: padding)
        case X509OID.sha256WithRSA:
            return key.isValidSignature(rsaSignature, for: SHA256.hash(data: signedData), padding: padding)
        case X509OID.sha384WithRSA:
            return key.isValidSignature(rsaSignature, for: SHA384.hash(data: signedData), padding: padding)
        default:
            throw CertificateSignatureError.unsupportedAlgorithm(algorithmOID)
        }
    }

    private static func verifyECDSA(
        signedData: Data,
        signature: [UInt8],
        publicKeyBytes: [UInt8],
        curveOID: String?,
        algorithmOID: String
    ) throws -> Bool {
        switch curveOID {
        case X509OID.secp256r1:
            let key = try p256Key(publicKeyBytes)
            let ecdsa = try p256Signature(signature)
            switch algorithmOID {
            case X509OID.ecdsaWithSHA256:
                return key.isValidSignature(ecdsa, for: SHA256.hash(data: signedData))
            case X509OID.ecdsaWithSHA384:
                return key.isValidSignature(ecdsa, for: SHA384.hash(data: signedData))
            default:
                throw CertificateSignatureError.unsupportedAlgorithm(algorithmOID)
            }
        case X509OID.secp384r1:
            let key = try p384Key(publicKeyBytes)
            let ecdsa = try P384.Signing.ECDSASignature(derRepresentation: Data(signature))
            switch algorithmOID {
            case X509OID.ecdsaWithSHA256:
                return key.isValidSignature(ecdsa, for: SHA256.hash(data: signedData))
            case X509OID.ecdsaWithSHA384:
                return key.isValidSignature(ecdsa, for: SHA384.hash(data: signedData))
            default:
                throw CertificateSignatureError.unsupportedAlgorithm(algorithmOID)
            }
        default:
            throw CertificateSignatureError.unsupportedKey(curveOID ?? "unknown curve")
        }
    }

    /// SPKI stores an EC point as X9.63 (`0x04 || X || Y`), while CryptoKit's
    /// `rawRepresentation` expects just `X || Y`.
    private static func ecRawRepresentation(_ bytes: [UInt8]) -> [UInt8] {
        bytes.count == 65 && bytes.first == 0x04 ? Array(bytes.dropFirst()) : bytes
    }

    private static func p256Key(_ bytes: [UInt8]) throws -> P256.Signing.PublicKey {
        do { return try P256.Signing.PublicKey(rawRepresentation: ecRawRepresentation(bytes)) }
        catch { throw CertificateSignatureError.invalidPublicKey }
    }

    private static func p384Key(_ bytes: [UInt8]) throws -> P384.Signing.PublicKey {
        do { return try P384.Signing.PublicKey(rawRepresentation: ecRawRepresentation(bytes)) }
        catch { throw CertificateSignatureError.invalidPublicKey }
    }

    /// TLS 1.3 uses a raw `r || s` signature; X.509 uses the DER
    /// `ECDSA-Sig-Value`. Accept both so CertificateVerify and chain
    /// signatures share one verifier.
    private static func p256Signature(_ bytes: [UInt8]) throws -> P256.Signing.ECDSASignature {
        if let der = try? P256.Signing.ECDSASignature(derRepresentation: Data(bytes)) {
            return der
        }
        do {
            return try P256.Signing.ECDSASignature(rawRepresentation: Data(bytes))
        } catch {
            throw CertificateSignatureError.invalidSignature
        }
    }

    private static func verifyEd25519(
        signedData: Data,
        signature: [UInt8],
        publicKeyBytes: [UInt8]
    ) throws -> Bool {
        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
        } catch {
            throw CertificateSignatureError.invalidPublicKey
        }
        return key.isValidSignature(Data(signature), for: signedData)
    }
}

/// RFC 8446 section 4.4.3: the signed content of `CertificateVerify`.
public enum CertificateVerifyContext {
    public static func signedContent(transcriptHash: [UInt8], isServer: Bool = true) -> [UInt8] {
        let label = isServer
            ? "TLS 1.3, server CertificateVerify"
            : "TLS 1.3, client CertificateVerify"
        return [UInt8](repeating: 0x20, count: 64)
            + Array(label.utf8)
            + [0x00]
            + transcriptHash
    }
}
