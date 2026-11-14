import Foundation

/// Object identifiers used by the minimal X.509 validator. Only algorithms
/// the client can actually verify are listed; anything else fails closed.
public enum X509OID {
    // Public key algorithms
    public static let rsaEncryption = "1.2.840.113549.1.1.1"
    public static let ecPublicKey = "1.2.840.10045.2.1"
    public static let ed25519 = "1.3.101.112"

    // ECDSA named curves
    public static let secp256r1 = "1.2.840.10045.3.1.7"
    public static let secp384r1 = "1.3.132.0.34"
    public static let secp521r1 = "1.3.132.0.35"

    // Certificate signature algorithms
    public static let sha1WithRSA = "1.2.840.113549.1.1.5"
    public static let sha256WithRSA = "1.2.840.113549.1.1.11"
    public static let sha384WithRSA = "1.2.840.113549.1.1.12"
    public static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    public static let ecdsaWithSHA384 = "1.2.840.10045.4.3.3"
    public static let ed25519Signature = "1.3.101.112"

    // Extensions
    public static let subjectKeyIdentifier = "2.5.29.14"
    public static let keyUsage = "2.5.29.15"
    public static let subjectAltName = "2.5.29.17"
    public static let basicConstraints = "2.5.29.19"
    public static let authorityKeyIdentifier = "2.5.29.35"
    public static let extKeyUsage = "2.5.29.37"
    public static let crlDistributionPoints = "2.5.29.31"
    public static let authorityInfoAccess = "1.3.6.1.5.5.7.1.1"
    public static let signedCertificateTimestamp = "1.3.6.1.4.1.11129.2.4.2"

    // Extended key usages
    public static let serverAuth = "1.3.6.1.5.5.7.3.1"
    public static let anyExtendedKeyUsage = "2.5.29.37.0"

    // Authority Information Access methods
    public static let ocspAccessMethod = "1.3.6.1.5.5.7.48.1"

    // Attribute types
    public static let commonName = "2.5.4.3"

    public static func isSupportedCertificateSignature(_ oid: String) -> Bool {
        [
            sha1WithRSA, sha256WithRSA, sha384WithRSA,
            ecdsaWithSHA256, ecdsaWithSHA384, ed25519Signature
        ].contains(oid)
    }
}

/// TLS 1.3 SignatureScheme values our CertificateVerify verifier understands.
public enum TLSSignatureScheme: Equatable, Sendable {
    case rsaPSSSHA256
    case rsaPSSSHA384
    case rsaPKCS1SHA256
    case ecdsaP256SHA256
    case ecdsaP384SHA384
    case ed25519

    public init?(rawValue: UInt16) {
        switch rawValue {
        case 0x0804: self = .rsaPSSSHA256
        case 0x0805: self = .rsaPSSSHA384
        case 0x0401: self = .rsaPKCS1SHA256
        case 0x0403: self = .ecdsaP256SHA256
        case 0x0503: self = .ecdsaP384SHA384
        case 0x0807: self = .ed25519
        default: return nil
        }
    }
}
