import Foundation

public enum CertificateTransparencyError: Error, Equatable, LocalizedError {
    case malformedSCTList
    case unsupportedVersion(UInt8)
    case missingSCT
    case untrustedLog
    case invalidSignature
    case futureTimestamp
    case unsupportedHash(UInt8)
    case unsupportedSignatureAlgorithm(UInt8)
    case insufficientSCTs(valid: Int, required: Int)

    public var errorDescription: String? {
        switch self {
        case .malformedSCTList: return "Signed Certificate Timestamp list is malformed."
        case let .unsupportedVersion(v): return "Unsupported SCT version \(v)."
        case .missingSCT: return "Certificate has no SCT but CT policy requires one."
        case .untrustedLog: return "SCT was issued by an untrusted CT log."
        case .invalidSignature: return "SCT signature is invalid."
        case .futureTimestamp: return "SCT timestamp is in the future."
        case let .unsupportedHash(v): return "Unsupported SCT hash algorithm \(v)."
        case let .unsupportedSignatureAlgorithm(v): return "Unsupported SCT signature algorithm \(v)."
        case let .insufficientSCTs(valid, required):
            return "Only \(valid) valid SCTs, \(required) required."
        }
    }
}

/// RFC 6962 v1 Signed Certificate Timestamp.
public struct SignedCertificateTimestamp: Equatable, Sendable {
    public let version: UInt8
    public let logID: [UInt8]
    public let timestamp: UInt64
    public let extensions: [UInt8]
    public let hashAlgorithm: UInt8
    public let signatureAlgorithm: UInt8
    public let signature: [UInt8]
}

public enum SCTList {
    /// Parses a TLS `SignedCertificateTimestampList` (u16 total length, then
    /// u16-prefixed SerializedSCT entries).
    public static func parse(_ bytes: [UInt8]) throws -> [SignedCertificateTimestamp] {
        var reader = ByteReader(bytes)
        let list = try reader.readLengthPrefixed16()
        guard reader.isAtEnd else { throw CertificateTransparencyError.malformedSCTList }
        var listReader = ByteReader(list)
        var result: [SignedCertificateTimestamp] = []
        while !listReader.isAtEnd {
            let serialized = try listReader.readLengthPrefixed16()
            result.append(try parseSCT(serialized))
        }
        return result
    }

    /// Parses the X.509 SCT extension payload: an OCTET STRING whose content is
    /// the TLS-encoded list.
    public static func parseEmbedded(_ bytes: [UInt8]) throws -> [SignedCertificateTimestamp] {
        let element = try DER.parse(bytes).requireTag(0x04)
        return try parse(element.content)
    }

    private static func parseSCT(_ bytes: [UInt8]) throws -> SignedCertificateTimestamp {
        var reader = ByteReader(bytes)
        let version = try reader.readUInt8()
        guard version == 0 else {
            throw CertificateTransparencyError.unsupportedVersion(version)
        }
        let logID = try reader.readBytes(32)
        let timestamp = try reader.readUInt64()
        let extensions = try reader.readLengthPrefixed16()
        let hashAlgorithm = try reader.readUInt8()
        let signatureAlgorithm = try reader.readUInt8()
        let signature = try reader.readLengthPrefixed16()
        guard reader.isAtEnd else {
            throw CertificateTransparencyError.malformedSCTList
        }
        return SignedCertificateTimestamp(
            version: version,
            logID: logID,
            timestamp: timestamp,
            extensions: extensions,
            hashAlgorithm: hashAlgorithm,
            signatureAlgorithm: signatureAlgorithm,
            signature: signature
        )
    }

    /// RFC 6962 section 3.2 digitally-signed input for an `x509_entry` SCT.
    public static func signedData(
        for sct: SignedCertificateTimestamp,
        certificateDER: [UInt8]
    ) -> [UInt8] {
        var output: [UInt8] = [0x00, 0x00]  // version + certificate_timestamp
        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8((sct.timestamp >> UInt64(shift)) & 0xff))
        }
        output.append(contentsOf: [0x00, 0x00])  // LogEntryType x509_entry
        let count = certificateDER.count
        output.append(UInt8((count >> 16) & 0xff))
        output.append(UInt8((count >> 8) & 0xff))
        output.append(UInt8(count & 0xff))
        output.append(contentsOf: certificateDER)
        output.append(UInt8((sct.extensions.count >> 8) & 0xff))
        output.append(UInt8(sct.extensions.count & 0xff))
        output.append(contentsOf: sct.extensions)
        return output
    }
}

public struct CTLog: Equatable, Sendable {
    public let logID: [UInt8]
    public let key: RawSignatureKey

    public init(logID: [UInt8], key: RawSignatureKey) {
        self.logID = logID
        self.key = key
    }

    /// Chrome-style log ID: SHA-256 of the DER public key.
    public static func trusted(
        keyBytes: [UInt8],
        algorithm: RawSignatureAlgorithm
    ) -> CTLog {
        CTLog(
            logID: Digests.sha256(keyBytes),
            key: RawSignatureKey(algorithm: algorithm, bytes: keyBytes)
        )
    }
}

public struct CTPolicy: Equatable, Sendable {
    public var trustedLogs: [CTLog]
    public var minimumValidSCTs: Int
    /// Allowed clock skew for SCT timestamps.
    public var timestampSkew: TimeInterval

    public init(
        trustedLogs: [CTLog] = [],
        minimumValidSCTs: Int = 0,
        timestampSkew: TimeInterval = 300
    ) {
        self.trustedLogs = trustedLogs
        self.minimumValidSCTs = minimumValidSCTs
        self.timestampSkew = timestampSkew
    }

    public static let disabled = CTPolicy()
}

public enum CertificateTransparencyVerifier {
    /// Returns the number of cryptographically valid SCTs.
    @discardableResult
    public static func verify(
        tlsSCTList: [UInt8]?,
        embeddedSCTList: [UInt8]?,
        certificateDER: [UInt8],
        policy: CTPolicy,
        now: Date = Date()
    ) throws -> Int {
        guard policy.minimumValidSCTs > 0 else { return 0 }
        var scts: [SignedCertificateTimestamp] = []
        if let tlsSCTList {
            scts.append(contentsOf: try SCTList.parse(tlsSCTList))
        }
        if let embeddedSCTList {
            // `X509Certificate.embeddedSCTList` already holds the unwrapped
            // TLS-encoded list (the X.509 OCTET STRING was removed by parser).
            scts.append(contentsOf: try SCTList.parse(embeddedSCTList))
        }
        guard !scts.isEmpty else { throw CertificateTransparencyError.missingSCT }

        var valid = 0
        for sct in scts {
            guard let log = policy.trustedLogs.first(where: {
                Digests.constantTimeEquals($0.logID, sct.logID)
            }) else { continue }
            guard let hash = RawSignatureHash(rawValue: sct.hashAlgorithm) else {
                throw CertificateTransparencyError.unsupportedHash(sct.hashAlgorithm)
            }
            guard try algorithm(for: sct.signatureAlgorithm, key: log.key) else {
                throw CertificateTransparencyError.unsupportedSignatureAlgorithm(
                    sct.signatureAlgorithm
                )
            }
            let issuedAt = Date(timeIntervalSince1970: Double(sct.timestamp) / 1_000)
            guard issuedAt <= now.addingTimeInterval(policy.timestampSkew) else {
                throw CertificateTransparencyError.futureTimestamp
            }
            let signed = SCTList.signedData(for: sct, certificateDER: certificateDER)
            guard try RawSignature.verify(
                signedData: signed,
                signature: sct.signature,
                hash: hash,
                key: log.key
            ) else {
                throw CertificateTransparencyError.invalidSignature
            }
            valid += 1
        }
        guard valid >= policy.minimumValidSCTs else {
            throw CertificateTransparencyError.insufficientSCTs(
                valid: valid,
                required: policy.minimumValidSCTs
            )
        }
        return valid
    }

    private static func algorithm(
        for value: UInt8,
        key: RawSignatureKey
    ) throws -> Bool {
        switch value {
        case 1: return key.algorithm == .rsa
        case 3: return key.algorithm == .ecdsaP256 || key.algorithm == .ecdsaP384
        default: return false
        }
    }
}
