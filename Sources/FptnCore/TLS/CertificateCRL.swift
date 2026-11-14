import Foundation

public enum CertificateCRLError: Error, Equatable, LocalizedError {
    case malformed
    case missingAlgorithm
    case invalidSignature
    case issuerMismatch
    case expired(Date)
    case notYetValid(Date)
    case revoked

    public var errorDescription: String? {
        switch self {
        case .malformed: return "CRL is malformed."
        case .missingAlgorithm: return "CRL signature algorithm is missing."
        case .invalidSignature: return "CRL signature is invalid."
        case .issuerMismatch: return "CRL was not issued by the certificate issuer."
        case let .expired(date): return "CRL expired at \(date)."
        case let .notYetValid(date): return "CRL is not valid until \(date)."
        case .revoked: return "Certificate serial number is present in the CRL."
        }
    }
}

public struct CRLInfo: Equatable, Sendable {
    public let issuerDER: [UInt8]
    public let thisUpdate: Date
    public let nextUpdate: Date?
    public let revokedSerials: [[UInt8]]
    public let tbsDER: [UInt8]
    public let signature: [UInt8]
    public let signatureAlgorithmOID: String
}

/// Minimal RFC 5280 `CertificateList` parser: issuer, validity window and
/// revoked serial numbers. Signature verification is done by the caller.
public enum CertificateCRL {
    public static func parse(_ der: [UInt8]) throws -> CRLInfo {
        let top = try DER.parse(der).requireTag(0x30)
        let fields = try top.children
        guard fields.count == 3 else { throw CertificateCRLError.malformed }
        let tbs = try fields[0].requireTag(0x30)
        let algorithm = try fields[1].requireTag(0x30)
        guard let algorithmOID = try algorithm.children.first else {
            throw CertificateCRLError.missingAlgorithm
        }
        let signature = try fields[2].bitStringBytes

        let parts = try tbs.children
        var index = 0
        if parts.first?.tag == 0x02 { index += 1 }          // optional version
        guard parts.count >= index + 3 else { throw CertificateCRLError.malformed }
        index += 1                                          // signature AlgorithmIdentifier
        let issuerDER = parts[index].encoded
        index += 1
        let thisUpdate = try parts[index].dateValue
        index += 1
        var nextUpdate: Date?
        if let candidate = parts[safe: index], candidate.tag == 0x17 || candidate.tag == 0x18 {
            nextUpdate = try candidate.dateValue
            index += 1
        }
        var revokedSerials: [[UInt8]] = []
        if let list = parts[safe: index], list.tag == 0x30 {
            for entry in try list.children {
                let entryParts = try entry.children
                guard let serial = entryParts.first, serial.tag == 0x02 else {
                    throw CertificateCRLError.malformed
                }
                revokedSerials.append(serial.content)
            }
        }
        return CRLInfo(
            issuerDER: issuerDER,
            thisUpdate: thisUpdate,
            nextUpdate: nextUpdate,
            revokedSerials: revokedSerials,
            tbsDER: tbs.encoded,
            signature: signature,
            signatureAlgorithmOID: try algorithmOID.objectIdentifier
        )
    }

    /// Verifies signature, issuer, freshness and serial membership.
    public static func verify(
        _ info: CRLInfo,
        certificate: X509Certificate,
        issuer: X509Certificate,
        now: Date = Date()
    ) throws {
        guard info.issuerDER == issuer.subjectDER else {
            throw CertificateCRLError.issuerMismatch
        }
        guard try CertificateSignature.verify(
            signedData: info.tbsDER,
            signature: info.signature,
            algorithmOID: info.signatureAlgorithmOID,
            issuer: issuer
        ) else {
            throw CertificateCRLError.invalidSignature
        }
        guard now >= info.thisUpdate else {
            throw CertificateCRLError.notYetValid(info.thisUpdate)
        }
        if let nextUpdate = info.nextUpdate, now > nextUpdate {
            throw CertificateCRLError.expired(nextUpdate)
        }
        guard !info.revokedSerials.contains(certificate.serialNumber) else {
            throw CertificateCRLError.revoked
        }
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
