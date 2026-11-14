import Foundation

public enum CertificateOCSPError: Error, Equatable, LocalizedError {
    case malformed
    case unsuccessfulResponse(UInt8)
    case unsupportedResponseType(String)
    case unsupportedStatus(UInt8)
    case invalidSignature
    case expired(Date)
    case notYetValid(Date)
    case revoked
    case unknownStatus
    case serialMismatch

    public var errorDescription: String? {
        switch self {
        case .malformed: return "OCSP response is malformed."
        case let .unsuccessfulResponse(status): return "OCSP response status \(status) is not successful."
        case let .unsupportedResponseType(oid): return "Unsupported OCSP response type \(oid)."
        case let .unsupportedStatus(tag): return String(format: "Unsupported OCSP certStatus tag 0x%02x.", tag)
        case .invalidSignature: return "OCSP response signature is invalid."
        case let .expired(date): return "OCSP status expired at \(date)."
        case let .notYetValid(date): return "OCSP status is not valid until \(date)."
        case .revoked: return "OCSP responder reports the certificate as revoked."
        case .unknownStatus: return "OCSP responder does not know this certificate."
        case .serialMismatch: return "OCSP response is for a different certificate."
        }
    }
}

public enum OCSPStatus: String, Equatable, Sendable {
    case good
    case revoked
    case unknown
}

public struct OCSPInfo: Equatable, Sendable {
    public let status: OCSPStatus
    public let serialNumber: [UInt8]
    public let thisUpdate: Date
    public let nextUpdate: Date?
    public let producedAt: Date
    public let tbsDER: [UInt8]
    public let signature: [UInt8]
    public let signatureAlgorithmOID: String
    public let responderCertificate: X509Certificate?
}

/// Minimal RFC 6960 `BasicOCSPResponse` parser.
public enum CertificateOCSP {
    private static let basicResponseOID = "1.3.6.1.5.5.7.48.1.1"

    public static func parse(_ der: [UInt8]) throws -> [OCSPInfo] {
        let top = try DER.parse(der).requireTag(0x30)
        let fields = try top.children
        guard let responseStatus = fields.first, responseStatus.tag == 0x0a else {
            throw CertificateOCSPError.malformed
        }
        guard (responseStatus.content.first ?? 1) == 0 else {
            throw CertificateOCSPError.unsuccessfulResponse(
                responseStatus.content.first ?? 0xff
            )
        }
        guard let responseBytes = fields[safe: 1], responseBytes.tag == 0xa0 else {
            throw CertificateOCSPError.malformed
        }
        let bytesFields = try DER.parseAll(responseBytes.content)
        guard bytesFields.count >= 2 else { throw CertificateOCSPError.malformed }
        let responseType = try bytesFields[0].objectIdentifier
        guard responseType == basicResponseOID else {
            throw CertificateOCSPError.unsupportedResponseType(responseType)
        }
        // `response` is an OCTET STRING containing the DER BasicOCSPResponse.
        let basic = try DER.parse(bytesFields[1].requireTag(0x04).content)
            .requireTag(0x30)
        let basicFields = try basic.children
        guard basicFields.count >= 3 else { throw CertificateOCSPError.malformed }
        let responseData = try basicFields[0].requireTag(0x30)
        let algorithm = try basicFields[1].requireTag(0x30)
        guard let algorithmOID = try algorithm.children.first else {
            throw CertificateOCSPError.malformed
        }
        let signature = try basicFields[2].bitStringBytes
        let oid = try algorithmOID.objectIdentifier

        var responderCertificate: X509Certificate?
        if let certs = basicFields[safe: 3], certs.tag == 0xa0,
           let first = try DER.parse(certs.content).children.first {
            responderCertificate = try? X509Certificate(der: first.encoded)
        }

        let dataParts = try responseData.children
        var index = 0
        if dataParts.first?.tag == 0xa0 { index += 1 }  // optional version
        guard dataParts.count >= index + 3 else { throw CertificateOCSPError.malformed }
        index += 1                                      // responderID
        let producedAt = try dataParts[index].requireTag(0x18).dateValue
        index += 1
        let responses = try dataParts[index].requireTag(0x30)

        var result: [OCSPInfo] = []
        for single in try responses.children {
            let parts = try single.children
            guard parts.count >= 3 else { throw CertificateOCSPError.malformed }
            let certID = try parts[0].requireTag(0x30).children
            guard certID.count >= 4, certID[3].tag == 0x02 else {
                throw CertificateOCSPError.malformed
            }
            let serial = certID[3].content
            let status = try parseStatus(parts[1])
            let thisUpdate = try parts[2].dateValue
            var nextUpdate: Date?
            if let next = parts[safe: 3], next.tag == 0xa0,
               let time = try next.children.first {
                nextUpdate = try time.dateValue
            }
            result.append(
                OCSPInfo(
                    status: status,
                    serialNumber: serial,
                    thisUpdate: thisUpdate,
                    nextUpdate: nextUpdate,
                    producedAt: producedAt,
                    tbsDER: responseData.encoded,
                    signature: signature,
                    signatureAlgorithmOID: oid,
                    responderCertificate: responderCertificate
                )
            )
        }
        return result
    }

    private static func parseStatus(_ element: DERElement) throws -> OCSPStatus {
        switch element.tag {
        case 0x80: return .good      // [0] IMPLICIT NULL
        case 0xa1: return .revoked   // [1] IMPLICIT RevokedInfo
        case 0x82: return .unknown   // [2] IMPLICIT UnknownInfo
        default: throw CertificateOCSPError.unsupportedStatus(element.tag)
        }
    }

    /// Verifies signature, freshness and status of the matching single response.
    public static func verify(
        _ infos: [OCSPInfo],
        certificate: X509Certificate,
        issuer: X509Certificate,
        now: Date = Date()
    ) throws {
        guard let info = infos.first(where: {
            $0.serialNumber == certificate.serialNumber
        }) else {
            throw CertificateOCSPError.serialMismatch
        }
        let signer = info.responderCertificate ?? issuer
        guard try CertificateSignature.verify(
            signedData: info.tbsDER,
            signature: info.signature,
            algorithmOID: info.signatureAlgorithmOID,
            issuer: signer
        ) else {
            throw CertificateOCSPError.invalidSignature
        }
        guard now >= info.thisUpdate else {
            throw CertificateOCSPError.notYetValid(info.thisUpdate)
        }
        if let nextUpdate = info.nextUpdate, now > nextUpdate {
            throw CertificateOCSPError.expired(nextUpdate)
        }
        switch info.status {
        case .good: return
        case .revoked: throw CertificateOCSPError.revoked
        case .unknown: throw CertificateOCSPError.unknownStatus
        }
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
