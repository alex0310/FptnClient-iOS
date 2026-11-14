import Foundation

public enum CertificateRevocationError: Error, Equatable, LocalizedError {
    case noRevocationData
    case missingIssuer

    public var errorDescription: String? {
        switch self {
        case .noRevocationData: return "No fresh revocation status is available."
        case .missingIssuer: return "Cannot verify revocation data without the issuer certificate."
        }
    }
}

/// Revocation inputs. The client never fetches CRLs/OCSP during a handshake:
/// the network is being tunneled, so data is supplied by the caller (or via
/// OCSP stapling) and is refreshed out of band.
public struct RevocationPolicy: Equatable, Sendable {
    public var crlDERs: [[UInt8]]
    public var ocspDERs: [[UInt8]]
    /// When true, at least one fresh, signature-verified good status is required.
    public var requireStatus: Bool

    public init(
        crlDERs: [[UInt8]] = [],
        ocspDERs: [[UInt8]] = [],
        requireStatus: Bool = false
    ) {
        self.crlDERs = crlDERs
        self.ocspDERs = ocspDERs
        self.requireStatus = requireStatus
    }

    public static let disabled = RevocationPolicy()
}

public enum CertificateRevocation {
    /// Returns `true` when a fresh, verified good status was found.
    @discardableResult
    public static func verify(
        certificate: X509Certificate,
        issuer: X509Certificate?,
        policy: RevocationPolicy,
        stapledOCSPDER: [UInt8]? = nil,
        now: Date = Date()
    ) throws -> Bool {
        let ocspDERs = policy.ocspDERs + (stapledOCSPDER.map { [$0] } ?? [])
        guard !policy.crlDERs.isEmpty || !ocspDERs.isEmpty else {
            if policy.requireStatus { throw CertificateRevocationError.noRevocationData }
            return false
        }
        guard let issuer else { throw CertificateRevocationError.missingIssuer }

        var freshStatusFound = false
        for der in ocspDERs {
            let infos = try CertificateOCSP.parse(der)
            // A revoked/unknown response is decisive; do not fall through to CRLs.
            guard infos.contains(where: {
                $0.serialNumber == certificate.serialNumber
            }) else { continue }
            try CertificateOCSP.verify(infos, certificate: certificate, issuer: issuer, now: now)
            freshStatusFound = true
        }
        for der in policy.crlDERs where !freshStatusFound {
            let info = try CertificateCRL.parse(der)
            try CertificateCRL.verify(info, certificate: certificate, issuer: issuer, now: now)
            freshStatusFound = true
        }
        guard freshStatusFound || !policy.requireStatus else {
            throw CertificateRevocationError.noRevocationData
        }
        return freshStatusFound
    }
}
