import Foundation

/// Optional, defence-in-depth checks applied after the primary certificate
/// policy (MD5 pin, strict chain or system trust) succeeds.
public struct CertificateSecurityOptions: Equatable, Sendable {
    /// SHA-256 SPKI pins (hex or base64). Empty means no pinning.
    public var spkiPins: [String]
    public var revocation: RevocationPolicy
    public var transparency: CTPolicy

    public init(
        spkiPins: [String] = [],
        revocation: RevocationPolicy = .disabled,
        transparency: CTPolicy = .disabled
    ) {
        self.spkiPins = spkiPins
        self.revocation = revocation
        self.transparency = transparency
    }

    public static let `default` = CertificateSecurityOptions()

    /// Adds a token-supplied SPKI pin without duplicating an existing one.
    public func addingSPKIPin(_ pin: String?) -> CertificateSecurityOptions {
        guard let pin, !spkiPins.contains(pin) else { return self }
        var copy = self
        copy.spkiPins.append(pin)
        return copy
    }

    public var isEnabled: Bool {
        !spkiPins.isEmpty
            || revocation.requireStatus
            || !revocation.crlDERs.isEmpty
            || !revocation.ocspDERs.isEmpty
            || transparency.minimumValidSCTs > 0
    }
}

public enum CertificateSecurityError: Error, Equatable, LocalizedError {
    case malformedLeaf

    public var errorDescription: String? {
        switch self {
        case .malformedLeaf: return "Cannot run certificate security checks: leaf DER is malformed."
        }
    }
}

public enum CertificateSecurity {
    /// Applies SPKI pinning, OCSP/CRL revocation and Certificate Transparency
    /// checks. When every option is disabled this is a no-op, so MD5-pinned
    /// connections with synthetic test certificates are unaffected.
    public static func verify(
        chainDER: [[UInt8]],
        chain: [X509Certificate],
        issuer: X509Certificate?,
        options: CertificateSecurityOptions,
        stapledOCSPDER: [UInt8]?,
        tlsSCTList: [UInt8]?,
        now: Date = Date()
    ) throws {
        guard options.isEnabled, let leafDER = chainDER.first else { return }
        let leaf: X509Certificate
        do {
            leaf = try chain.first ?? X509Certificate(der: leafDER)
        } catch {
            throw CertificateSecurityError.malformedLeaf
        }

        try CertificateSPKI.verify(certificate: leaf, pins: options.spkiPins)
        try CertificateRevocation.verify(
            certificate: leaf,
            issuer: issuer,
            policy: options.revocation,
            stapledOCSPDER: stapledOCSPDER,
            now: now
        )
        try CertificateTransparencyVerifier.verify(
            tlsSCTList: tlsSCTList,
            embeddedSCTList: leaf.embeddedSCTList,
            certificateDER: leafDER,
            policy: options.transparency,
            now: now
        )
    }
}
