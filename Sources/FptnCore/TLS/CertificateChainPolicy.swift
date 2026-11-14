import Foundation

public enum CertificateChainError: Error, Equatable, LocalizedError {
    case emptyChain
    case malformedCertificate
    case noTrustAnchor
    case untrustedRoot
    case brokenChain
    case invalidSignature
    case expired
    case notYetValid
    case notACertificateAuthority
    case missingServerAuthEKU
    case hostnameMismatch(expected: String, present: [String])

    public var errorDescription: String? {
        switch self {
        case .emptyChain: return "The server sent an empty certificate chain."
        case .malformedCertificate: return "A certificate in the chain is malformed."
        case .noTrustAnchor: return "No trusted root certificates are configured."
        case .untrustedRoot: return "The certificate chain does not end at a trusted root."
        case .brokenChain: return "The certificate chain is incomplete or out of order."
        case .invalidSignature: return "A certificate signature is invalid."
        case .expired: return "A certificate in the chain has expired."
        case .notYetValid: return "A certificate in the chain is not yet valid."
        case .notACertificateAuthority: return "An intermediate certificate is not a CA."
        case .missingServerAuthEKU: return "The leaf certificate is not valid for server authentication."
        case let .hostnameMismatch(expected, present):
            return "Certificate does not match host \(expected); present names: \(present.joined(separator: ", "))."
        }
    }
}

/// Explicitly configured trust anchors. There is no implicit public CA bundle:
/// without anchors a strict chain can never validate (fail-closed).
public struct X509TrustAnchors: Equatable, Sendable {
    public let certificates: [X509Certificate]

    public init(certificates: [X509Certificate]) {
        self.certificates = certificates
    }

    public init(derRoots: [[UInt8]]) throws {
        self.certificates = try derRoots.map { try X509Certificate(der: $0) }
    }

    public static let empty = X509TrustAnchors(certificates: [])
    public var isEmpty: Bool { certificates.isEmpty }
}

/// How the TLS client authenticates the server.
public enum CertificateValidationPolicy: Equatable, Sendable {
    /// Upstream FPTN behaviour: compare the MD5 of the leaf DER against the
    /// token's fingerprint. `nil` is rejected rather than silently trusted.
    case pinnedMD5(String?)
    /// Full X.509 path validation plus TLS `CertificateVerify` signature check.
    case strictChain(X509TrustAnchors)
    /// Use the OS trust store (`SecTrust` on Apple, the system PEM bundle on
    /// other platforms). This is the default when a token has no MD5 pin.
    case systemTrust
}

public enum CertificateHostname {
    public static func matches(_ certificate: X509Certificate, hostname: String) -> Bool {
        let host = normalize(hostname)
        guard !host.isEmpty else { return false }
        if !certificate.dnsNames.isEmpty {
            return certificate.dnsNames.contains { matches(pattern: $0, hostname: host) }
        }
        guard let commonName = certificate.commonName else { return false }
        return matches(pattern: commonName, hostname: host)
    }

    /// RFC 6125-style matching: exact match or a single left-most `*` label.
    public static func matches(pattern: String, hostname: String) -> Bool {
        let candidate = normalize(pattern)
        let host = normalize(hostname)
        guard !candidate.isEmpty, !host.isEmpty else { return false }
        if candidate == host { return true }
        guard candidate.hasPrefix("*."),
              !candidate.dropFirst(2).contains("*") else { return false }
        let suffix = String(candidate.dropFirst(2))
        guard host.hasSuffix("." + suffix) else { return false }
        let extraLabels = host.dropLast(suffix.count + 1)
        return !extraLabels.isEmpty && !extraLabels.contains(".")
    }

    private static func normalize(_ value: String) -> String {
        var result = value.lowercased()
        if result.hasSuffix(".") { result.removeLast() }
        return result
    }
}

/// Builds and validates a path from the leaf to one of the configured anchors.
public enum CertificateChainValidator {
    private static let maximumPathLength = 8

    public static func validate(
        chainDER: [[UInt8]],
        hostname: String,
        anchors: X509TrustAnchors,
        now: Date = Date()
    ) throws -> X509Certificate {
        guard !chainDER.isEmpty else { throw CertificateChainError.emptyChain }
        guard !anchors.isEmpty else { throw CertificateChainError.noTrustAnchor }
        let chain: [X509Certificate]
        do {
            chain = try chainDER.map { try X509Certificate(der: $0) }
        } catch {
            throw CertificateChainError.malformedCertificate
        }
        let leaf = chain[0]
        guard CertificateHostname.matches(leaf, hostname: hostname) else {
            throw CertificateChainError.hostnameMismatch(
                expected: hostname,
                present: leaf.dnsNames.isEmpty ? [leaf.commonName ?? ""] : leaf.dnsNames
            )
        }
        try checkLeaf(leaf, now: now)

        var current = leaf
        var usedIntermediates = Set<Int>()
        var reachedAnchor = false
        for _ in 0..<maximumPathLength {
            if let anchor = anchors.certificates.first(where: {
                $0.subjectDER == current.issuerDER
            }) {
                guard try CertificateSignature.verify(certificate: current, issuer: anchor) else {
                    throw CertificateChainError.invalidSignature
                }
                try checkAnchor(anchor, now: now)
                reachedAnchor = true
                break
            }
            guard let index = chain.indices.dropFirst().first(where: {
                !usedIntermediates.contains($0) && chain[$0].subjectDER == current.issuerDER
            }) else {
                throw CertificateChainError.brokenChain
            }
            let issuer = chain[index]
            guard try CertificateSignature.verify(certificate: current, issuer: issuer) else {
                throw CertificateChainError.invalidSignature
            }
            try checkIntermediate(issuer, now: now)
            usedIntermediates.insert(index)
            current = issuer
        }
        guard reachedAnchor else { throw CertificateChainError.untrustedRoot }
        return leaf
    }

    static func checkLeaf(_ leaf: X509Certificate, now: Date) throws {
        try checkValidity(leaf, now: now)
        guard leaf.supportsServerAuthentication else {
            throw CertificateChainError.missingServerAuthEKU
        }
    }

    private static func checkIntermediate(_ certificate: X509Certificate, now: Date) throws {
        try checkValidity(certificate, now: now)
        guard certificate.isCA, certificate.canSignCertificates else {
            throw CertificateChainError.notACertificateAuthority
        }
    }

    private static func checkAnchor(_ anchor: X509Certificate, now: Date) throws {
        try checkValidity(anchor, now: now)
        guard anchor.isCA else { throw CertificateChainError.notACertificateAuthority }
    }

    private static func checkValidity(_ certificate: X509Certificate, now: Date) throws {
        guard now >= certificate.notBefore else { throw CertificateChainError.notYetValid }
        guard now <= certificate.notAfter else { throw CertificateChainError.expired }
    }
}

/// Single entry point used by the TLS handshake.
public enum CertificateAuthenticator {
    /// Returns the parsed leaf for `.strictChain` (needed to verify
    /// `CertificateVerify`), or `nil` for the MD5 pinning policy.
    public static func verify(
        chainDER: [[UInt8]],
        hostname: String,
        policy: CertificateValidationPolicy,
        now: Date = Date(),
        systemAnchors: X509TrustAnchors? = nil
    ) throws -> X509Certificate? {
        switch policy {
        case let .pinnedMD5(fingerprint):
            guard let leaf = chainDER.first else { throw CertificateChainError.emptyChain }
            try CertificatePinner(expectedFingerprint: fingerprint).verify(leafDER: leaf)
            return nil
        case let .strictChain(anchors):
            return try CertificateChainValidator.validate(
                chainDER: chainDER,
                hostname: hostname,
                anchors: anchors,
                now: now
            )
        case .systemTrust:
            return try verifySystemTrust(
                chainDER: chainDER,
                hostname: hostname,
                now: now,
                systemAnchors: systemAnchors
            )
        }
    }

    private static func verifySystemTrust(
        chainDER: [[UInt8]],
        hostname: String,
        now: Date,
        systemAnchors: X509TrustAnchors?
    ) throws -> X509Certificate {
        guard !chainDER.isEmpty else { throw CertificateChainError.emptyChain }
        let chain: [X509Certificate]
        do {
            chain = try chainDER.map { try X509Certificate(der: $0) }
        } catch {
            throw CertificateChainError.malformedCertificate
        }
        let leaf = chain[0]
        guard CertificateHostname.matches(leaf, hostname: hostname) else {
            throw CertificateChainError.hostnameMismatch(
                expected: hostname,
                present: leaf.dnsNames.isEmpty ? [leaf.commonName ?? ""] : leaf.dnsNames
            )
        }
        try CertificateChainValidator.checkLeaf(leaf, now: now)

        // An explicit anchor set always wins: it keeps the pure-Swift path
        // deterministic for tests and for callers that embed their own roots.
        if let systemAnchors {
            guard !systemAnchors.isEmpty else { throw CertificateChainError.noTrustAnchor }
            return try CertificateChainValidator.validate(
                chainDER: chainDER,
                hostname: hostname,
                anchors: systemAnchors,
                now: now
            )
        }
        #if canImport(Security)
        guard SystemTrustEvaluator.evaluate(chainDER: chainDER, hostname: hostname) else {
            throw CertificateChainError.untrustedRoot
        }
        return leaf
        #else
        let anchors = SystemTrustAnchors.shared
        guard !anchors.isEmpty else { throw CertificateChainError.noTrustAnchor }
        return try CertificateChainValidator.validate(
            chainDER: chainDER,
            hostname: hostname,
            anchors: anchors,
            now: now
        )
        #endif
    }
}
