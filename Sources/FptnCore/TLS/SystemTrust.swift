import Foundation

#if canImport(Security)
import Security
#endif

/// System-provided trust anchors. No CA bundle is vendored: a static copy goes
/// stale and drags a third-party licence into the app. Apple platforms use the
/// OS trust store; other platforms read the OS PEM bundle.
public enum SystemTrustAnchors {
    public static let defaultPaths: [String] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/local/etc/openssl/cert.pem"
    ]

    /// Cached once per process; parsing ~120 root certificates on every
    /// handshake would be needless work.
    public static let shared: X509TrustAnchors = load()

    public static func load(paths: [String] = defaultPaths) -> X509TrustAnchors {
        for path in paths {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  let ders = try? X509PEM.decodeCertificates(text),
                  !ders.isEmpty else { continue }
            let roots = ders.compactMap { try? X509Certificate(der: $0) }
                .filter(\.isCA)
            if !roots.isEmpty {
                return X509TrustAnchors(certificates: roots)
            }
        }
        return .empty
    }
}

#if canImport(Security)
/// Apple-only system trust evaluation. `SecTrust` uses the OS anchor store,
/// which iOS does not expose as an enumerable certificate list.
public enum SystemTrustEvaluator {
    public static func evaluate(chainDER: [[UInt8]], hostname: String) -> Bool {
        let certificates = chainDER.compactMap {
            SecCertificateCreateWithData(nil, Data($0) as CFData)
        }
        guard certificates.count == chainDER.count, !certificates.isEmpty else {
            return false
        }
        let policy = SecPolicyCreateSSL(true, hostname as CFString)
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(
            certificates as CFArray,
            policy,
            &trust
        )
        guard status == errSecSuccess, let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}
#endif
