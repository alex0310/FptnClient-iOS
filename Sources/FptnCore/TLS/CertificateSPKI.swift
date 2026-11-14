import Foundation

public enum CertificateSPKIError: Error, Equatable, LocalizedError {
    case malformedPin(String)
    case pinMismatch(expectedCount: Int, actual: String)

    public var errorDescription: String? {
        switch self {
        case let .malformedPin(value): return "Malformed SPKI SHA-256 pin: \(value)."
        case let .pinMismatch(count, actual):
            return "SPKI pin mismatch: none of \(count) pins matched \(actual)."
        }
    }
}

/// SHA-256 pinning of the DER `SubjectPublicKeyInfo`. Unlike an MD5 leaf pin
/// this is collision-resistant and survives certificate renewal with the same
/// key. Pins may be supplied as 64 hex digits or as base64.
public enum CertificateSPKI {
    public static func sha256(of certificate: X509Certificate) -> String {
        Hex.encode(Digests.sha256(certificate.subjectPublicKeyInfoDER))
    }

    /// Returns a lowercase 64-character hex digest, or `nil` if the pin is
    /// neither hex nor valid base64 of a 32-byte value.
    public static func normalized(_ pin: String) -> String? {
        let compact = pin.filter { !$0.isWhitespace && $0 != ":" }
        if compact.count == 64, compact.allSatisfy(\.isHexDigit) {
            return compact.lowercased()
        }
        // Base64 is case-sensitive, so it must be decoded before lowercasing.
        guard let data = Data(base64Encoded: compact), data.count == 32 else {
            return nil
        }
        return Hex.encode([UInt8](data))
    }

    public static func verify(
        certificate: X509Certificate,
        pins: [String]
    ) throws {
        guard !pins.isEmpty else { return }
        var normalizedPins: [String] = []
        for pin in pins {
            guard let normalized = normalized(pin) else {
                throw CertificateSPKIError.malformedPin(pin)
            }
            normalizedPins.append(normalized)
        }
        let actual = sha256(of: certificate)
        let matched = normalizedPins.contains { expected in
            Digests.constantTimeEquals(
                Array(expected.utf8),
                Array(actual.utf8)
            )
        }
        guard matched else {
            throw CertificateSPKIError.pinMismatch(
                expectedCount: normalizedPins.count,
                actual: actual
            )
        }
    }
}
