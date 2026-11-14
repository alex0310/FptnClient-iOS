import Foundation

public enum X509PEMError: Error, Equatable, LocalizedError {
    case missingEndMarker
    case invalidBase64

    public var errorDescription: String? {
        switch self {
        case .missingEndMarker: return "PEM certificate has no END CERTIFICATE marker."
        case .invalidBase64: return "PEM certificate contains invalid base64."
        }
    }
}

/// Minimal PEM decoder for root bundles. Deliberately ignores comments, blank
/// lines and any block that is not a CERTIFICATE.
public enum X509PEM {
    private static let begin = "-----BEGIN CERTIFICATE-----"
    private static let end = "-----END CERTIFICATE-----"

    public static func decodeCertificates(_ text: String) throws -> [[UInt8]] {
        var result: [[UInt8]] = []
        var current: [String] = []
        var inside = false
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line == begin {
                inside = true
                current = []
                continue
            }
            if line == end {
                guard inside else { continue }
                inside = false
                let base64 = current.joined()
                guard let data = Data(base64Encoded: base64) else {
                    throw X509PEMError.invalidBase64
                }
                result.append([UInt8](data))
                continue
            }
            guard inside, !line.isEmpty, !line.hasPrefix("#") else { continue }
            // Bundles use either LF or CRLF line endings; strip all whitespace
            // before reassembling the base64 payload.
            current.append(line.filter { !$0.isWhitespace })
        }
        guard !inside else { throw X509PEMError.missingEndMarker }
        return result
    }
}
