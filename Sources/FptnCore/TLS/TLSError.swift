import Foundation

public enum TLSError: Error, Equatable, LocalizedError {
    case truncatedRecord
    case recordTooLarge(Int)
    case invalidRecordVersion(UInt16)
    case invalidRecordType(UInt8)
    case invalidHandshakeType(UInt8)
    case truncatedHandshake
    case handshakeTooLarge(Int)
    case unexpectedMessage(String)
    case unsupportedVersion(UInt16)
    case unsupportedCipherSuite(UInt16)
    case sessionIDMismatch
    case missingExtension(UInt16)
    case invalidExtension(UInt16)
    case invalidKeyShare
    case emptyCertificateChain
    case missingServerAuthentication
    case certificatePinMismatch(expected: String, actual: String)
    case certificateVerifyMismatch
    case serverFinishedMismatch
    case invalidAlert(level: UInt8, description: UInt8)
    case connectionClosed
    case sequenceNumberOverflow
    case invalidState(String)
    case invalidConfiguration(String)

    public var errorDescription: String? {
        switch self {
        case .truncatedRecord: return "TLS record is truncated."
        case let .recordTooLarge(size): return "TLS record is too large (\(size) bytes)."
        case let .invalidRecordVersion(version): return String(format: "Unsupported TLS record version 0x%04x.", version)
        case let .invalidRecordType(type): return "Unsupported TLS record type \(type)."
        case let .invalidHandshakeType(type): return "Unsupported TLS handshake type \(type)."
        case .truncatedHandshake: return "TLS handshake message is truncated."
        case let .handshakeTooLarge(size): return "TLS handshake message is too large (\(size) bytes)."
        case let .unexpectedMessage(name): return "Unexpected TLS handshake message: \(name)."
        case let .unsupportedVersion(version): return String(format: "Unsupported TLS version 0x%04x.", version)
        case let .unsupportedCipherSuite(suite): return String(format: "Unsupported TLS cipher suite 0x%04x.", suite)
        case .sessionIDMismatch: return "TLS server echoed a different session identifier."
        case let .missingExtension(type): return String(format: "Required TLS extension 0x%04x is missing.", type)
        case let .invalidExtension(type): return String(format: "TLS extension 0x%04x is malformed.", type)
        case .invalidKeyShare: return "TLS server sent an invalid key share."
        case .emptyCertificateChain: return "TLS server sent an empty certificate chain."
        case .missingServerAuthentication:
            return "No server authentication configured: supply an MD5 pin or strict X.509 trust anchors."
        case let .certificatePinMismatch(expected, actual):
            return "TLS certificate fingerprint mismatch: expected \(expected), got \(actual)."
        case .certificateVerifyMismatch: return "TLS CertificateVerify signature verification failed."
        case .serverFinishedMismatch: return "TLS server Finished verification failed."
        case let .invalidAlert(level, description):
            return "TLS alert received (level \(level), description \(description))."
        case .connectionClosed: return "TLS connection was closed by the peer."
        case .sequenceNumberOverflow: return "TLS record sequence number overflow."
        case let .invalidState(state): return "TLS client is in an invalid state: \(state)."
        case let .invalidConfiguration(reason): return "Invalid TLS configuration: \(reason)."
        }
    }
}
