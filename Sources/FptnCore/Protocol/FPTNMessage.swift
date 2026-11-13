import Foundation

public enum FPTNErrorKind: Equatable, Sendable {
    case defaultError
    case wrongVersion
    case sessionExpired
    case unknown(Int32)

    public init(rawValue: Int32) {
        switch rawValue {
        case 0: self = .defaultError
        case 1: self = .wrongVersion
        case 2: self = .sessionExpired
        default: self = .unknown(rawValue)
        }
    }

    public var rawValue: Int32 {
        switch self {
        case .defaultError: return 0
        case .wrongVersion: return 1
        case .sessionExpired: return 2
        case let .unknown(value): return value
        }
    }
}

/// A decoded FPTN control/data message. Addresses in `ipAssignment` are the
/// textual IPv4/IPv6 addresses sent by the server.
public enum FPTNMessage: Equatable, Sendable {
    case batch([[UInt8]])
    case ipPacket([UInt8])
    case ipAssignment(ipv4: String, ipv6: String)
    case error(kind: FPTNErrorKind, message: String)

    public static func decode(_ data: [UInt8]) -> FPTNMessage? {
        guard let incoming = YAFF.parseMessage(data) else { return nil }
        switch incoming {
        case let .batch(packets):
            return .batch(packets)
        case let .ipPacket(packet):
            return .ipPacket(packet)
        case let .ipAssignment(ipv4, ipv6):
            guard let v4 = Self.addressString(ipv4), let v6 = Self.addressString(ipv6) else {
                return nil
            }
            return .ipAssignment(ipv4: v4, ipv6: v6)
        case let .error(errorType, message):
            return .error(kind: FPTNErrorKind(rawValue: errorType), message: message)
        }
    }

    public static func encodeBatch(_ packets: [[UInt8]]) -> [UInt8]? {
        YAFF.serializeBatchMessage(packets.map { YAFF.IPPacketData(payload: $0) })
    }

    public static func encodeAssignment(ipv4: String, ipv6: String) -> [UInt8] {
        YAFF.serializeIpAssignmentMessage(
            ipv4: Array(ipv4.utf8),
            ipv6: Array(ipv6.utf8)
        )
    }

    public static func encodeError(kind: FPTNErrorKind, message: String) -> [UInt8] {
        YAFF.serializeErrorMessage(errorType: kind.rawValue, message: message)
    }

    /// The server sends textual addresses, but the reference YAFF vectors use
    /// raw address bytes. Accept both forms.
    private static func addressString(_ bytes: [UInt8]) -> String? {
        if bytes.count == 4 {
            let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            return IPAddress.ipv4(value).text
        }
        if bytes.count == 16 {
            return IPAddress.ipv6(bytes).text
        }
        let text = String(decoding: bytes, as: UTF8.self)
        guard !text.isEmpty else { return nil }
        return text
    }
}
