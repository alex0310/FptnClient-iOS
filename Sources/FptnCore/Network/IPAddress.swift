import Foundation

/// Platform-independent IPv4/IPv6 address. IPv4 is stored in host order so
/// prefix masks are simple integer operations; IPv6 is stored as 16 bytes.
public enum IPAddress: Equatable, Hashable, Sendable {
    case ipv4(UInt32)
    case ipv6([UInt8])

    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains(":") {
            guard let bytes = Self.parseIPv6(trimmed) else { return nil }
            self = .ipv6(bytes)
        } else {
            guard let value = Self.parseIPv4(trimmed) else { return nil }
            self = .ipv4(value)
        }
    }

    public var bytes: [UInt8] {
        switch self {
        case let .ipv4(value):
            return [
                UInt8((value >> 24) & 0xff),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ]
        case let .ipv6(bytes):
            return bytes
        }
    }

    public var text: String {
        switch self {
        case let .ipv4(value):
            return "\(value >> 24).\((value >> 16) & 0xff).\((value >> 8) & 0xff).\(value & 0xff)"
        case let .ipv6(bytes):
            return Self.formatIPv6(bytes)
        }
    }

    public var isIPv4: Bool {
        if case .ipv4 = self { return true }
        return false
    }

    public var isIPv6: Bool {
        if case .ipv6 = self { return true }
        return false
    }

    // MARK: - IPv4

    private static func parseIPv4(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, let octet = UInt8(part) else {
                return nil
            }
            value = (value << 8) | UInt32(octet)
        }
        return value
    }

    // MARK: - IPv6

    private static func parseIPv6(_ text: String) -> [UInt8]? {
        guard !text.isEmpty, !text.contains(":::") else { return nil }
        let compressionParts = text.components(separatedBy: "::")
        guard compressionParts.count <= 2 else { return nil }
        let hasCompression = compressionParts.count == 2

        guard let left = parseIPv6Groups(compressionParts[0]) else { return nil }
        let right: [UInt16]
        if hasCompression {
            guard let parsed = parseIPv6Groups(compressionParts[1]) else { return nil }
            right = parsed
        } else {
            right = []
        }

        let total = left.count + right.count
        if hasCompression {
            guard total < 8 else { return nil }
        } else {
            guard total == 8 else { return nil }
        }
        let zeros = hasCompression ? 8 - total : 0
        let groups = left + Array(repeating: UInt16(0), count: zeros) + right
        guard groups.count == 8 else { return nil }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for group in groups {
            bytes.append(UInt8((group >> 8) & 0xff))
            bytes.append(UInt8(group & 0xff))
        }
        return bytes
    }

    private static func parseIPv6Groups(_ text: String) -> [UInt16]? {
        guard !text.isEmpty else { return [] }
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        var groups: [UInt16] = []
        groups.reserveCapacity(parts.count)
        for part in parts {
            guard !part.isEmpty else { return nil }
            if part.contains(".") {
                guard let value = parseIPv4(String(part)) else { return nil }
                groups.append(UInt16((value >> 16) & 0xffff))
                groups.append(UInt16(value & 0xffff))
            } else {
                guard part.count <= 4, let value = UInt16(part, radix: 16) else {
                    return nil
                }
                groups.append(value)
            }
        }
        return groups
    }

    private static func formatIPv6(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return "" }
        var groups: [UInt16] = []
        groups.reserveCapacity(8)
        for index in stride(from: 0, to: 16, by: 2) {
            groups.append((UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1]))
        }

        var bestStart = -1
        var bestLength = 0
        var index = 0
        while index < groups.count {
            guard groups[index] == 0 else {
                index += 1
                continue
            }
            var end = index
            while end < groups.count && groups[end] == 0 {
                end += 1
            }
            let length = end - index
            if length > bestLength && length >= 2 {
                bestStart = index
                bestLength = length
            }
            index = end
        }

        func render(_ range: Range<Int>) -> String {
            range.map { String(groups[$0], radix: 16) }.joined(separator: ":")
        }

        if bestStart < 0 {
            return render(0..<8)
        }
        let left = render(0..<bestStart)
        let right = render((bestStart + bestLength)..<8)
        return "\(left)::\(right)"
    }
}

/// CIDR prefix used by the split-tunnel matcher.
public struct IPPrefix: Equatable, Hashable, Sendable {
    public let address: IPAddress
    public let prefixLength: Int

    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        guard let address = IPAddress(String(parts[0])) else { return nil }
        if parts.count == 2 {
            guard let length = Int(parts[1]) else { return nil }
            self.prefixLength = length
        } else {
            self.prefixLength = address.isIPv4 ? 32 : 128
        }
        let maximum = address.isIPv4 ? 32 : 128
        guard (0...maximum).contains(self.prefixLength) else { return nil }
        self.address = address
    }

    public init(address: IPAddress, prefixLength: Int) {
        self.address = address
        self.prefixLength = prefixLength
    }

    public func contains(_ candidate: IPAddress) -> Bool {
        switch (address, candidate) {
        case let (.ipv4(network), .ipv4(value)):
            guard prefixLength > 0 else { return true }
            let mask: UInt32 = prefixLength >= 32 ? .max : ~(UInt32.max >> UInt32(prefixLength))
            return (network & mask) == (value & mask)
        case let (.ipv6(network), .ipv6(value)):
            guard network.count == 16, value.count == 16 else { return false }
            var bits = prefixLength
            for index in 0..<16 {
                if bits <= 0 { return true }
                let take = min(8, bits)
                let mask: UInt8 = take >= 8 ? 0xff : UInt8((0xff << (8 - take)) & 0xff)
                if (network[index] & mask) != (value[index] & mask) { return false }
                bits -= take
            }
            return true
        default:
            return false
        }
    }
}
