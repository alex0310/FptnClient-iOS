import Foundation

/// IP packet address rewriting and checksum recalculation. This mirrors the
/// upstream `ip_utils` helper: the TUN keeps a stable local address, while the
/// server sees the VPN address it assigned.
public enum IPPacket {
    public static let protocolICMP: UInt8 = 1
    public static let protocolTCP: UInt8 = 6
    public static let protocolUDP: UInt8 = 17
    public static let protocolICMPv6: UInt8 = 58

    private static let minimumIPv4 = 20
    private static let minimumIPv6 = 40

    public static func version(of packet: [UInt8]) -> Int? {
        guard let first = packet.first else { return nil }
        return Int(first >> 4)
    }

    public static func sourcePort(of packet: [UInt8]) -> UInt16? {
        guard let first = packet.first else { return nil }
        switch first >> 4 {
        case 4:
            guard packet.count >= minimumIPv4, packet[9] == protocolTCP || packet[9] == protocolUDP else {
                return nil
            }
            let headerLength = Int(first & 0x0f) * 4
            guard headerLength >= minimumIPv4, packet.count >= headerLength + 4 else {
                return nil
            }
            return readU16BE(packet, headerLength)
        case 6:
            guard packet.count >= 44, packet[6] == protocolTCP || packet[6] == protocolUDP else {
                return nil
            }
            return readU16BE(packet, 40)
        default:
            return nil
        }
    }

    public static func setSourceIPv4(_ packet: inout [UInt8], address: UInt32) {
        guard packet.count >= minimumIPv4, packet[0] >> 4 == 4, packet[8] != 0 else { return }
        packet[12] = UInt8((address >> 24) & 0xff)
        packet[13] = UInt8((address >> 16) & 0xff)
        packet[14] = UInt8((address >> 8) & 0xff)
        packet[15] = UInt8(address & 0xff)
        recalculateChecksums(&packet)
    }

    public static func setDestinationIPv4(_ packet: inout [UInt8], address: UInt32) {
        guard packet.count >= minimumIPv4, packet[0] >> 4 == 4, packet[8] != 0 else { return }
        packet[16] = UInt8((address >> 24) & 0xff)
        packet[17] = UInt8((address >> 16) & 0xff)
        packet[18] = UInt8((address >> 8) & 0xff)
        packet[19] = UInt8(address & 0xff)
        recalculateChecksums(&packet)
    }

    public static func setSourceIPv6(_ packet: inout [UInt8], address: [UInt8]) {
        guard packet.count >= minimumIPv6, packet[0] >> 4 == 6, address.count == 16 else { return }
        packet.replaceSubrange(8..<24, with: address)
        recalculateChecksums(&packet)
    }

    public static func setDestinationIPv6(_ packet: inout [UInt8], address: [UInt8]) {
        guard packet.count >= minimumIPv6, packet[0] >> 4 == 6, address.count == 16 else { return }
        packet.replaceSubrange(24..<40, with: address)
        recalculateChecksums(&packet)
    }

    public static func rewriteOutgoing(
        _ packet: inout [UInt8],
        assignedIPv4: IPAddress?,
        assignedIPv6: IPAddress?
    ) {
        switch version(of: packet) {
        case 4:
            if case let .ipv4(value)? = assignedIPv4 {
                setSourceIPv4(&packet, address: value)
            }
        case 6:
            if case let .ipv6(bytes)? = assignedIPv6 {
                setSourceIPv6(&packet, address: bytes)
            }
        default:
            break
        }
    }

    public static func rewriteIncoming(
        _ packet: inout [UInt8],
        tunIPv4: IPAddress?,
        tunIPv6: IPAddress?
    ) {
        switch version(of: packet) {
        case 4:
            if case let .ipv4(value)? = tunIPv4 {
                setDestinationIPv4(&packet, address: value)
            }
        case 6:
            if case let .ipv6(bytes)? = tunIPv6 {
                setDestinationIPv6(&packet, address: bytes)
            }
        default:
            break
        }
    }

    public static func recalculateChecksums(_ packet: inout [UInt8]) {
        guard let first = packet.first else { return }
        switch first >> 4 {
        case 4:
            guard packet.count >= minimumIPv4 else { return }
            switch packet[9] {
            case protocolTCP: checksumTCPv4(&packet)
            case protocolUDP: checksumUDPv4(&packet)
            case protocolICMP: checksumICMPv4(&packet)
            default: break
            }
            checksumIPv4Header(&packet)
        case 6:
            guard packet.count >= minimumIPv6 else { return }
            switch packet[6] {
            case protocolTCP: checksumTCPv6(&packet)
            case protocolUDP: checksumUDPv6(&packet)
            case protocolICMPv6: checksumICMPv6(&packet)
            default: break
            }
        default:
            break
        }
    }

    // MARK: - IPv4 checksums

    private static func checksumIPv4Header(_ packet: inout [UInt8]) {
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard headerLength >= minimumIPv4, packet.count >= headerLength else { return }
        writeU16BE(&packet, 10, 0)
        writeU16BE(&packet, 10, rfc1071(packet[0..<headerLength]))
    }

    private static func checksumTCPv4(_ packet: inout [UInt8]) {
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard packet.count >= headerLength + 18 else { return }
        let total = Int(readU16BE(packet, 2))
        let tcpLength = min(max(0, total - headerLength), packet.count - headerLength)
        guard tcpLength >= 18 else { return }
        writeU16BE(&packet, headerLength + 16, 0)
        let sum = pseudoHeaderIPv4(packet, protocolNumber: protocolTCP, length: tcpLength)
        let checksum = rfc1071(
            packet[headerLength..<(headerLength + tcpLength)],
            seed: sum
        )
        writeU16BE(&packet, headerLength + 16, checksum)
    }

    private static func checksumUDPv4(_ packet: inout [UInt8]) {
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard packet.count >= headerLength + 8 else { return }
        let udpLength = Int(readU16BE(packet, headerLength + 4))
        guard udpLength >= 8, packet.count >= headerLength + udpLength else { return }
        writeU16BE(&packet, headerLength + 6, 0)
        let sum = pseudoHeaderIPv4(packet, protocolNumber: protocolUDP, length: udpLength)
        let checksum = rfc1071(packet[headerLength..<(headerLength + udpLength)], seed: sum)
        writeU16BE(&packet, headerLength + 6, checksum)
    }

    private static func checksumICMPv4(_ packet: inout [UInt8]) {
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard packet.count >= headerLength + 4 else { return }
        let total = Int(readU16BE(packet, 2))
        let icmpLength = min(max(0, total - headerLength), packet.count - headerLength)
        guard icmpLength >= 4 else { return }
        writeU16BE(&packet, headerLength + 2, 0)
        let checksum = rfc1071(packet[headerLength..<(headerLength + icmpLength)])
        writeU16BE(&packet, headerLength + 2, checksum)
    }

    private static func pseudoHeaderIPv4(
        _ packet: [UInt8],
        protocolNumber: UInt8,
        length: Int
    ) -> UInt32 {
        var sum = UInt32(0)
        sum += UInt32(readU16BE(packet, 12))
        sum += UInt32(readU16BE(packet, 14))
        sum += UInt32(readU16BE(packet, 16))
        sum += UInt32(readU16BE(packet, 18))
        sum += UInt32(protocolNumber)
        sum += UInt32(length)
        return sum
    }

    // MARK: - IPv6 checksums

    private static func checksumTCPv6(_ packet: inout [UInt8]) {
        guard packet.count >= minimumIPv6 + 18 else { return }
        let payloadLength = Int(readU16BE(packet, 4))
        let tcpLength = min(payloadLength, packet.count - minimumIPv6)
        guard tcpLength >= 18 else { return }
        writeU16BE(&packet, minimumIPv6 + 16, 0)
        let sum = pseudoHeaderIPv6(packet, nextHeader: protocolTCP, length: tcpLength)
        let checksum = rfc1071(
            packet[minimumIPv6..<(minimumIPv6 + tcpLength)],
            seed: sum
        )
        writeU16BE(&packet, minimumIPv6 + 16, checksum)
    }

    private static func checksumUDPv6(_ packet: inout [UInt8]) {
        guard packet.count >= minimumIPv6 + 8 else { return }
        let udpLength = Int(readU16BE(packet, minimumIPv6 + 4))
        guard udpLength >= 8, packet.count >= minimumIPv6 + udpLength else { return }
        writeU16BE(&packet, minimumIPv6 + 6, 0)
        let sum = pseudoHeaderIPv6(packet, nextHeader: protocolUDP, length: udpLength)
        let checksum = rfc1071(
            packet[minimumIPv6..<(minimumIPv6 + udpLength)],
            seed: sum
        )
        writeU16BE(&packet, minimumIPv6 + 6, checksum)
    }

    private static func checksumICMPv6(_ packet: inout [UInt8]) {
        guard packet.count >= minimumIPv6 + 4 else { return }
        let payloadLength = Int(readU16BE(packet, 4))
        let icmpLength = min(payloadLength, packet.count - minimumIPv6)
        guard icmpLength >= 4 else { return }
        writeU16BE(&packet, minimumIPv6 + 2, 0)
        let sum = pseudoHeaderIPv6(packet, nextHeader: protocolICMPv6, length: icmpLength)
        let checksum = rfc1071(
            packet[minimumIPv6..<(minimumIPv6 + icmpLength)],
            seed: sum
        )
        writeU16BE(&packet, minimumIPv6 + 2, checksum)
    }

    private static func pseudoHeaderIPv6(
        _ packet: [UInt8],
        nextHeader: UInt8,
        length: Int
    ) -> UInt32 {
        var sum = UInt32(0)
        for range in [8..<24, 24..<40] {
            var index = range.lowerBound
            while index + 1 < range.upperBound {
                sum += UInt32(readU16BE(packet, index))
                index += 2
            }
        }
        sum += UInt32((length >> 16) & 0xffff)
        sum += UInt32(length & 0xffff)
        sum += UInt32(nextHeader)
        return sum
    }

    // MARK: - RFC 1071

    private static func rfc1071(_ data: ArraySlice<UInt8>, seed: UInt32 = 0) -> UInt16 {
        var sum = UInt64(seed)
        var index = data.startIndex
        while index + 1 < data.endIndex {
            sum += (UInt64(data[index]) << 8) | UInt64(data[index + 1])
            index += 2
        }
        if index < data.endIndex {
            sum += UInt64(data[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return UInt16(~sum & 0xffff)
    }

    private static func readU16BE(_ packet: [UInt8], _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 1 < packet.count else { return 0 }
        return (UInt16(packet[offset]) << 8) | UInt16(packet[offset + 1])
    }

    private static func writeU16BE(_ packet: inout [UInt8], _ offset: Int, _ value: UInt16) {
        guard offset >= 0, offset + 1 < packet.count else { return }
        packet[offset] = UInt8((value >> 8) & 0xff)
        packet[offset + 1] = UInt8(value & 0xff)
    }
}
