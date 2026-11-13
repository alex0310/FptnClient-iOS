import Foundation

public enum SplitTunnelPolicy: String, CaseIterable, Sendable {
    case exclude
    case include
}

public enum SplitTunnelError: Error, Equatable, LocalizedError {
    case invalidCIDR(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidCIDR(value): return "Invalid split-tunnel CIDR: \(value)"
        }
    }
}

public struct SplitTunnelExclusion: Equatable, Sendable {
    public let destination: IPAddress
    /// A TCP RST to feed back into the TUN so the local client reconnects over
    /// the direct route. `nil` when the destination was excluded by CIDR.
    public let reset: [UInt8]?

    public init(destination: IPAddress, reset: [UInt8]?) {
        self.destination = destination
        self.reset = reset
    }
}

/// Split-tunnel matcher: CIDR bypass for the routing layer, plus domain rules
/// for SNI/DNS-driven bypass. Domain rules match at a label boundary, so
/// `vk.com` matches `m.vk.com` but not `notvk.com`.
public struct SplitTunnel: Sendable {
    public let rules: Set<String>
    public let cidrs: [IPPrefix]
    public let policy: SplitTunnelPolicy
    public let enabled: Bool

    public init(
        rules: [String] = [],
        cidrs: [String] = [],
        policy: SplitTunnelPolicy = .exclude,
        enabled: Bool = true
    ) throws {
        self.rules = Set(rules.map(Self.normalizeRule).filter { !$0.isEmpty })
        self.cidrs = try cidrs.map { value in
            guard let prefix = IPPrefix(value) else {
                throw SplitTunnelError.invalidCIDR(value)
            }
            return prefix
        }
        self.policy = policy
        self.enabled = enabled
    }

    public var ruleCount: Int { rules.count }

    public func matches(domain: String) -> Bool {
        guard !rules.isEmpty else { return false }
        let lower = Self.normalizeRule(domain)
        guard !lower.isEmpty else { return false }
        var start = lower.startIndex
        while start < lower.endIndex {
            if rules.contains(String(lower[start...])) {
                return true
            }
            guard let dot = lower[start...].firstIndex(of: ".") else { return false }
            start = lower.index(after: dot)
        }
        return false
    }

    public func needsExclude(domain: String) -> Bool {
        guard enabled else { return false }
        let matched = matches(domain: domain)
        return policy == .exclude ? matched : !matched
    }

    public func shouldBypass(address: IPAddress) -> Bool {
        enabled && cidrs.contains { $0.contains(address) }
    }

    /// Inspects an outgoing TUN packet. A matching TLS SNI produces a RST; a
    /// destination covered by a CIDR rule is excluded without a reset.
    public func outgoingExclusion(packet: [UInt8]) -> SplitTunnelExclusion? {
        guard enabled else { return nil }
        if let destination = Self.destinationIPv4(packet), shouldBypass(address: destination) {
            return SplitTunnelExclusion(destination: destination, reset: nil)
        }
        guard Self.isIPv4(packet), Self.protocolNumber(packet) == IPPacket.protocolTCP,
              let payload = Self.tcpPayload(packet),
              Self.isTLSClientHello(payload),
              let sni = Self.tlsSNI(payload),
              needsExclude(domain: sni),
              let destination = Self.destinationIPv4(packet) else {
            return nil
        }
        return SplitTunnelExclusion(
            destination: destination,
            reset: Self.makeTCPReset(packet)
        )
    }

    /// Inspects an incoming DNS response and returns the A/AAAA answers whose
    /// question name is covered by the domain rules.
    public func incomingDNSExclusion(packet: [UInt8]) -> [IPAddress] {
        guard enabled, Self.dnsOffset(packet) != nil,
              let domain = Self.dnsDomain(packet),
              needsExclude(domain: domain) else {
            return []
        }
        return Self.dnsAddresses(packet)
    }

    // MARK: - Normalization

    public static func normalizeRule(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.hasPrefix("domain:") {
            value = String(value.dropFirst("domain:".count))
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if value.hasPrefix("*.") {
            value = String(value.dropFirst(2))
        }
        while value.hasSuffix(".") {
            value.removeLast()
        }
        return value
    }

    // MARK: - IP helpers

    static func isIPv4(_ packet: [UInt8]) -> Bool {
        !packet.isEmpty && packet[0] >> 4 == 4
    }

    static func isIPv6(_ packet: [UInt8]) -> Bool {
        !packet.isEmpty && packet[0] >> 4 == 6
    }

    static func protocolNumber(_ packet: [UInt8]) -> UInt8? {
        if isIPv4(packet) {
            return packet.count >= 20 ? packet[9] : nil
        }
        if isIPv6(packet) {
            return packet.count >= 40 ? packet[6] : nil
        }
        return nil
    }

    static func destinationIPv4(_ packet: [UInt8]) -> IPAddress? {
        guard isIPv4(packet), packet.count >= 20 else { return nil }
        let value = UInt32(packet[16]) << 24
            | UInt32(packet[17]) << 16
            | UInt32(packet[18]) << 8
            | UInt32(packet[19])
        return .ipv4(value)
    }

    static func tcpPayload(_ packet: [UInt8]) -> ArraySlice<UInt8>? {
        guard protocolNumber(packet) == IPPacket.protocolTCP else { return nil }
        let ipHeader = isIPv4(packet) ? Int(packet[0] & 0x0f) * 4 : 40
        guard packet.count >= ipHeader + 20 else { return nil }
        let tcpHeader = Int(packet[ipHeader + 12] >> 4) * 4
        guard tcpHeader >= 20, packet.count >= ipHeader + tcpHeader else { return nil }
        return packet[(ipHeader + tcpHeader)...]
    }

    // MARK: - TLS

    static func isTLSClientHello(_ data: ArraySlice<UInt8>) -> Bool {
        guard data.count >= 6, data.first == 0x16 else { return false }
        let bytes = Array(data)
        let version = UInt16(bytes[1]) << 8 | UInt16(bytes[2])
        return (0x0301...0x0304).contains(version) && bytes[5] == 0x01
    }

    static func tlsSNI(_ payload: ArraySlice<UInt8>) -> String? {
        let data = Array(payload)
        var position = 43
        guard position < data.count else { return nil }
        position += 1 + Int(data[position])
        guard position + 2 <= data.count else { return nil }
        position += 2 + Int(UInt16(data[position]) << 8 | UInt16(data[position + 1]))
        guard position < data.count else { return nil }
        position += 1 + Int(data[position])
        guard position + 2 <= data.count else { return nil }
        let extensionsEnd = position + 2
            + Int(UInt16(data[position]) << 8 | UInt16(data[position + 1]))
        position += 2
        guard extensionsEnd <= data.count else { return nil }

        while position + 4 <= extensionsEnd {
            let type = UInt16(data[position]) << 8 | UInt16(data[position + 1])
            let length = Int(UInt16(data[position + 2]) << 8 | UInt16(data[position + 3]))
            position += 4
            guard position + length <= extensionsEnd else { return nil }
            if type == 0x0000, length >= 5 {
                let nameLength = Int(UInt16(data[position + 3]) << 8 | UInt16(data[position + 4]))
                guard position + 5 + nameLength <= extensionsEnd else { return nil }
                let start = position + 5
                return String(decoding: data[start..<(start + nameLength)], as: UTF8.self)
                    .lowercased()
            }
            position += length
        }
        return nil
    }

    // MARK: - TCP reset

    public static func makeTCPReset(_ packet: [UInt8]) -> [UInt8]? {
        guard isIPv4(packet), protocolNumber(packet) == IPPacket.protocolTCP else { return nil }
        let ipHeader = Int(packet[0] & 0x0f) * 4
        guard packet.count >= ipHeader + 20 else { return nil }
        let tcpHeader = Int(packet[ipHeader + 12] >> 4) * 4
        guard packet.count >= ipHeader + tcpHeader else { return nil }
        let sequence = readU32(packet, ipHeader + 4)
        let acknowledgement = readU32(packet, ipHeader + 8)
        let payloadLength = UInt32(packet.count - ipHeader - tcpHeader)

        var reset = [UInt8](repeating: 0, count: 40)
        reset[0] = 0x45
        writeU16(&reset, 2, 40)
        reset[8] = 64
        reset[9] = IPPacket.protocolTCP
        reset.replaceSubrange(12..<16, with: packet[16..<20])
        reset.replaceSubrange(16..<20, with: packet[12..<16])
        writeU16(&reset, 20, readU16(packet, ipHeader + 2))
        writeU16(&reset, 22, readU16(packet, ipHeader))
        writeU32(&reset, 24, acknowledgement)
        writeU32(&reset, 28, sequence &+ payloadLength)
        reset[32] = 0x50
        reset[33] = 0x14
        IPPacket.recalculateChecksums(&reset)
        return reset
    }

    // MARK: - DNS

    static func dnsOffset(_ packet: [UInt8]) -> Int? {
        guard protocolNumber(packet) == IPPacket.protocolUDP else { return nil }
        let ipHeader = isIPv4(packet) ? Int(packet[0] & 0x0f) * 4 : 40
        guard packet.count >= ipHeader + 8 else { return nil }
        let sourcePort = readU16(packet, ipHeader)
        let destinationPort = readU16(packet, ipHeader + 2)
        guard sourcePort == 53 || destinationPort == 53 else { return nil }
        let offset = ipHeader + 8
        guard packet.count >= offset + 12 else { return nil }
        return offset
    }

    static func dnsDomain(_ packet: [UInt8]) -> String? {
        guard let offset = dnsOffset(packet), packet.count >= offset + 12 else { return nil }
        guard readU16(packet, offset + 4) != 0 else { return nil }
        let dns = Array(packet[offset...])
        let (name, _) = parseDNSName(dns, 12)
        return name.isEmpty ? nil : name.lowercased()
    }

    static func dnsAddresses(_ packet: [UInt8]) -> [IPAddress] {
        guard let offset = dnsOffset(packet) else { return [] }
        let dns = Array(packet[offset...])
        guard let (start, count) = dnsAnswerStart(dns) else { return [] }
        var cursor = start
        var output: [IPAddress] = []
        for _ in 0..<count {
            guard cursor < dns.count, skipDNSName(dns, &cursor), dns.count - cursor >= 10 else {
                break
            }
            let type = readU16(dns, cursor)
            cursor += 8
            let length = Int(readU16(dns, cursor))
            cursor += 2
            guard dns.count - cursor >= length else { break }
            if type == 1, length == 4 {
                let value = UInt32(dns[cursor]) << 24
                    | UInt32(dns[cursor + 1]) << 16
                    | UInt32(dns[cursor + 2]) << 8
                    | UInt32(dns[cursor + 3])
                output.append(.ipv4(value))
            } else if type == 28, length == 16 {
                output.append(.ipv6(Array(dns[cursor..<(cursor + 16)])))
            }
            cursor += length
        }
        return output
    }

    static func parseDNSName(_ data: [UInt8], _ start: Int) -> (String, Int) {
        var name = ""
        var jumped = false
        var pointer = start
        var next = start
        for _ in 0..<128 {
            guard pointer < data.count else { break }
            let length = data[pointer]
            if length == 0 {
                if !jumped { next = pointer + 1 }
                break
            }
            if length & 0xc0 == 0xc0 {
                guard pointer + 1 < data.count else { break }
                if !jumped { next = pointer + 2 }
                jumped = true
                let offset = (Int(length & 0x3f) << 8) | Int(data[pointer + 1])
                guard offset < data.count else { break }
                pointer = offset
                continue
            }
            pointer += 1
            guard data.count - pointer >= Int(length) else { break }
            if !name.isEmpty { name.append(".") }
            name += String(decoding: data[pointer..<(pointer + Int(length))], as: UTF8.self)
            pointer += Int(length)
        }
        return (name, next)
    }

    static func skipDNSName(_ data: [UInt8], _ cursor: inout Int) -> Bool {
        for _ in 0..<256 {
            guard cursor < data.count else { return false }
            let length = data[cursor]
            if length == 0 {
                cursor += 1
                return true
            }
            let compressed = length & 0xc0 == 0xc0
            let step = compressed ? 2 : 1 + Int(length)
            guard data.count - cursor >= step else { return false }
            cursor += step
            if compressed { return true }
        }
        return false
    }

    static func dnsAnswerStart(_ dns: [UInt8]) -> (Int, Int)? {
        guard dns.count >= 12, dns[2] & 0x80 != 0 else { return nil }
        let questions = Int(readU16(dns, 4))
        let answers = Int(readU16(dns, 6))
        guard answers > 0 else { return nil }
        var cursor = 12
        for _ in 0..<questions {
            guard cursor < dns.count, skipDNSName(dns, &cursor), dns.count - cursor >= 4 else {
                return nil
            }
            cursor += 4
        }
        return cursor < dns.count ? (cursor, answers) : nil
    }

    // MARK: - Byte helpers

    private static func readU16(_ data: [UInt8], _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 1 < data.count else { return 0 }
        return UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private static func readU32(_ data: [UInt8], _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 3 < data.count else { return 0 }
        return UInt32(data[offset]) << 24
            | UInt32(data[offset + 1]) << 16
            | UInt32(data[offset + 2]) << 8
            | UInt32(data[offset + 3])
    }

    private static func writeU16(_ data: inout [UInt8], _ offset: Int, _ value: UInt16) {
        guard offset >= 0, offset + 1 < data.count else { return }
        data[offset] = UInt8((value >> 8) & 0xff)
        data[offset + 1] = UInt8(value & 0xff)
    }

    private static func writeU32(_ data: inout [UInt8], _ offset: Int, _ value: UInt32) {
        guard offset >= 0, offset + 3 < data.count else { return }
        data[offset] = UInt8((value >> 24) & 0xff)
        data[offset + 1] = UInt8((value >> 16) & 0xff)
        data[offset + 2] = UInt8((value >> 8) & 0xff)
        data[offset + 3] = UInt8(value & 0xff)
    }
}
