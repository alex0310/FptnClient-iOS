import XCTest

@testable import FptnCore

final class FPTNRelayTests: XCTestCase {
    private func icmpPacket(destination: [UInt8] = [8, 8, 8, 8]) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 24)
        packet[0] = 0x45
        packet[9] = IPPacket.protocolICMP
        packet.replaceSubrange(16..<20, with: destination)
        return packet
    }

    private func dnsResponse(domain: String, answers: [[UInt8]]) -> [UInt8] {
        var dns: [UInt8] = [0x12, 0x34, 0x81, 0x80]
        dns += be16(1)
        dns += be16(answers.count)
        dns += be16(0) + be16(0)
        for label in domain.split(separator: ".") {
            dns.append(UInt8(label.utf8.count))
            dns += Array(label.utf8)
        }
        dns.append(0)
        dns += be16(1) + be16(1)
        for answer in answers {
            dns += [0xc0, 0x0c]
            dns += be16(1) + be16(1)
            dns += [0, 0, 0, 60]
            dns += be16(answer.count)
            dns += answer
        }

        let total = 20 + 8 + dns.count
        var packet = [UInt8](repeating: 0, count: total)
        packet[0] = 0x45
        packet[2] = UInt8((total >> 8) & 0xff)
        packet[3] = UInt8(total & 0xff)
        packet[8] = 64
        packet[9] = IPPacket.protocolUDP
        packet.replaceSubrange(12..<16, with: [172, 20, 0, 1])
        packet.replaceSubrange(16..<20, with: [10, 0, 0, 2])
        packet[20] = 0x00
        packet[21] = 0x35
        packet[22] = 0x9c
        packet[23] = 0x40
        packet[24] = UInt8(((8 + dns.count) >> 8) & 0xff)
        packet[25] = UInt8((8 + dns.count) & 0xff)
        packet.replaceSubrange(28..<total, with: dns)
        return packet
    }

    private func be16(_ value: Int) -> [UInt8] {
        [UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
    }

    private func tcpHelloPacket(sni: String) throws -> [UInt8] {
        let handshake = try TLSClientHelloBuilder(
            serverName: sni,
            random: [UInt8](repeating: 1, count: 32),
            sessionID: [],
            keyShare: [UInt8](repeating: 2, count: 32)
        ).build().encoded()
        let hello = [0x16, 0x03, 0x01, UInt8((handshake.count >> 8) & 0xff), UInt8(handshake.count & 0xff)] + handshake
        let total = 20 + 20 + hello.count
        var packet = [UInt8](repeating: 0, count: total)
        packet[0] = 0x45
        packet[2] = UInt8((total >> 8) & 0xff)
        packet[3] = UInt8(total & 0xff)
        packet[8] = 64
        packet[9] = IPPacket.protocolTCP
        packet.replaceSubrange(12..<16, with: [10, 0, 0, 2])
        packet.replaceSubrange(16..<20, with: [1, 2, 3, 4])
        packet[20] = 0x9c
        packet[21] = 0x40
        packet[22] = 0x01
        packet[23] = 0xbb
        packet[24...27] = [0, 0, 0, 1]
        packet[28...31] = [0, 0, 0, 2]
        packet[32] = 0x50
        packet[33] = 0x18
        packet.replaceSubrange(40..<total, with: hello)
        return packet
    }

    func testForwardOutgoingWithoutSplitSendsEverything() throws {
        let sender = RelaySender()
        let sink = RelaySink()
        let relay = FPTNRelay(sender: sender, sink: sink)
        let packets = [icmpPacket(), icmpPacket(destination: [1, 1, 1, 1])]
        XCTAssertEqual(try relay.forwardOutgoing(packets), 2)
        XCTAssertEqual(sender.packets.count, 2)
        XCTAssertTrue(sink.packets.isEmpty)
    }

    func testCIDRExclusionDropsPacketWithoutReset() throws {
        let sender = RelaySender()
        let sink = RelaySink()
        let split = try SplitTunnel(cidrs: ["10.0.0.0/8"])
        let relay = FPTNRelay(sender: sender, sink: sink, splitTunnel: split)
        XCTAssertEqual(try relay.forwardOutgoing([icmpPacket(destination: [10, 1, 2, 3])]), 0)
        XCTAssertTrue(sender.packets.isEmpty)
        XCTAssertTrue(sink.packets.isEmpty)
    }

    func testSNIExclusionWritesResetAndSkipsPacket() throws {
        let sender = RelaySender()
        let sink = RelaySink()
        let split = try SplitTunnel(rules: ["example.com"])
        let relay = FPTNRelay(sender: sender, sink: sink, splitTunnel: split)
        let packet = try tcpHelloPacket(sni: "www.example.com")
        XCTAssertEqual(try relay.forwardOutgoing([packet]), 0)
        XCTAssertTrue(sender.packets.isEmpty)
        XCTAssertEqual(sink.packets.count, 1)
        XCTAssertEqual(sink.packets[0].count, 40)
    }

    func testForwardIncomingWritesAllPackets() throws {
        let sender = RelaySender()
        let sink = RelaySink()
        let relay = FPTNRelay(sender: sender, sink: sink)
        let packets = [icmpPacket(), icmpPacket(destination: [4, 4, 4, 4])]
        try relay.forwardIncoming(packets)
        XCTAssertEqual(sink.packets, packets)
        XCTAssertTrue(sender.packets.isEmpty)
    }

    func testForwardIncomingEmptyDoesNothing() throws {
        let sink = RelaySink()
        let relay = FPTNRelay(sender: RelaySender(), sink: sink)
        try relay.forwardIncoming([])
        XCTAssertTrue(sink.packets.isEmpty)
    }

    func testDNSResponseLearnsExcludedAddresses() throws {
        let sink = RelaySink()
        let store = SplitTunnelRouteStore()
        var changes = 0
        let split = try SplitTunnel(rules: ["example.com"])
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: sink,
            splitTunnel: split,
            routeStore: store,
            onExcludedAddressesChanged: { changes += 1 }
        )
        let packet = dnsResponse(
            domain: "www.example.com",
            answers: [[1, 2, 3, 4], [5, 6, 7, 8]]
        )

        try relay.forwardIncoming([packet])

        XCTAssertEqual(
            store.snapshot(),
            [IPAddress("1.2.3.4")!, IPAddress("5.6.7.8")!]
        )
        XCTAssertEqual(changes, 1)
        XCTAssertEqual(sink.packets, [packet])
    }

    func testDNSResponseForOtherDomainDoesNotLearnAddresses() throws {
        let store = SplitTunnelRouteStore()
        var changes = 0
        let split = try SplitTunnel(rules: ["example.com"])
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            splitTunnel: split,
            routeStore: store,
            onExcludedAddressesChanged: { changes += 1 }
        )

        try relay.forwardIncoming([
            dnsResponse(domain: "other.net", answers: [[1, 2, 3, 4]])
        ])

        XCTAssertTrue(store.snapshot().isEmpty)
        XCTAssertEqual(changes, 0)
    }

    func testSNIExclusionLearnsDestinationRoute() throws {
        let store = SplitTunnelRouteStore()
        var changes = 0
        let split = try SplitTunnel(rules: ["example.com"])
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            splitTunnel: split,
            routeStore: store,
            onExcludedAddressesChanged: { changes += 1 }
        )

        _ = try relay.forwardOutgoing([tcpHelloPacket(sni: "www.example.com")])

        XCTAssertEqual(store.snapshot(), [IPAddress("1.2.3.4")!])
        XCTAssertEqual(changes, 1)
    }

    func testDuplicateLearnedAddressNotifiesOnlyOnce() throws {
        let store = SplitTunnelRouteStore()
        var changes = 0
        let split = try SplitTunnel(rules: ["example.com"])
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            splitTunnel: split,
            routeStore: store,
            onExcludedAddressesChanged: { changes += 1 }
        )
        let packet = dnsResponse(domain: "www.example.com", answers: [[1, 2, 3, 4]])

        try relay.forwardIncoming([packet])
        try relay.forwardIncoming([packet])

        XCTAssertEqual(store.snapshot(), [IPAddress("1.2.3.4")!])
        XCTAssertEqual(changes, 1)
    }

    // MARK: - Traffic accounting

    func testTrafficCallbacksCountForwardedBytesAndPackets() throws {
        var outbound = (bytes: 0, packets: 0)
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            onOutboundTraffic: { bytes, packets in
                outbound.bytes += bytes
                outbound.packets += packets
            }
        )
        let packets = [icmpPacket(), icmpPacket(destination: [4, 4, 4, 4])]

        XCTAssertEqual(try relay.forwardOutgoing(packets), 2)
        XCTAssertEqual(outbound.bytes, packets.reduce(0) { $0 + $1.count })
        XCTAssertEqual(outbound.packets, 2)
    }

    func testTrafficCallbacksIgnoreSplitExcludedOutgoingPackets() throws {
        var outbound = (bytes: 0, packets: 0)
        let split = try SplitTunnel(cidrs: ["10.0.0.0/8"])
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            splitTunnel: split,
            onOutboundTraffic: { bytes, packets in
                outbound.bytes += bytes
                outbound.packets += packets
            }
        )
        let excluded = icmpPacket(destination: [10, 1, 2, 3])
        let forwarded = icmpPacket(destination: [8, 8, 8, 8])

        XCTAssertEqual(try relay.forwardOutgoing([excluded, forwarded]), 1)
        XCTAssertEqual(outbound.bytes, forwarded.count)
        XCTAssertEqual(outbound.packets, 1)
    }

    func testTrafficCallbacksCountIncomingBytesAndPackets() throws {
        var inbound = (bytes: 0, packets: 0)
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            onInboundTraffic: { bytes, packets in
                inbound.bytes += bytes
                inbound.packets += packets
            }
        )
        let packets = [icmpPacket(), icmpPacket(destination: [4, 4, 4, 4])]

        try relay.forwardIncoming(packets)
        XCTAssertEqual(inbound.bytes, packets.reduce(0) { $0 + $1.count })
        XCTAssertEqual(inbound.packets, 2)
    }

    func testTrafficCallbacksSkipEmptyBatches() throws {
        var calls = 0
        let relay = FPTNRelay(
            sender: RelaySender(),
            sink: RelaySink(),
            onInboundTraffic: { _, _ in calls += 1 },
            onOutboundTraffic: { _, _ in calls += 1 }
        )
        XCTAssertEqual(try relay.forwardOutgoing([]), 0)
        try relay.forwardIncoming([])
        XCTAssertEqual(calls, 0)
    }

    func testOutboundTrafficIsNotRecordedWhenSenderFails() throws {
        var outbound = (bytes: 0, packets: 0)
        let relay = FPTNRelay(
            sender: FailingSender(),
            sink: RelaySink(),
            onOutboundTraffic: { bytes, packets in
                outbound.bytes += bytes
                outbound.packets += packets
            }
        )
        XCTAssertThrowsError(try relay.forwardOutgoing([icmpPacket()]))
        XCTAssertEqual(outbound.bytes, 0)
        XCTAssertEqual(outbound.packets, 0)
    }
}

private final class FailingSender: PacketSender {
    func send(packets: [[UInt8]]) throws -> Int {
        throw TransportError.timeout
    }
}

private final class RelaySender: PacketSender {
    private(set) var packets: [[UInt8]] = []

    func send(packets: [[UInt8]]) throws -> Int {
        self.packets.append(contentsOf: packets)
        return packets.count
    }
}

private final class RelaySink: PacketSink {
    private(set) var packets: [[UInt8]] = []

    func writePackets(_ packets: [[UInt8]]) throws {
        self.packets.append(contentsOf: packets)
    }
}
