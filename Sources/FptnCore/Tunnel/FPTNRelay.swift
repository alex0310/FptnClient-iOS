import Foundation

public protocol PacketSender: AnyObject {
    @discardableResult
    func send(packets: [[UInt8]]) throws -> Int
}

public protocol PacketSink: AnyObject {
    func writePackets(_ packets: [[UInt8]]) throws
}

extension FPTNClient: PacketSender {}

/// The platform-independent half of the relay loop. The iOS extension supplies
/// `NEPacketTunnelFlow` as the sink and `FPTNClient` as the sender; Linux tests
/// supply in-memory doubles.
public final class FPTNRelay {
    private let sender: PacketSender
    private let sink: PacketSink
    private let splitTunnel: SplitTunnel?
    private let routeStore: SplitTunnelRouteStore?
    private let onExcludedAddressesChanged: (() -> Void)?
    private let onInboundTraffic: ((_ bytes: Int, _ packets: Int) -> Void)?
    private let onOutboundTraffic: ((_ bytes: Int, _ packets: Int) -> Void)?

    public init(
        sender: PacketSender,
        sink: PacketSink,
        splitTunnel: SplitTunnel? = nil,
        routeStore: SplitTunnelRouteStore? = nil,
        onExcludedAddressesChanged: (() -> Void)? = nil,
        onInboundTraffic: ((_ bytes: Int, _ packets: Int) -> Void)? = nil,
        onOutboundTraffic: ((_ bytes: Int, _ packets: Int) -> Void)? = nil
    ) {
        self.sender = sender
        self.sink = sink
        self.splitTunnel = splitTunnel
        self.routeStore = routeStore
        self.onExcludedAddressesChanged = onExcludedAddressesChanged
        self.onInboundTraffic = onInboundTraffic
        self.onOutboundTraffic = onOutboundTraffic
    }

    /// Forwards TUN packets to the tunnel. A split-tunnel match either writes a
    /// TCP reset back to the TUN or silently drops the packet because its CIDR
    /// route already bypasses the tunnel. SNI matches also learn the destination
    /// so the extension can install a host excluded route for the retry.
    @discardableResult
    public func forwardOutgoing(_ packets: [[UInt8]]) throws -> Int {
        var forwarded: [[UInt8]] = []
        forwarded.reserveCapacity(packets.count)
        var learned: [IPAddress] = []
        for packet in packets {
            if let exclusion = splitTunnel?.outgoingExclusion(packet: packet) {
                if exclusion.reset != nil {
                    learned.append(exclusion.destination)
                }
                if let reset = exclusion.reset {
                    try sink.writePackets([reset])
                }
                continue
            }
            forwarded.append(packet)
        }
        record(learned)
        guard !forwarded.isEmpty else { return 0 }
        let sent = try sender.send(packets: forwarded)
        onOutboundTraffic?(byteCount(forwarded), sent)
        return sent
    }

    /// Writes incoming packets to the TUN. DNS answers for excluded domains are
    /// remembered before delivery so the next connection can use a host route.
    public func forwardIncoming(_ packets: [[UInt8]]) throws {
        guard !packets.isEmpty else { return }
        if let splitTunnel {
            var learned: [IPAddress] = []
            for packet in packets {
                learned.append(contentsOf: splitTunnel.incomingDNSExclusion(packet: packet))
            }
            record(learned)
        }
        try sink.writePackets(packets)
        onInboundTraffic?(byteCount(packets), packets.count)
    }

    private func byteCount(_ packets: [[UInt8]]) -> Int {
        packets.reduce(0) { $0 + $1.count }
    }

    private func record(_ addresses: [IPAddress]) {
        guard !addresses.isEmpty,
              let routeStore,
              routeStore.insert(addresses) else {
            return
        }
        onExcludedAddressesChanged?()
    }
}
