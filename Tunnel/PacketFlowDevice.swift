import Foundation
import NetworkExtension
import Darwin
import FptnCore

/// Blocking adapter around `NEPacketTunnelFlow`. NetworkExtension exposes an
/// asynchronous callback API; the relay loop is deliberately synchronous so the
/// same packet loop can be exercised with a fake device on Linux.
final class PacketFlowDevice: PacketSink {
    private let flow: NEPacketTunnelFlow

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func readPackets() throws -> [[UInt8]] {
        let semaphore = DispatchSemaphore(value: 0)
        var result: [[UInt8]] = []
        flow.readPackets { packets, _ in
            result = packets.map { [UInt8]($0) }
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }

    func writePackets(_ packets: [[UInt8]]) throws {
        guard !packets.isEmpty else { return }
        let data = packets.map { Data($0) }
        let protocols = packets.map { packet -> NSNumber in
            let isIPv6 = packet.first.map { $0 >> 4 == 6 } ?? false
            return NSNumber(value: isIPv6 ? AF_INET6 : AF_INET)
        }
        flow.writePackets(data, withProtocols: protocols)
    }
}
