import Foundation

/// Thread-safe accumulator used inside the packet-tunnel extension. Packet
/// reads and writes happen on different queues, so all mutable state is
/// protected by a single lock.
public final class TrafficCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TrafficSnapshot

    public init(sessionID: UUID = UUID()) {
        value = TrafficSnapshot(sessionID: sessionID)
    }

    public func recordInbound(bytes: Int, packets: Int = 1) {
        add(rxBytes: bytes, rxPackets: packets)
    }

    public func recordOutbound(bytes: Int, packets: Int = 1) {
        add(txBytes: bytes, txPackets: packets)
    }

    /// Returns a snapshot stamped with the current wall-clock time so the app
    /// can compute throughput from two consecutive reads.
    public func snapshot() -> TrafficSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return value.stamped()
    }

    /// Starts a new session; used when the tunnel reconnects.
    public func reset(sessionID: UUID = UUID()) -> TrafficSnapshot {
        lock.lock()
        defer { lock.unlock() }
        value = TrafficSnapshot(sessionID: sessionID)
        return value.stamped()
    }

    private func add(rxBytes: Int = 0, txBytes: Int = 0, rxPackets: Int = 0, txPackets: Int = 0) {
        let rx = UInt64(max(0, rxBytes))
        let tx = UInt64(max(0, txBytes))
        let rxCount = UInt64(max(0, rxPackets))
        let txCount = UInt64(max(0, txPackets))
        lock.lock()
        defer { lock.unlock() }
        value = value.adding(
            rxBytes: rx,
            txBytes: tx,
            rxPackets: rxCount,
            txPackets: txCount
        )
    }
}
