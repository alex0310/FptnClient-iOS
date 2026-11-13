import Foundation

/// A point-in-time view of the tunnel's traffic counters. `sessionID` changes
/// on every reconnect so the app can discard a stale snapshot from a previous
/// tunnel session instead of showing a sudden jump in the totals.
public struct TrafficSnapshot: Codable, Equatable, Sendable {
    public let sessionID: UUID
    public let rxBytes: UInt64
    public let txBytes: UInt64
    public let rxPackets: UInt64
    public let txPackets: UInt64
    public let updatedAt: Date

    public init(
        sessionID: UUID = UUID(),
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0,
        rxPackets: UInt64 = 0,
        txPackets: UInt64 = 0,
        updatedAt: Date = Date()
    ) {
        self.sessionID = sessionID
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.rxPackets = rxPackets
        self.txPackets = txPackets
        self.updatedAt = updatedAt
    }

    public func adding(
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0,
        rxPackets: UInt64 = 0,
        txPackets: UInt64 = 0
    ) -> TrafficSnapshot {
        TrafficSnapshot(
            sessionID: sessionID,
            rxBytes: Self.clampedAdd(self.rxBytes, rxBytes),
            txBytes: Self.clampedAdd(self.txBytes, txBytes),
            rxPackets: Self.clampedAdd(self.rxPackets, rxPackets),
            txPackets: Self.clampedAdd(self.txPackets, txPackets),
            updatedAt: updatedAt
        )
    }

    public func stamped(at date: Date = Date()) -> TrafficSnapshot {
        TrafficSnapshot(
            sessionID: sessionID,
            rxBytes: rxBytes,
            txBytes: txBytes,
            rxPackets: rxPackets,
            txPackets: txPackets,
            updatedAt: date
        )
    }

    /// Average throughput between two snapshots of the same session. Returns
    /// `nil` when the session changed, time went backwards or the counters
    /// were reset in between.
    public func speed(relativeTo earlier: TrafficSnapshot) -> TrafficSpeed? {
        guard sessionID == earlier.sessionID else { return nil }
        let seconds = updatedAt.timeIntervalSince(earlier.updatedAt)
        guard seconds > 0,
              rxBytes >= earlier.rxBytes,
              txBytes >= earlier.txBytes else { return nil }
        return TrafficSpeed(
            rxBytesPerSecond: Double(rxBytes - earlier.rxBytes) / seconds,
            txBytesPerSecond: Double(txBytes - earlier.txBytes) / seconds
        )
    }

    static func clampedAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }
}

public struct TrafficSpeed: Equatable, Sendable {
    public let rxBytesPerSecond: Double
    public let txBytesPerSecond: Double

    public init(rxBytesPerSecond: Double, txBytesPerSecond: Double) {
        self.rxBytesPerSecond = rxBytesPerSecond
        self.txBytesPerSecond = txBytesPerSecond
    }
}
