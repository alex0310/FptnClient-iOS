import Foundation

public enum TunnelPoolStrategy: String, CaseIterable, Sendable {
    case dual
    case triple

    public var connectionCount: Int {
        switch self {
        case .dual: return 2
        case .triple: return 3
        }
    }

    public var stagger: TimeInterval {
        switch self {
        case .dual, .triple: return 15
        }
    }
}

public struct TunnelPoolConfiguration: Sendable {
    public var strategy: TunnelPoolStrategy
    public var lifetime: TimeInterval?
    public var replacementLead: TimeInterval
    public var keepaliveIdle: TimeInterval
    public var maxBatchSize: Int

    public init(
        strategy: TunnelPoolStrategy = .dual,
        lifetime: TimeInterval? = 600,
        replacementLead: TimeInterval = 60,
        keepaliveIdle: TimeInterval = Keepalive.defaultPingIdle,
        maxBatchSize: Int = 64
    ) {
        self.strategy = strategy
        self.lifetime = lifetime
        self.replacementLead = max(0, replacementLead)
        self.keepaliveIdle = max(0, keepaliveIdle)
        self.maxBatchSize = max(1, maxBatchSize)
    }
}

/// The small surface the pool needs from a connected tunnel. `FPTNTunnel`
/// conforms to it; tests can provide a deterministic fake.
public protocol PoolTunnel: AnyObject {
    var assignedIPv4: IPAddress? { get }
    var assignedIPv6: IPAddress? { get }
    var isClosed: Bool { get }
    func send(packets: [[UInt8]]) throws -> Int
    func receivePackets() throws -> [[UInt8]]
    func tick() throws -> FPTNTunnelStatus
    func close()
}

extension FPTNTunnel: PoolTunnel {}

public struct TunnelPoolSlot: Equatable {
    public let id: UInt64
    public let closeAt: TimeInterval
    public let assignedIPv4: IPAddress?
    public let assignedIPv6: IPAddress?
    public var tunnel: (any PoolTunnel)?

    public static func == (lhs: TunnelPoolSlot, rhs: TunnelPoolSlot) -> Bool {
        lhs.id == rhs.id && lhs.closeAt == rhs.closeAt
    }
}

public enum TunnelPoolError: Error, Equatable, LocalizedError {
    case noTunnel
    case connectorFailed
    case sendFailed

    public var errorDescription: String? {
        switch self {
        case .noTunnel: return "The tunnel pool has no healthy connection."
        case .connectorFailed: return "The tunnel pool could not open a replacement."
        case .sendFailed: return "The tunnel pool could not send packets."
        }
    }
}

/// Dual/triple rolling tunnel pool. It keeps `N` overlapping connections,
/// replaces each one before its scheduled close, pins a flow to a slot by
/// source port, and shares one `SessionID` across all connections.
///
/// The connector is synchronous so the pool remains deterministic and testable.
/// Production code should drive `maintain` from a background queue because a
/// reality-mode handshake can block for several seconds.
public final class TunnelPool {
    public static let defaultBaseLifetime: TimeInterval = 600

    public let configuration: TunnelPoolConfiguration
    public let sessionID: String
    private let connector: () throws -> any PoolTunnel
    private let clock: () -> TimeInterval
    private var slots: [TunnelPoolSlot] = []
    private var nextID: UInt64 = 1
    private var lastSpawn: TimeInterval?
    private var roundRobin = 0
    private var startedAt: TimeInterval

    public init(
        configuration: TunnelPoolConfiguration = TunnelPoolConfiguration(),
        sessionID: String = TunnelPool.randomSessionID(),
        connector: @escaping () throws -> any PoolTunnel,
        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.configuration = configuration
        self.sessionID = sessionID
        self.connector = connector
        self.clock = clock
        self.startedAt = clock()
    }

    public var activeSlots: [TunnelPoolSlot] { slots }

    public var desiredCount: Int { configuration.strategy.connectionCount }

    public var isEmpty: Bool { slots.isEmpty }

    /// Removes expired/dead slots and opens replacements until the desired
    /// number of healthy connections exists. A failed connector is retried
    /// after the stagger interval, matching the upstream pool.
    @discardableResult
    public func maintain(now: TimeInterval? = nil) -> Bool {
        let now = now ?? clock()
        slots.removeAll { slot in
            let dead = slot.tunnel?.isClosed ?? true
            if dead {
                slot.tunnel?.close()
            }
            return dead || slot.closeAt <= now
        }
        let healthy = slots.filter { $0.closeAt > now + configuration.replacementLead }.count
        guard healthy < desiredCount else { return false }
        if let lastSpawn, now - lastSpawn < configuration.strategy.stagger {
            return false
        }
        let replacedID = replacementCandidate(now: now)
        let lifetime = nextLifetime(now: now)
        lastSpawn = now
        do {
            let tunnel = try connector()
            let slot = TunnelPoolSlot(
                id: nextID,
                closeAt: now + lifetime,
                assignedIPv4: tunnel.assignedIPv4,
                assignedIPv6: tunnel.assignedIPv6,
                tunnel: tunnel
            )
            nextID += 1
            if let replacedID, let index = slots.firstIndex(where: { $0.id == replacedID }) {
                slots[index].tunnel?.close()
                slots[index] = slot
            } else {
                slots.append(slot)
            }
            return true
        } catch {
            return false
        }
    }

    /// Sends each packet through the slot selected by its source port. Packets
    /// without a transport source port fall back to round-robin. If a slot
    /// fails, the pool marks it closed and rethrows so the caller can maintain
    /// the pool.
    @discardableResult
    public func send(packets: [[UInt8]], now: TimeInterval? = nil) throws -> Int {
        let now = now ?? clock()
        if slots.isEmpty {
            maintain(now: now)
        }
        guard !slots.isEmpty else { throw TunnelPoolError.noTunnel }
        var groups: [UInt64: [[UInt8]]] = [:]
        for packet in packets {
            guard let slot = chooseSlot(for: packet, now: now) else { continue }
            groups[slot.id, default: []].append(packet)
        }
        var sent = 0
        for (id, packets) in groups {
            guard let index = slots.firstIndex(where: { $0.id == id }),
                  let tunnel = slots[index].tunnel else {
                continue
            }
            do {
                sent += try tunnel.send(packets: packets)
            } catch {
                tunnel.close()
                slots.remove(at: index)
                throw TunnelPoolError.sendFailed
            }
        }
        return sent
    }

    /// Advances keep-alive and lifetime state. Expired or dead slots are
    /// removed and replacements are requested immediately (subject to stagger).
    @discardableResult
    public func tick(now: TimeInterval? = nil) -> Bool {
        let now = now ?? clock()
        for index in slots.indices {
            guard let tunnel = slots[index].tunnel else { continue }
            do {
                let status = try tunnel.tick()
                if status != .active {
                    tunnel.close()
                    slots[index].tunnel = nil
                }
            } catch {
                tunnel.close()
                slots[index].tunnel = nil
            }
        }
        return maintain(now: now)
    }

    public func close() {
        for slot in slots {
            slot.tunnel?.close()
        }
        slots.removeAll()
    }

    public var isExpired: Bool {
        guard let lifetime = configuration.lifetime else { return false }
        return clock() - startedAt >= lifetime
    }

    // MARK: - Scheduling

    /// Port of upstream `NextLifetimeSeconds`: place a new connection so the
    /// pool closes sockets one at a time.
    public func nextLifetime(now: TimeInterval? = nil) -> TimeInterval {
        let now = now ?? clock()
        guard let lifetime = configuration.lifetime else {
            return 365 * 24 * 3600
        }
        let remaining = slots
            .map { Int(($0.closeAt - now).rounded(.down)) }
            .filter { $0 > 0 && TimeInterval($0) <= lifetime }
        return TimeInterval(Self.nextLifetimeSeconds(
            remaining: remaining,
            lifetime: Int(lifetime.rounded(.down)),
            count: desiredCount
        ))
    }

    public static func nextLifetimeSeconds(
        remaining: [Int],
        lifetime: Int,
        count: Int
    ) -> Int {
        let slot = max(lifetime / max(1, count), 1)
        if remaining.isEmpty || count == 1 {
            return slot
        }
        let sorted = remaining.sorted()
        let appended = (sorted.last ?? 0) + slot
        if appended <= lifetime {
            return appended
        }
        var widest = sorted[0]
        var result = max(widest / 2, 1)
        for index in 1..<sorted.count {
            let gap = sorted[index] - sorted[index - 1]
            if gap > widest {
                widest = gap
                result = max(sorted[index - 1] + gap / 2, 1)
            }
        }
        return result
    }

    private func replacementCandidate(now: TimeInterval) -> UInt64? {
        slots
            .filter { $0.closeAt <= now + configuration.replacementLead }
            .min(by: { $0.closeAt < $1.closeAt })?
            .id
    }

    private func chooseSlot(for packet: [UInt8], now: TimeInterval) -> TunnelPoolSlot? {
        let live = slots.indices.filter {
            slots[$0].tunnel != nil && slots[$0].closeAt > now
        }
        guard !live.isEmpty else { return nil }
        let start: Int
        if let port = IPPacket.sourcePort(of: packet) {
            start = Int(port) % live.count
        } else {
            start = roundRobin % live.count
            roundRobin &+= 1
        }
        let index = live[(start + live.count) % live.count]
        return slots[index]
    }

    // MARK: - Session ID

    public static func randomSessionID() -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
        let bytes = SecureRandom.bytes(64)
        return String(bytes: bytes.map { alphabet[Int($0) % alphabet.count] }, encoding: .utf8) ?? ""
    }
}
