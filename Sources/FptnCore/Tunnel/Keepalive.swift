import Foundation

/// WebSocket keep-alive and dead-tunnel detection. The caller supplies a
/// monotonic clock in seconds, which keeps the state machine deterministic and
/// easy to test.
public struct Keepalive: Equatable, Sendable {
    public static let defaultPingIdle: TimeInterval = 15
    public static let defaultDeadAfter: TimeInterval = 90

    public static func deadAfter(for pingIdle: TimeInterval) -> TimeInterval {
        max(pingIdle * 6, 60)
    }

    public enum Action: Equatable, Sendable {
        case none
        case ping(idle: TimeInterval, sequence: UInt64)
    }

    public let pingIdle: TimeInterval
    public let deadAfter: TimeInterval
    private var lastOutbound: TimeInterval
    private var lastInbound: TimeInterval
    private var pingCount: UInt64 = 0
    private var pongCount: UInt64 = 0
    private var outstandingSince: TimeInterval?

    public init(
        now: TimeInterval,
        pingIdle: TimeInterval = Keepalive.defaultPingIdle,
        deadAfter: TimeInterval? = nil
    ) {
        self.pingIdle = max(0, pingIdle)
        self.deadAfter = max(0, deadAfter ?? Self.deadAfter(for: pingIdle))
        self.lastOutbound = now
        self.lastInbound = now
    }

    public var isEnabled: Bool {
        pingIdle > 0 && deadAfter > 0
    }

    public var pings: UInt64 { pingCount }
    public var pongs: UInt64 { pongCount }

    public mutating func sent(at now: TimeInterval) {
        lastOutbound = now
    }

    public mutating func received(at now: TimeInterval, pong: Bool) {
        lastInbound = now
        if pong {
            pongCount += 1
            outstandingSince = nil
        }
    }

    public func silentFor(at now: TimeInterval) -> TimeInterval {
        max(0, now - lastInbound)
    }

    public func quietFor(at now: TimeInterval) -> TimeInterval {
        max(0, now - lastOutbound)
    }

    public func unansweredFor(at now: TimeInterval) -> TimeInterval? {
        outstandingSince.map { max(0, now - $0) }
    }

    public mutating func poll(at now: TimeInterval) -> Action {
        guard pingIdle > 0 else { return .none }
        let idle = quietFor(at: now)
        guard idle >= pingIdle else { return .none }
        lastOutbound = now
        pingCount += 1
        if outstandingSince == nil {
            outstandingSince = now
        }
        return .ping(idle: idle, sequence: pingCount)
    }

    public func isDead(at now: TimeInterval) -> Bool {
        isEnabled && silentFor(at: now) >= deadAfter
    }
}
