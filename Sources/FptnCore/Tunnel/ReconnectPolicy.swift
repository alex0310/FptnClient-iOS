import Foundation

/// Bounded reconnect budget used by the router client: at most `maxAttempts`
/// reconnects inside a sliding `window`, with exponential backoff capped at
/// `maximumDelay`. This prevents a broken server from turning into a hot loop.
public struct ReconnectPolicy: Equatable, Sendable {
    public let maxAttempts: Int
    public let window: TimeInterval
    public let baseDelay: TimeInterval
    public let maximumDelay: TimeInterval
    private var attempts: [TimeInterval] = []

    public init(
        maxAttempts: Int = 5,
        window: TimeInterval = 120,
        baseDelay: TimeInterval = 1,
        maximumDelay: TimeInterval = 30
    ) {
        self.maxAttempts = max(1, maxAttempts)
        self.window = max(0, window)
        self.baseDelay = max(0, baseDelay)
        self.maximumDelay = max(self.baseDelay, maximumDelay)
    }

    public var usedAttempts: Int { attempts.count }

    public mutating func canAttempt(at now: TimeInterval) -> Bool {
        prune(at: now)
        return attempts.count < maxAttempts
    }

    public mutating func recordAttempt(at now: TimeInterval) {
        prune(at: now)
        attempts.append(now)
    }

    public mutating func reset() {
        attempts.removeAll(keepingCapacity: true)
    }

    /// Delay before reconnect number `attempt` (zero-based).
    public func delay(forAttempt attempt: Int) -> TimeInterval {
        guard attempt > 0 else { return baseDelay }
        let exponent = min(attempt, 20)
        let value = baseDelay * pow(2, Double(exponent))
        return min(value, maximumDelay)
    }

    private mutating func prune(at now: TimeInterval) {
        let cutoff = now - window
        attempts.removeAll { $0 < cutoff }
    }
}
