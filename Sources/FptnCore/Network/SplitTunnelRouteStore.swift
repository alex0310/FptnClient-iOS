import Foundation

/// Bounded, thread-safe set of addresses learned from split-tunnel DNS answers
/// or TLS SNI. The packet-tunnel extension converts these addresses into host
/// excluded routes so matching domains bypass the VPN.
public final class SplitTunnelRouteStore: @unchecked Sendable {
    public static let defaultCapacity = 4096

    private let lock = NSLock()
    private let capacity: Int
    private var order: [IPAddress] = []
    private var seen: Set<IPAddress> = []

    public init(capacity: Int = SplitTunnelRouteStore.defaultCapacity) {
        self.capacity = max(1, capacity)
    }

    /// Inserts addresses in discovery order. Returns `true` when at least one
    /// new address was added; duplicates are ignored.
    @discardableResult
    public func insert(_ addresses: [IPAddress]) -> Bool {
        guard !addresses.isEmpty else { return false }
        lock.lock()
        defer { lock.unlock() }

        var changed = false
        for address in addresses where seen.insert(address).inserted {
            order.append(address)
            changed = true
        }

        if order.count > capacity {
            let overflow = order.count - capacity
            let removed = order.prefix(overflow)
            order.removeFirst(overflow)
            seen.subtract(removed)
        }
        return changed
    }

    /// Snapshot in discovery order. The caller may use it to rebuild
    /// `NEIPv4Route`/`NEIPv6Route` excluded routes.
    public func snapshot() -> [IPAddress] {
        lock.lock()
        defer { lock.unlock() }
        return order
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return order.count
    }
}
