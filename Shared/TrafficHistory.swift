import Foundation

/// One point of the live throughput chart, produced once per app poll.
public struct TrafficSample: Equatable, Sendable {
    public let timestamp: Date
    public let rxBytesPerSecond: Double
    public let txBytesPerSecond: Double

    public init(
        timestamp: Date = Date(),
        rxBytesPerSecond: Double,
        txBytesPerSecond: Double
    ) {
        self.timestamp = timestamp
        self.rxBytesPerSecond = rxBytesPerSecond
        self.txBytesPerSecond = txBytesPerSecond
    }
}

/// A fixed-size ring of the most recent speed samples. The history lives in
/// the app process: a live-speed chart is only meaningful while the app is in
/// the foreground, so there is no need to persist it in the App Group.
public struct TrafficHistory: Equatable, Sendable {
    public let limit: Int
    public private(set) var samples: [TrafficSample]

    /// Sixty samples at one poll per second = a rolling one-minute window.
    public init(limit: Int = 60) {
        self.limit = max(2, limit)
        self.samples = []
    }

    public var count: Int { samples.count }
    public var isEmpty: Bool { samples.isEmpty }

    public mutating func append(_ sample: TrafficSample) {
        if samples.count >= limit {
            samples.removeFirst(samples.count - limit + 1)
        }
        samples.append(sample)
    }

    public mutating func reset() {
        samples.removeAll(keepingCapacity: true)
    }
}
