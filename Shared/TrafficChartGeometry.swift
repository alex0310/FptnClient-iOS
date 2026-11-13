import Foundation

/// A chart point in normalized coordinates: `x` grows from 0 to 1, `y` is 0
/// at the top of the chart and 1 at the bottom (matching SwiftUI's y axis).
public struct TrafficChartPoint: Equatable, Sendable {
    public let x: Double
    public let rxY: Double
    public let txY: Double
}

/// Platform-independent scale calculation. Keeping it out of SwiftUI lets the
/// macOS CI build stay a thin rendering layer and makes the math testable on
/// Linux.
public enum TrafficChartScale {
    /// Rounds a value up to the next 1/2/5 x 10^n, so the axis does not jitter
    /// on every poll. Non-finite and non-positive values produce 0.
    public static func niceCeiling(_ value: Double) -> Double {
        guard value.isFinite, value > 0 else { return 0 }
        let magnitude = pow(10, floor(log10(value)))
        let normalized = value / magnitude
        let step: Double
        if normalized <= 1 {
            step = 1
        } else if normalized <= 2 {
            step = 2
        } else if normalized <= 5 {
            step = 5
        } else {
            step = 10
        }
        return step * magnitude
    }

    /// Largest finite, non-negative speed in the window.
    public static func peak(for samples: [TrafficSample]) -> Double {
        samples.reduce(0) { current, sample in
            max(current, max(sanitized(sample.rxBytesPerSecond), sanitized(sample.txBytesPerSecond)))
        }
    }

    /// The chart's ceiling: at least `minimum` so an idle tunnel still shows a
    /// stable baseline instead of amplifying noise.
    public static func scale(for samples: [TrafficSample], minimum: Double = 1_024) -> Double {
        max(niceCeiling(peak(for: samples)), max(0, minimum))
    }

    private static func sanitized(_ value: Double) -> Double {
        guard value.isFinite, value > 0 else { return 0 }
        return value
    }
}

public enum TrafficChartGeometry {
    public static func points(
        for samples: [TrafficSample],
        scale: Double
    ) -> [TrafficChartPoint] {
        guard !samples.isEmpty else { return [] }
        let last = Double(max(1, samples.count - 1))
        return samples.enumerated().map { index, sample in
            TrafficChartPoint(
                x: Double(index) / last,
                rxY: normalized(sample.rxBytesPerSecond, scale: scale),
                txY: normalized(sample.txBytesPerSecond, scale: scale)
            )
        }
    }

    private static func normalized(_ value: Double, scale: Double) -> Double {
        guard scale > 0, value.isFinite, value > 0 else { return 1 }
        return 1 - min(1, value / scale)
    }
}
