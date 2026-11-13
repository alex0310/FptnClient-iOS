import Foundation

/// Deterministic, locale-independent formatting. The UI localizes only the
/// labels, never the unit strings, so snapshots and tests stay reproducible.
public enum TrafficFormatter {
    private static let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]

    public static func bytes(_ value: UInt64) -> String {
        var scalar = Double(value)
        var unit = 0
        while scalar >= 1024, unit < units.count - 1 {
            scalar /= 1024
            unit += 1
        }
        if unit == 0 { return "\(value) B" }
        return "\(rounded(scalar)) \(units[unit])"
    }

    public static func speed(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return "0 B/s" }
        var scalar = bytesPerSecond
        var unit = 0
        while scalar >= 1024, unit < units.count - 1 {
            scalar /= 1024
            unit += 1
        }
        if unit == 0 { return "\(Int(scalar.rounded())) B/s" }
        return "\(rounded(scalar)) \(units[unit])/s"
    }

    public static func packets(_ value: UInt64) -> String {
        "\(value)"
    }

    private static func rounded(_ value: Double) -> String {
        String(
            format: "%.1f",
            locale: Locale(identifier: "en_US_POSIX"),
            value
        )
    }
}
