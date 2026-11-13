import Foundation

/// A theme colour in sRGB space. Kept as plain numbers so the design tokens
/// can be asserted from Linux, without importing SwiftUI.
public struct ThemeColor: Equatable, Sendable {
    public let red: Double
    public let green: Double
    public let blue: Double
    public let alpha: Double

    public init(_ red: Double, _ green: Double, _ blue: Double, _ alpha: Double = 1) {
        self.red = red
        self.green = green
        self.blue = blue
        self.alpha = alpha
    }

    public var isInUnitRange: Bool {
        [red, green, blue, alpha].allSatisfy { $0 >= 0 && $0 <= 1 }
    }

    /// WCAG relative luminance (alpha is intentionally ignored: contrast is
    /// computed against the opaque background the colour sits on).
    public var relativeLuminance: Double {
        func linear(_ channel: Double) -> Double {
            channel <= 0.04045
                ? channel / 12.92
                : pow((channel + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(red)
            + 0.7152 * linear(green)
            + 0.0722 * linear(blue)
    }

    public var snapshotLine: String {
        String(
            format: "%.3f,%.3f,%.3f,%.3f",
            locale: Locale(identifier: "en_US_POSIX"),
            red, green, blue, alpha
        )
    }
}

/// The complete, platform-independent definition of a visual theme. Changing
/// any value here breaks the golden snapshot tests.
public struct ThemeTokens: Equatable, Sendable {
    public let name: String
    public let backgroundTop: ThemeColor
    public let backgroundBottom: ThemeColor
    public let surface: ThemeColor
    public let surfaceStrong: ThemeColor
    public let accent: ThemeColor
    public let accentSecondary: ThemeColor
    public let textPrimary: ThemeColor
    public let textSecondary: ThemeColor
    public let success: ThemeColor
    public let warning: ThemeColor
    public let danger: ThemeColor

    public init(
        name: String,
        backgroundTop: ThemeColor,
        backgroundBottom: ThemeColor,
        surface: ThemeColor,
        surfaceStrong: ThemeColor,
        accent: ThemeColor,
        accentSecondary: ThemeColor,
        textPrimary: ThemeColor,
        textSecondary: ThemeColor,
        success: ThemeColor,
        warning: ThemeColor,
        danger: ThemeColor
    ) {
        self.name = name
        self.backgroundTop = backgroundTop
        self.backgroundBottom = backgroundBottom
        self.surface = surface
        self.surfaceStrong = surfaceStrong
        self.accent = accent
        self.accentSecondary = accentSecondary
        self.textPrimary = textPrimary
        self.textSecondary = textSecondary
        self.success = success
        self.warning = warning
        self.danger = danger
    }

    /// Stable field order for golden files.
    public var labelledColors: [(String, ThemeColor)] {
        [
            ("backgroundTop", backgroundTop),
            ("backgroundBottom", backgroundBottom),
            ("surface", surface),
            ("surfaceStrong", surfaceStrong),
            ("accent", accent),
            ("accentSecondary", accentSecondary),
            ("textPrimary", textPrimary),
            ("textSecondary", textSecondary),
            ("success", success),
            ("warning", warning),
            ("danger", danger)
        ]
    }

    public var allColors: [ThemeColor] {
        labelledColors.map(\.1)
    }

    public var snapshot: String {
        var lines = ["theme \(name)"]
        for (label, color) in labelledColors {
            lines.append("\(label) \(color.snapshotLine)")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static let aurora = ThemeTokens(
        name: "aurora",
        backgroundTop: ThemeColor(0.035, 0.075, 0.11),
        backgroundBottom: ThemeColor(0.015, 0.035, 0.06),
        surface: ThemeColor(1, 1, 1, 0.07),
        surfaceStrong: ThemeColor(1, 1, 1, 0.12),
        accent: ThemeColor(0.28, 0.92, 0.82),
        accentSecondary: ThemeColor(0.32, 0.58, 1.0),
        textPrimary: ThemeColor(0.93, 0.98, 1.0),
        textSecondary: ThemeColor(0.55, 0.68, 0.76),
        success: ThemeColor(0.35, 0.94, 0.66),
        warning: ThemeColor(1.0, 0.78, 0.32),
        danger: ThemeColor(1.0, 0.42, 0.45)
    )

    public static let ember = ThemeTokens(
        name: "ember",
        backgroundTop: ThemeColor(0.10, 0.075, 0.065),
        backgroundBottom: ThemeColor(0.035, 0.03, 0.03),
        surface: ThemeColor(1, 1, 1, 0.06),
        surfaceStrong: ThemeColor(1, 1, 1, 0.11),
        accent: ThemeColor(1.0, 0.62, 0.28),
        accentSecondary: ThemeColor(0.94, 0.31, 0.24),
        textPrimary: ThemeColor(1.0, 0.96, 0.91),
        textSecondary: ThemeColor(0.68, 0.60, 0.54),
        success: ThemeColor(0.49, 0.90, 0.58),
        warning: ThemeColor(1.0, 0.78, 0.32),
        danger: ThemeColor(1.0, 0.40, 0.38)
    )
}

public enum ThemeContrast {
    /// WCAG contrast ratio between two colours, from 1 (identical) to 21.
    public static func ratio(_ lhs: ThemeColor, _ rhs: ThemeColor) -> Double {
        let first = lhs.relativeLuminance
        let second = rhs.relativeLuminance
        let lighter = max(first, second)
        let darker = min(first, second)
        return (lighter + 0.05) / (darker + 0.05)
    }
}
