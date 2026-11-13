import SwiftUI
import FptnShared

enum AppTheme: String, CaseIterable, Identifiable, Sendable {
    case aurora
    case ember

    var id: String { rawValue }

    var titleKey: L10nKey {
        switch self {
        case .aurora: return .themeAuroraTitle
        case .ember: return .themeEmberTitle
        }
    }

    var subtitleKey: L10nKey {
        switch self {
        case .aurora: return .themeAuroraSubtitle
        case .ember: return .themeEmberSubtitle
        }
    }

    var palette: ThemePalette {
        switch self {
        case .aurora: return .aurora
        case .ember: return .ember
        }
    }
}

struct ThemePalette {
    let backgroundTop: Color
    let backgroundBottom: Color
    let surface: Color
    let surfaceStrong: Color
    let accent: Color
    let accentSecondary: Color
    let textPrimary: Color
    let textSecondary: Color
    let success: Color
    let warning: Color
    let danger: Color

    var background: LinearGradient {
        LinearGradient(
            colors: [backgroundTop, backgroundBottom],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    var orb: AngularGradient {
        AngularGradient(
            colors: [accent, accentSecondary, accent, accentSecondary, accent],
            center: .center
        )
    }

    static let aurora = ThemePalette(
        backgroundTop: Color(red: 0.035, green: 0.075, blue: 0.11),
        backgroundBottom: Color(red: 0.015, green: 0.035, blue: 0.06),
        surface: Color.white.opacity(0.07),
        surfaceStrong: Color.white.opacity(0.12),
        accent: Color(red: 0.28, green: 0.92, blue: 0.82),
        accentSecondary: Color(red: 0.32, green: 0.58, blue: 1.0),
        textPrimary: Color(red: 0.93, green: 0.98, blue: 1.0),
        textSecondary: Color(red: 0.55, green: 0.68, blue: 0.76),
        success: Color(red: 0.35, green: 0.94, blue: 0.66),
        warning: Color(red: 1.0, green: 0.78, blue: 0.32),
        danger: Color(red: 1.0, green: 0.42, blue: 0.45)
    )

    static let ember = ThemePalette(
        backgroundTop: Color(red: 0.10, green: 0.075, blue: 0.065),
        backgroundBottom: Color(red: 0.035, green: 0.03, blue: 0.03),
        surface: Color.white.opacity(0.06),
        surfaceStrong: Color.white.opacity(0.11),
        accent: Color(red: 1.0, green: 0.62, blue: 0.28),
        accentSecondary: Color(red: 0.94, green: 0.31, blue: 0.24),
        textPrimary: Color(red: 1.0, green: 0.96, blue: 0.91),
        textSecondary: Color(red: 0.68, green: 0.60, blue: 0.54),
        success: Color(red: 0.49, green: 0.90, blue: 0.58),
        warning: Color(red: 1.0, green: 0.78, blue: 0.32),
        danger: Color(red: 1.0, green: 0.40, blue: 0.38)
    )
}

extension AppTheme {
    init(stored: String) {
        self = AppTheme(rawValue: stored) ?? .aurora
    }
}
