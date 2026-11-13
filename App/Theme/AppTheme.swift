import SwiftUI
import FptnShared

/// SwiftUI adapter over the shared design tokens. There are deliberately no
/// colour literals here: every value comes from `ThemeTokens` in `FptnShared`,
/// which is covered by golden snapshot tests on Linux.
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

    init(_ tokens: ThemeTokens) {
        backgroundTop = Color(tokens.backgroundTop)
        backgroundBottom = Color(tokens.backgroundBottom)
        surface = Color(tokens.surface)
        surfaceStrong = Color(tokens.surfaceStrong)
        accent = Color(tokens.accent)
        accentSecondary = Color(tokens.accentSecondary)
        textPrimary = Color(tokens.textPrimary)
        textSecondary = Color(tokens.textSecondary)
        success = Color(tokens.success)
        warning = Color(tokens.warning)
        danger = Color(tokens.danger)
    }

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
}

private extension Color {
    init(_ token: ThemeColor) {
        self = Color(
            .sRGB,
            red: token.red,
            green: token.green,
            blue: token.blue,
            opacity: token.alpha
        )
    }
}
