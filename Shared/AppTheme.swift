import Foundation

/// The two visual themes. Design tokens live here so the app and the Linux
/// test suite agree on exactly the same colours; `ThemePalette` in the app
/// target only maps them onto `SwiftUI.Color`.
public enum AppTheme: String, CaseIterable, Identifiable, Sendable {
    case aurora
    case ember

    public var id: String { rawValue }

    public var titleKey: L10nKey {
        switch self {
        case .aurora: return .themeAuroraTitle
        case .ember: return .themeEmberTitle
        }
    }

    public var subtitleKey: L10nKey {
        switch self {
        case .aurora: return .themeAuroraSubtitle
        case .ember: return .themeEmberSubtitle
        }
    }

    public var tokens: ThemeTokens {
        switch self {
        case .aurora: return .aurora
        case .ember: return .ember
        }
    }

    /// Unknown or corrupted stored values fall back to the default theme.
    public init(stored: String) {
        self = AppTheme(rawValue: stored) ?? .aurora
    }
}
