import Foundation
import XCTest

@testable import FptnShared

/// Golden-file snapshots of both visual themes. The reference files live in
/// `Tests/FptnSharedTests/Snapshots/` and are compared, never rewritten by a
/// test, so any colour change fails CI until the design change is reviewed.
final class ThemeSnapshotTests: XCTestCase {
    func testGoldenSnapshotsMatchThemeTokens() throws {
        for theme in AppTheme.allCases {
            let url = try XCTUnwrap(
                Bundle.module.url(
                    forResource: theme.rawValue,
                    withExtension: "theme",
                    subdirectory: "Snapshots"
                ),
                "Missing golden snapshot for \(theme.rawValue)"
            )
            let golden = try String(contentsOf: url, encoding: .utf8)
            XCTAssertEqual(
                theme.tokens.snapshot,
                golden,
                "Theme \(theme.rawValue) changed; review and update its golden file"
            )
        }
    }

    func testSnapshotCoversEveryDesignToken() {
        for theme in AppTheme.allCases {
            let lines = theme.tokens.snapshot.split(separator: "\n")
            XCTAssertEqual(lines.count, theme.tokens.labelledColors.count + 1)
            XCTAssertEqual(String(lines.first ?? ""), "theme \(theme.rawValue)")
        }
    }

    func testSnapshotIsDeterministic() {
        XCTAssertEqual(ThemeTokens.aurora.snapshot, ThemeTokens.aurora.snapshot)
        XCTAssertNotEqual(ThemeTokens.aurora.snapshot, ThemeTokens.ember.snapshot)
    }

    func testThemesAreDistinct() {
        XCTAssertEqual(AppTheme.allCases.count, 2)
        XCTAssertNotEqual(ThemeTokens.aurora, ThemeTokens.ember)
        XCTAssertEqual(Set(AppTheme.allCases.map(\.rawValue)).count, 2)
    }

    func testAllThemeColorsAreInUnitRange() {
        for theme in AppTheme.allCases {
            for color in theme.tokens.allColors {
                XCTAssertTrue(color.isInUnitRange, "Invalid component in \(theme.rawValue)")
            }
        }
    }

    func testStoredThemeFallsBackToAurora() {
        XCTAssertEqual(AppTheme(stored: "aurora"), .aurora)
        XCTAssertEqual(AppTheme(stored: "ember"), .ember)
        XCTAssertEqual(AppTheme(stored: "unknown"), .aurora)
        XCTAssertEqual(AppTheme(stored: ""), .aurora)
    }

    func testEveryThemeHasLocalizedTitleAndSubtitle() {
        for language in ResolvedLanguage.allCases {
            let localizer = Localizer(language: language)
            for theme in AppTheme.allCases {
                for key in [theme.titleKey, theme.subtitleKey] {
                    let text = localizer.text(key)
                    XCTAssertNotEqual(text, key.rawValue, "\(key.rawValue) missing in \(language.rawValue)")
                    XCTAssertFalse(text.isEmpty)
                }
            }
        }
    }

    // MARK: - Accessibility

    func testPrimaryTextMeetsWCAGAAOnBothBackgrounds() {
        for theme in AppTheme.allCases {
            let tokens = theme.tokens
            for background in [tokens.backgroundTop, tokens.backgroundBottom] {
                XCTAssertGreaterThanOrEqual(
                    ThemeContrast.ratio(tokens.textPrimary, background),
                    4.5,
                    "\(theme.rawValue): primary text contrast too low"
                )
            }
        }
    }

    func testSecondaryTextMeetsLargeTextThreshold() {
        for theme in AppTheme.allCases {
            let tokens = theme.tokens
            for background in [tokens.backgroundTop, tokens.backgroundBottom] {
                XCTAssertGreaterThanOrEqual(
                    ThemeContrast.ratio(tokens.textSecondary, background),
                    3.0,
                    "\(theme.rawValue): secondary text contrast too low"
                )
            }
        }
    }

    func testContrastRatioIsSymmetricAndBounded() {
        let black = ThemeColor(0, 0, 0)
        let white = ThemeColor(1, 1, 1)
        XCTAssertEqual(ThemeContrast.ratio(black, white), 21, accuracy: 0.001)
        XCTAssertEqual(ThemeContrast.ratio(white, black), 21, accuracy: 0.001)
        XCTAssertEqual(ThemeContrast.ratio(black, black), 1, accuracy: 0.001)
    }
}
