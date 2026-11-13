import XCTest
import SwiftUI
import FptnShared

@testable import FptnClient

/// Real SwiftUI rendering tests, executed by `xcodebuild test` on the macOS
/// CI runner. They do not compare pixels against a device-specific reference
/// (fonts/SF Symbols differ per runtime); instead they assert that every theme
/// produces a non-empty rendered bitmap and that the two themes are visually
/// distinct. The exact design tokens are pinned by the Linux golden files.
@MainActor
final class ThemeRenderingTests: XCTestCase {
    private let localizer = Localizer(language: .english)

    func testEveryThemeRendersThemeSwatch() throws {
        for theme in AppTheme.allCases {
            let png = try render(
                ThemeSwatch(theme: theme, isSelected: false, localizer: localizer)
            )
            XCTAssertGreaterThan(png.count, 100, "\(theme.rawValue) swatch rendered empty")
        }
    }

    func testThemesProduceDifferentRenderedImages() throws {
        let aurora = try render(
            ThemeSwatch(theme: .aurora, isSelected: false, localizer: localizer)
        )
        let ember = try render(
            ThemeSwatch(theme: .ember, isSelected: false, localizer: localizer)
        )
        XCTAssertNotEqual(aurora, ember, "Aurora and Ember must not render identically")
    }

    func testSelectedSwatchRenders() throws {
        let png = try render(
            ThemeSwatch(theme: .aurora, isSelected: true, localizer: localizer)
        )
        XCTAssertGreaterThan(png.count, 100)
    }

    func testTrafficChartRendersForBothThemes() throws {
        var history = TrafficHistory()
        history.append(TrafficSample(rxBytesPerSecond: 2_048, txBytesPerSecond: 1_024))
        history.append(TrafficSample(rxBytesPerSecond: 4_096, txBytesPerSecond: 512))
        history.append(TrafficSample(rxBytesPerSecond: 1_024, txBytesPerSecond: 3_072))

        for theme in AppTheme.allCases {
            let png = try render(
                TrafficChartView(
                    history: history,
                    palette: ThemePalette(theme.tokens),
                    l10n: localizer
                )
            )
            XCTAssertGreaterThan(png.count, 100, "\(theme.rawValue) chart rendered empty")
        }
    }

    private func render<Content: View>(_ content: Content) throws -> Data {
        let renderer = ImageRenderer(
            content: content
                .frame(width: 260, height: 180)
                .background(Color.black)
        )
        renderer.scale = 1
        return try XCTUnwrap(
            renderer.uiImage?.pngData(),
            "ImageRenderer produced no image"
        )
    }
}
