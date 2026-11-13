import Foundation
import XCTest

@testable import FptnShared

final class LocalizationTests: XCTestCase {
    func testEveryKeyHasBothLocalizations() {
        let english = Localizer(language: .english)
        let russian = Localizer(language: .russian)
        for key in L10nKey.allCases {
            let en = english.text(key)
            let ru = russian.text(key)
            XCTAssertNotEqual(en, key.rawValue, "Missing English value for \(key.rawValue)")
            XCTAssertNotEqual(ru, key.rawValue, "Missing Russian value for \(key.rawValue)")
            XCTAssertFalse(en.isEmpty)
            XCTAssertFalse(ru.isEmpty)
        }
    }

    func testKeysAreUnique() {
        let rawValues = L10nKey.allCases.map(\.rawValue)
        XCTAssertEqual(Set(rawValues).count, rawValues.count)
    }

    func testEnglishAndRussianReturnDifferentText() {
        let english = Localizer(language: .english)
        let russian = Localizer(language: .russian)
        XCTAssertEqual(english.text(.settingsTitle), "Settings")
        XCTAssertEqual(russian.text(.settingsTitle), "Настройки")
    }

    func testFormattingUsesArguments() {
        let english = Localizer(language: .english)
        let russian = Localizer(language: .russian)
        XCTAssertEqual(english.text(.commonServersCount, 3), "Servers: 3")
        XCTAssertEqual(russian.text(.commonServersCount, 3), "Серверов: 3")
        XCTAssertEqual(
            russian.text(.tokenErrorInvalidServerHost, 2),
            "Сервер №2 имеет неверный хост."
        )
    }

    func testSystemLanguageUsesFirstPreferredLanguage() {
        XCTAssertEqual(
            AppLanguage.system.resolved(preferredLanguages: ["ru-RU", "en-US"]),
            .russian
        )
        XCTAssertEqual(
            AppLanguage.system.resolved(preferredLanguages: ["en-US"]),
            .english
        )
        XCTAssertEqual(
            AppLanguage.system.resolved(preferredLanguages: ["de-DE"]),
            .english
        )
        XCTAssertEqual(
            AppLanguage.system.resolved(preferredLanguages: []),
            .english
        )
    }

    func testExplicitLanguageOverridesPreferredLanguages() {
        XCTAssertEqual(
            AppLanguage.english.resolved(preferredLanguages: ["ru-RU"]),
            .english
        )
        XCTAssertEqual(
            AppLanguage.russian.resolved(preferredLanguages: ["en-US"]),
            .russian
        )
    }

    func testLocalizerCanBeConstructedFromAppLanguage() {
        let localizer = Localizer(
            language: .system,
            preferredLanguages: ["ru-RU"]
        )
        XCTAssertEqual(localizer.language, .russian)
        XCTAssertEqual(localizer.text(.tabTunnel), "Туннель")
    }
}
