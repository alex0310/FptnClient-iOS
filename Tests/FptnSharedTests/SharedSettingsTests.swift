import XCTest

@testable import FptnShared

final class SharedSettingsTests: XCTestCase {
    func testDefaultSettingsAreStable() {
        let settings = SharedSettings()
        XCTAssertEqual(settings.strategy, "dual")
        XCTAssertEqual(settings.securityMode, "obfuscated")
        XCTAssertEqual(settings.theme, "aurora")
        XCTAssertEqual(settings.language, .system)
        XCTAssertTrue(settings.onDemandEnabled)
        XCTAssertTrue(settings.splitTunnelEnabled)
        XCTAssertEqual(settings.splitCIDRs, SharedSettings.defaultSplitCIDRs)
        XCTAssertEqual(settings.splitDomains, [])
        XCTAssertNil(settings.preferredServerID)
    }

    func testMandatorySplitCIDRsCoverLocalAndSystemTraffic() {
        let required = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8"
        ]
        for cidr in required {
            XCTAssertTrue(
                SharedSettings.mandatorySplitCIDRs.contains(cidr),
                "missing mandatory CIDR \(cidr)"
            )
        }
    }

    func testEffectiveSplitCIDRsAlwaysIncludeMandatory() {
        let custom = "203.0.113.0/24"
        let settings = SharedSettings(splitCIDRs: [custom, "10.0.0.0/8"])
        let effective = settings.effectiveSplitCIDRs

        for cidr in SharedSettings.mandatorySplitCIDRs {
            XCTAssertTrue(effective.contains(cidr), "missing mandatory CIDR \(cidr)")
        }
        XCTAssertTrue(effective.contains(custom))
        XCTAssertEqual(Set(effective).count, effective.count)
        XCTAssertEqual(effective.count, SharedSettings.mandatorySplitCIDRs.count + 1)
        XCTAssertEqual(settings.splitCIDRs, [custom, "10.0.0.0/8"])
    }

    func testEffectiveSplitCIDRsTrimAndSkipBlankEntries() {
        let settings = SharedSettings(splitCIDRs: [" 203.0.113.0/24 ", "", "   "])
        let effective = settings.effectiveSplitCIDRs
        XCTAssertTrue(effective.contains("203.0.113.0/24"))
        XCTAssertFalse(effective.contains(""))
        XCTAssertFalse(effective.contains("   "))
    }

    func testCodableRoundTripPreservesAllFields() throws {
        let settings = SharedSettings(
            strategy: "triple",
            securityMode: "reality",
            theme: "ember",
            language: .russian,
            onDemandEnabled: false,
            splitTunnelEnabled: false,
            splitCIDRs: ["192.168.0.0/16"],
            splitDomains: ["example.com"],
            preferredServerID: "vpn.example.com:443"
        )
        let data = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(SharedSettings.self, from: data)
        XCTAssertEqual(decoded, settings)
    }

    func testDecodesLegacyPayloadWithoutDomains() throws {
        let json = """
        {
          "token": "fptn:legacy",
          "strategy": "dual",
          "securityMode": "plain",
          "theme": "aurora",
          "splitTunnelEnabled": true,
          "splitCIDRs": ["10.0.0.0/8"]
        }
        """
        let settings = try JSONDecoder().decode(
            SharedSettings.self,
            from: Data(json.utf8)
        )
        XCTAssertEqual(settings.strategy, "dual")
        XCTAssertEqual(settings.securityMode, "plain")
        XCTAssertEqual(settings.language, .system)
        XCTAssertTrue(settings.onDemandEnabled)
        XCTAssertEqual(settings.splitDomains, [])
        XCTAssertNil(settings.preferredServerID)
    }

    func testEncodedSettingsDoNotContainToken() throws {
        let data = try JSONEncoder().encode(SharedSettings())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertNil(object["token"])
    }

    func testLegacyTokenIsReadAndClearedFromSettingsBlob() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer {
            defaults.removePersistentDomain(forName: suite)
        }
        let json = """
        {
          "token": "  fptn:legacy  ",
          "strategy": "dual",
          "securityMode": "plain",
          "theme": "aurora",
          "splitTunnelEnabled": true,
          "splitCIDRs": ["10.0.0.0/8"]
        }
        """
        defaults.set(Data(json.utf8), forKey: SharedStore.key)

        XCTAssertEqual(SharedStore.loadLegacyToken(defaults: defaults), "fptn:legacy")
        XCTAssertEqual(SharedStore.load(defaults: defaults).securityMode, "plain")

        SharedStore.clearLegacyToken(defaults: defaults)
        XCTAssertNil(SharedStore.loadLegacyToken(defaults: defaults))
        XCTAssertEqual(SharedStore.load(defaults: defaults).securityMode, "plain")
    }

    func testLegacyTokenMissingOrEmptyReturnsNil() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer {
            defaults.removePersistentDomain(forName: suite)
        }

        XCTAssertNil(SharedStore.loadLegacyToken(defaults: defaults))

        let json = """
        {"token": "   ", "strategy": "dual", "securityMode": "plain", "theme": "aurora",
         "splitTunnelEnabled": true, "splitCIDRs": []}
        """
        defaults.set(Data(json.utf8), forKey: SharedStore.key)
        XCTAssertNil(SharedStore.loadLegacyToken(defaults: defaults))

        defaults.set(Data("not json".utf8), forKey: SharedStore.key)
        XCTAssertNil(SharedStore.loadLegacyToken(defaults: defaults))
    }

    func testLoadCustomIncludesBundledAndCustom() {
        let rules = SplitTunnelRules.load(custom: ["custom.invalid"])
        XCTAssertGreaterThan(rules.count, 2000)
        XCTAssertTrue(rules.contains("custom.invalid"))
    }

    func testLoadMissingBundleStillReturnsCustomRules() {
        let rules = SplitTunnelRules.load(
            bundle: Bundle(for: SharedSettingsTests.self),
            custom: ["custom.invalid"]
        )
        XCTAssertEqual(rules, ["custom.invalid"])
    }

    func testStoreLoadsDefaultsWhenEmpty() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer {
            defaults.removePersistentDomain(forName: suite)
        }
        XCTAssertEqual(SharedStore.load(defaults: defaults), SharedSettings())
    }

    func testStoreRoundTrip() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer {
            defaults.removePersistentDomain(forName: suite)
        }
        let settings = SharedSettings(
            splitDomains: ["example.com"]
        )
        SharedStore.save(settings, defaults: defaults)
        XCTAssertEqual(SharedStore.load(defaults: defaults), settings)
    }

    func testBundledDomainListIsPackaged() {
        XCTAssertGreaterThan(SplitTunnelRules.bundled().count, 2000)
    }

    func testParseNormalizesAndDeduplicates() {
        let parsed = SplitTunnelRules.parse(
            "# comment\nExample.COM\n*.example.com\ndomain:Example.com.\n\nvk.com # inline\n"
        )
        XCTAssertEqual(parsed, ["example.com", "vk.com"])
    }

    func testMergeKeepsBaseFirstAndDeduplicates() {
        let merged = SplitTunnelRules.merge(
            ["example.com", "vk.com"],
            ["VK.COM", "ok.ru", "example.com"]
        )
        XCTAssertEqual(merged, ["example.com", "vk.com", "ok.ru"])
    }

    func testSplitRulesSkipCommentsAndBlankLines() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("split-domains-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: url) }
        try """
        # comment
        example.com

          vk.com
        """.write(to: url, atomically: true, encoding: .utf8)

        XCTAssertEqual(
            SplitTunnelRules.load(url: url),
            ["example.com", "vk.com"]
        )
    }

    func testMissingSplitRulesFileReturnsEmptyList() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-\(UUID().uuidString).txt")
        XCTAssertEqual(SplitTunnelRules.load(url: url), [])
    }

    func testUnreadableSplitRulesFileReturnsEmptyList() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("directory-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertEqual(SplitTunnelRules.load(url: url), [])
    }
}
