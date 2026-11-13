import Foundation

/// Settings shared by the app and the packet-tunnel extension. The access
/// token is deliberately not part of this blob: the app stores it in Keychain
/// and passes it to the extension in `NETunnelProviderProtocol.providerConfiguration`.
/// Older builds stored it here; `SharedStore.loadLegacyToken` migrates it.
public struct SharedSettings: Codable, Equatable, Sendable {
    public var strategy: String
    public var securityMode: String
    public var theme: String
    public var language: AppLanguage
    public var onDemandEnabled: Bool
    public var splitTunnelEnabled: Bool
    public var splitCIDRs: [String]
    public var splitDomains: [String]
    public var preferredServerID: String?

    public init(
        strategy: String = "dual",
        securityMode: String = "obfuscated",
        theme: String = "aurora",
        language: AppLanguage = .system,
        onDemandEnabled: Bool = true,
        splitTunnelEnabled: Bool = true,
        splitCIDRs: [String] = SharedSettings.defaultSplitCIDRs,
        splitDomains: [String] = [],
        preferredServerID: String? = nil
    ) {
        self.strategy = strategy
        self.securityMode = securityMode
        self.theme = theme
        self.language = language
        self.onDemandEnabled = onDemandEnabled
        self.splitTunnelEnabled = splitTunnelEnabled
        self.splitCIDRs = splitCIDRs
        self.splitDomains = splitDomains
        self.preferredServerID = preferredServerID
    }

    private enum CodingKeys: String, CodingKey {
        case strategy
        case securityMode
        case theme
        case language
        case onDemandEnabled
        case splitTunnelEnabled
        case splitCIDRs
        case splitDomains
        case preferredServerID
    }

    /// Decodes older payloads that predate `splitDomains`, `language` or
    /// `onDemandEnabled` instead of dropping the whole settings blob on
    /// upgrade. The legacy `token` field is ignored here and read separately by
    /// `SharedStore.loadLegacyToken`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        strategy = try container.decode(String.self, forKey: .strategy)
        securityMode = try container.decode(String.self, forKey: .securityMode)
        theme = try container.decode(String.self, forKey: .theme)
        language = try container.decodeIfPresent(AppLanguage.self, forKey: .language) ?? .system
        onDemandEnabled = try container.decodeIfPresent(Bool.self, forKey: .onDemandEnabled) ?? true
        splitTunnelEnabled = try container.decode(Bool.self, forKey: .splitTunnelEnabled)
        splitCIDRs = try container.decode([String].self, forKey: .splitCIDRs)
        splitDomains = try container.decodeIfPresent([String].self, forKey: .splitDomains) ?? []
        preferredServerID = try container.decodeIfPresent(String.self, forKey: .preferredServerID)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(strategy, forKey: .strategy)
        try container.encode(securityMode, forKey: .securityMode)
        try container.encode(theme, forKey: .theme)
        try container.encode(language, forKey: .language)
        try container.encode(onDemandEnabled, forKey: .onDemandEnabled)
        try container.encode(splitTunnelEnabled, forKey: .splitTunnelEnabled)
        try container.encode(splitCIDRs, forKey: .splitCIDRs)
        try container.encode(splitDomains, forKey: .splitDomains)
        try container.encodeIfPresent(preferredServerID, forKey: .preferredServerID)
    }

    /// CIDRs that must always stay outside the tunnel: private LANs, loopback,
    /// link-local, multicast/broadcast and their IPv6 equivalents. They are
    /// merged with the user list by `effectiveSplitCIDRs`, so clearing the
    /// editable list cannot accidentally route local traffic into the VPN.
    public static let mandatorySplitCIDRs = [
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

    public static let defaultSplitCIDRs = mandatorySplitCIDRs

    /// The editable user list plus the mandatory local/system exclusions.
    /// Order is stable and duplicates are removed.
    public var effectiveSplitCIDRs: [String] {
        Self.mergeSplitCIDRs(Self.mandatorySplitCIDRs, splitCIDRs)
    }

    public static func mergeSplitCIDRs(_ base: [String], _ extra: [String]) -> [String] {
        var seen = Set<String>()
        return (base + extra).compactMap { raw in
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, seen.insert(value).inserted else { return nil }
            return value
        }
    }
}

public enum SharedStore {
    public static let suiteName = "group.com.example.fptnclient"
    static let key = "fptn.settings.v1"

    public static func load(
        defaults: UserDefaults? = UserDefaults(suiteName: suiteName)
    ) -> SharedSettings {
        guard let defaults,
              let data = defaults.data(forKey: key),
              let settings = try? JSONDecoder().decode(SharedSettings.self, from: data) else {
            return SharedSettings()
        }
        return settings
    }

    public static func save(
        _ settings: SharedSettings,
        defaults: UserDefaults? = UserDefaults(suiteName: suiteName)
    ) {
        guard let defaults,
              let data = try? JSONEncoder().encode(settings) else {
            return
        }
        defaults.set(data, forKey: key)
    }

    /// Reads the token from an old settings blob. It is intentionally separate
    /// from `SharedSettings` so a normal save rewrites the blob without the
    /// credential.
    public static func loadLegacyToken(
        defaults: UserDefaults? = UserDefaults(suiteName: suiteName)
    ) -> String? {
        guard let defaults,
              let data = defaults.data(forKey: key),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any],
              let raw = dictionary["token"] as? String else {
            return nil
        }
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return token.isEmpty ? nil : token
    }

    /// Rewrites the settings blob without the legacy token. This is safe to
    /// call after a successful Keychain migration.
    public static func clearLegacyToken(
        defaults: UserDefaults? = UserDefaults(suiteName: suiteName)
    ) {
        save(load(defaults: defaults), defaults: defaults)
    }
}

public enum SplitTunnelRules {
    /// Full list shipped with the app. The list is a SwiftPM resource so the
    /// app and the extension read exactly the same bytes.
    public static func bundled() -> [String] {
        load(bundle: .module)
    }

    public static func load(custom: [String] = []) -> [String] {
        merge(bundled(), custom)
    }

    public static func load(bundle: Bundle = .main, custom: [String] = []) -> [String] {
        let bundled: [String]
        if let url = bundle.url(forResource: "split-domains", withExtension: "txt") {
            bundled = load(url: url)
        } else {
            bundled = []
        }
        return merge(bundled, custom)
    }

    public static func load(url: URL) -> [String] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return parse(text)
    }

    /// Parses an imported plain-text list. Blank lines and `#` comments are
    /// ignored; `domain:`, `*.` and trailing dots are normalized by
    /// `SplitTunnel` later, but normalizing here keeps the stored list tidy.
    public static func parse(_ text: String) -> [String] {
        deduplicate(text.split(whereSeparator: { $0.isNewline }).map(String.init))
    }

    /// Merges two lists, preserving the first occurrence order. Bundled rules
    /// stay first so an imported list cannot silently shadow them.
    public static func merge(_ base: [String], _ imported: [String]) -> [String] {
        deduplicate(base + imported)
    }

    private static func deduplicate(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        result.reserveCapacity(values.count)
        for raw in values {
            let value = normalize(raw)
            guard !value.isEmpty, !value.hasPrefix("#"), seen.insert(value).inserted else {
                continue
            }
            result.append(value)
        }
        return result
    }

    private static func normalize(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let hash = value.firstIndex(of: "#") {
            value = String(value[..<hash]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if value.hasPrefix("domain:") {
            value = String(value.dropFirst("domain:".count))
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if value.hasPrefix("*.") {
            value = String(value.dropFirst(2))
        }
        while value.hasSuffix(".") {
            value.removeLast()
        }
        return value
    }
}
