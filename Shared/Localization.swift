import Foundation

/// UI language selected in Settings. `.system` follows the device language and
/// falls back to English for languages that do not have a translation yet.
public enum AppLanguage: String, Codable, CaseIterable, Sendable {
    case system
    case english = "en"
    case russian = "ru"

    public var id: String { rawValue }

    public func resolved(
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> ResolvedLanguage {
        switch self {
        case .english:
            return .english
        case .russian:
            return .russian
        case .system:
            let first = preferredLanguages.first?.lowercased() ?? ""
            return first.hasPrefix("ru") ? .russian : .english
        }
    }
}

public enum ResolvedLanguage: String, CaseIterable, Sendable {
    case english = "en"
    case russian = "ru"
}

/// Stable keys keep translations independent from the English source text and
/// let tests verify that both language bundles contain every key.
public enum L10nKey: String, CaseIterable, Sendable {
    case tabTunnel = "tab.tunnel"
    case tabServers = "tab.servers"
    case tabSettings = "tab.settings"

    case commonOk = "common.ok"
    case commonOn = "common.on"
    case commonOff = "common.off"
    case commonEnabled = "common.enabled"
    case commonDisabled = "common.disabled"
    case commonAutomatic = "common.automatic"
    case commonManual = "common.manual"
    case commonUnknown = "common.unknown"
    case commonServersCount = "common.serversCount"
    case commonEndpointsCount = "common.endpointsCount"

    case statusProtected = "status.protected"
    case statusConnecting = "status.connecting"
    case statusClosing = "status.closing"
    case statusReady = "status.ready"
    case statusNotConfigured = "status.notConfigured"
    case statusUnknown = "status.unknown"
    case statusDetailConnected = "status.detail.connected"
    case statusDetailConnecting = "status.detail.connecting"
    case statusDetailDisconnecting = "status.detail.disconnecting"
    case statusDetailDisconnected = "status.detail.disconnected"
    case statusDetailInvalid = "status.detail.invalid"
    case statusDetailUnknown = "status.detail.unknown"

    case orbWorking = "orb.working"
    case orbConnected = "orb.connected"
    case orbConnecting = "orb.connecting"
    case orbClosing = "orb.closing"
    case orbTapToStart = "orb.tapToStart"
    case orbUnknown = "orb.unknown"

    case dashboardBringYourOwnAccess = "dashboard.bringYourOwnAccess"
    case dashboardTokenExplanation = "dashboard.tokenExplanation"
    case dashboardImportToken = "dashboard.importToken"
    case dashboardConnect = "dashboard.connect"
    case dashboardDisconnect = "dashboard.disconnect"
    case dashboardServers = "dashboard.servers"
    case dashboardPool = "dashboard.pool"
    case dashboardSplit = "dashboard.split"
    case dashboardSelectedRoute = "dashboard.selectedRoute"
    case dashboardAutomaticRace = "dashboard.automaticRace"
    case dashboardAutomaticRaceExplanation = "dashboard.automaticRaceExplanation"
    case dashboardLocalNetworkBypass = "dashboard.localNetworkBypass"
    case dashboardLocalNetworkBypassDetail = "dashboard.localNetworkBypassDetail"

    case serversUseAutomaticRace = "servers.useAutomaticRace"
    case serversTokenPool = "servers.tokenPool"
    case serversLoginRaceExplanation = "servers.loginRaceExplanation"
    case serversNoServers = "servers.noServers"
    case serversEmptyExplanation = "servers.emptyExplanation"
    case serversRealityBadge = "servers.realityBadge"

    case settingsTitle = "settings.title"
    case settingsImportAccessToken = "settings.importAccessToken"
    case settingsTokenLoaded = "settings.tokenLoaded"
    case settingsReplaceToken = "settings.replaceToken"
    case settingsRemoveToken = "settings.removeToken"
    case settingsAccess = "settings.access"
    case settingsAppearance = "settings.appearance"
    case settingsLanguage = "settings.language"
    case settingsLanguageSystem = "settings.language.system"
    case settingsLanguageEnglish = "settings.language.english"
    case settingsLanguageRussian = "settings.language.russian"
    case settingsRollingPool = "settings.rollingPool"
    case settingsDual = "settings.dual"
    case settingsTriple = "settings.triple"
    case settingsCensorshipMode = "settings.censorshipMode"
    case settingsPlainSNI = "settings.plainSNI"
    case settingsTLSObfuscation = "settings.tlsObfuscation"
    case settingsReality = "settings.reality"
    case settingsBypassPrivateNetworks = "settings.bypassPrivateNetworks"
    case settingsConnectOnDemand = "settings.connectOnDemand"
    case settingsOnDemandExplanation = "settings.onDemandExplanation"
    case settingsSplitTunnelCIDRs = "settings.splitTunnelCIDRs"
    case settingsTunnel = "settings.tunnel"
    case settingsConnectionDiagnostics = "settings.connectionDiagnostics"
    case settingsDiagnostics = "settings.diagnostics"
    case settingsVersion = "settings.version"
    case settingsAbout = "settings.about"
    case settingsAboutText = "settings.aboutText"

    case diagnosticsTitle = "diagnostics.title"
    case diagnosticsVPNState = "diagnostics.vpnState"
    case diagnosticsService = "diagnostics.service"
    case diagnosticsServers = "diagnostics.servers"
    case diagnosticsPreferred = "diagnostics.preferred"
    case diagnosticsConnection = "diagnostics.connection"
    case diagnosticsPool = "diagnostics.pool"
    case diagnosticsCensorship = "diagnostics.censorship"
    case diagnosticsOnDemand = "diagnostics.onDemand"
    case diagnosticsSplitTunnel = "diagnostics.splitTunnel"
    case diagnosticsCIDRs = "diagnostics.cidrs"
    case diagnosticsImportedDomains = "diagnostics.importedDomains"
    case diagnosticsTransport = "diagnostics.transport"
    case diagnosticsProtocol = "diagnostics.protocol"
    case diagnosticsTLS = "diagnostics.tls"
    case diagnosticsKeepalive = "diagnostics.keepalive"
    case diagnosticsLifetime = "diagnostics.lifetime"
    case diagnosticsCore = "diagnostics.core"
    case diagnosticsProtocolValue = "diagnostics.protocolValue"
    case diagnosticsTLSValue = "diagnostics.tlsValue"
    case diagnosticsKeepaliveValue = "diagnostics.keepaliveValue"
    case diagnosticsLifetimeValue = "diagnostics.lifetimeValue"

    case splitTitle = "split.title"
    case splitDomainRules = "split.domainRules"
    case splitBundled = "split.bundled"
    case splitImported = "split.imported"
    case splitDomainExplanation = "split.domainExplanation"
    case splitAppendImported = "split.appendImported"
    case splitImportDomainList = "split.importDomainList"
    case splitClearImported = "split.clearImported"
    case splitImportedListCleared = "split.importedListCleared"
    case splitCIDRExclusions = "split.cidrExclusions"
    case splitCIDRExplanation = "split.cidrExplanation"
    case splitIgnoredEntries = "split.ignoredEntries"
    case splitSaveCIDRRules = "split.saveCIDRRules"
    case splitRestoreDefaults = "split.restoreDefaults"
    case splitNoFileSelected = "split.noFileSelected"
    case splitNoDomainRules = "split.noDomainRules"
    case splitImportedRules = "split.importedRules"

    case tokenAccessToken = "token.accessToken"
    case tokenHero = "token.hero"
    case tokenExplanation = "token.explanation"
    case tokenValidateAndSave = "token.validateAndSave"
    case tokenLoadStored = "token.loadStored"
    case tokenImportTitle = "token.importTitle"

    case themeAuroraTitle = "theme.aurora.title"
    case themeAuroraSubtitle = "theme.aurora.subtitle"
    case themeEmberTitle = "theme.ember.title"
    case themeEmberSubtitle = "theme.ember.subtitle"

    case errorImportTokenFirst = "error.importTokenFirst"
    case errorKeychain = "error.keychain"
    case tokenErrorEmpty = "token.error.empty"
    case tokenErrorInvalidBase64 = "token.error.invalidBase64"
    case tokenErrorBrotli = "token.error.brotli"
    case tokenErrorInvalidJSON = "token.error.invalidJSON"
    case tokenErrorMissingUsername = "token.error.missingUsername"
    case tokenErrorMissingPassword = "token.error.missingPassword"
    case tokenErrorNoServers = "token.error.noServers"
    case tokenErrorInvalidServerName = "token.error.invalidServerName"
    case tokenErrorInvalidServerHost = "token.error.invalidServerHost"
    case tokenErrorInvalidServerPort = "token.error.invalidServerPort"
}

/// Resolves a stable key against the `en.lproj`/`ru.lproj` bundles packaged in
/// `FptnShared`. The app can switch language at runtime without restarting.
public struct Localizer: Sendable {
    public let language: ResolvedLanguage

    public init(language: ResolvedLanguage) {
        self.language = language
    }

    public init(
        language: AppLanguage,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) {
        self.language = language.resolved(preferredLanguages: preferredLanguages)
    }

    public func text(_ key: L10nKey) -> String {
        let bundle = Self.bundle(for: language)
        return bundle.localizedString(
            forKey: key.rawValue,
            value: key.rawValue,
            table: nil
        )
    }

    public func text(_ key: L10nKey, _ arguments: CVarArg...) -> String {
        let format = text(key)
        return String(
            format: format,
            locale: Locale(identifier: language.rawValue),
            arguments: arguments
        )
    }

    private static func bundle(for language: ResolvedLanguage) -> Bundle {
        if let url = Bundle.module.url(forResource: language.rawValue, withExtension: "lproj"),
           let localized = Bundle(url: url) {
            return localized
        }
        return Bundle.module
    }
}
