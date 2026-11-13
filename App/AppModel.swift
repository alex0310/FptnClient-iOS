import Foundation
import NetworkExtension
import SwiftUI
import FptnShared
import FptnCore

@MainActor
final class AppModel: ObservableObject {
    @Published var settings: SharedSettings {
        didSet { SharedStore.save(settings) }
    }
    @Published private(set) var token: FPTNAccessToken?
    @Published private(set) var rawToken = ""
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published var lastError: String?
    @Published var isBusy = false
    @Published private(set) var traffic: TrafficSnapshot?
    @Published private(set) var trafficSpeed: TrafficSpeed?
    @Published private(set) var trafficHistory = TrafficHistory()

    private let vpn = VPNController()
    private let tokenStore: any TokenStore
    private var trafficTimer: Timer?
    private var previousTraffic: TrafficSnapshot?

    init(tokenStore: any TokenStore = TokenStorage.make()) {
        self.tokenStore = tokenStore
        let stored = SharedStore.load()
        settings = stored

        let legacy = SharedStore.loadLegacyToken()
        let storedToken: String?
        do {
            storedToken = try tokenStore.load()
        } catch {
            storedToken = nil
        }
        let raw = TokenMigration.preferredToken(
            stored: storedToken,
            legacy: legacy
        ) { candidate in
            (try? TokenParser.parse(candidate)) != nil
        }
        var persisted = false
        if let raw {
            rawToken = raw
            token = try? TokenParser.parse(raw)
            if raw == storedToken {
                persisted = true
            } else {
                do {
                    try tokenStore.save(raw)
                    persisted = true
                } catch {
                    // Keep the legacy value for the next launch instead of
                    // deleting the only copy of the credential.
                }
            }
        } else {
            rawToken = ""
            token = nil
            if storedToken != nil {
                try? tokenStore.delete()
            }
        }
        if legacy != nil, persisted || raw == nil {
            SharedStore.clearLegacyToken()
        }
    }

    var theme: AppTheme {
        AppTheme(stored: settings.theme)
    }

    var palette: ThemePalette { ThemePalette(theme.tokens) }

    var l10n: Localizer { Localizer(language: settings.language) }

    var servers: [FPTNServer] { token?.servers ?? [] }

    var serviceName: String {
        token?.serviceName?.isEmpty == false ? token!.serviceName! : "FPTN"
    }

    var isConnected: Bool { status == .connected }

    var isTransitioning: Bool {
        status == .connecting || status == .reasserting || status == .disconnecting
    }

    var statusTitle: String {
        switch status {
        case .connected: return l10n.text(.statusProtected)
        case .connecting, .reasserting: return l10n.text(.statusConnecting)
        case .disconnecting: return l10n.text(.statusClosing)
        case .disconnected: return l10n.text(.statusReady)
        case .invalid: return l10n.text(.statusNotConfigured)
        @unknown default: return l10n.text(.statusUnknown)
        }
    }

    var statusDetail: String {
        switch status {
        case .connected:
            return l10n.text(.statusDetailConnected)
        case .connecting, .reasserting:
            return l10n.text(.statusDetailConnecting)
        case .disconnecting:
            return l10n.text(.statusDetailDisconnecting)
        case .disconnected:
            return l10n.text(.statusDetailDisconnected)
        case .invalid:
            return l10n.text(.statusDetailInvalid)
        @unknown default:
            return l10n.text(.statusDetailUnknown)
        }
    }

    var strategyTitle: String {
        switch settings.strategy {
        case "triple": return l10n.text(.settingsTriple)
        default: return l10n.text(.settingsDual)
        }
    }

    var securityModeTitle: String {
        switch settings.securityMode {
        case "plain": return l10n.text(.settingsPlainSNI)
        case "reality": return l10n.text(.settingsReality)
        default: return l10n.text(.settingsTLSObfuscation)
        }
    }

    var splitTunnelTitle: String {
        settings.splitTunnelEnabled
            ? l10n.text(.commonEnabled)
            : l10n.text(.commonDisabled)
    }

    var onDemandTitle: String {
        settings.onDemandEnabled
            ? l10n.text(.commonAutomatic)
            : l10n.text(.commonManual)
    }

    func statusColor(_ palette: ThemePalette) -> Color {
        switch status {
        case .connected: return palette.success
        case .connecting, .reasserting: return palette.warning
        case .disconnecting: return palette.accentSecondary
        case .disconnected, .invalid: return palette.textSecondary
        @unknown default: return palette.textSecondary
        }
    }

    func importToken(_ raw: String) throws {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let parsed = try TokenParser.parse(value)
        try tokenStore.save(value)
        rawToken = value
        token = parsed
        lastError = nil
    }

    func clearToken() async {
        rawToken = ""
        token = nil
        do {
            try tokenStore.delete()
        } catch {
            lastError = message(for: error)
        }
        await applyOnDemandSetting(false)
        vpn.stop()
        await refreshStatus()
        do {
            try await vpn.clearStoredToken()
        } catch {
            lastError = message(for: error)
        }
        await refreshStatus()
    }

    func connect() async {
        guard token != nil, !rawToken.isEmpty else {
            lastError = l10n.text(.errorImportTokenFirst)
            return
        }
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await vpn.start(settings: settings, token: rawToken)
            await refreshStatus()
        } catch {
            lastError = message(for: error)
        }
    }

    func disconnect() async {
        vpn.stop()
        await refreshStatus()
    }

    func refreshStatus() async {
        await vpn.reloadStatus()
        status = vpn.status
        updateTrafficPolling()
    }

    // MARK: - Traffic

    /// The extension publishes a snapshot once a second into the App Group
    /// container. Polling (rather than a Darwin notification) keeps the app
    /// side simple and works while the app is in the foreground.
    private func updateTrafficPolling() {
        guard isConnected else {
            trafficTimer?.invalidate()
            trafficTimer = nil
            previousTraffic = nil
            traffic = nil
            trafficSpeed = nil
            trafficHistory.reset()
            return
        }
        guard trafficTimer == nil else { return }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshTraffic() }
        }
        RunLoop.main.add(timer, forMode: .common)
        trafficTimer = timer
        refreshTraffic()
    }

    private func refreshTraffic() {
        guard isConnected, let current = TrafficSnapshotStore.read() else {
            previousTraffic = nil
            traffic = nil
            trafficSpeed = nil
            trafficHistory.reset()
            return
        }
        if let previous = previousTraffic,
           let speed = current.speed(relativeTo: previous) {
            trafficSpeed = speed
            trafficHistory.append(
                TrafficSample(
                    timestamp: current.updatedAt,
                    rxBytesPerSecond: speed.rxBytesPerSecond,
                    txBytesPerSecond: speed.txBytesPerSecond
                )
            )
        } else {
            trafficSpeed = nil
        }
        previousTraffic = current
        traffic = current
    }

    func applyOnDemandSetting(_ enabled: Bool) async {
        do {
            try await vpn.updateOnDemand(enabled: enabled)
        } catch {
            lastError = message(for: error)
        }
    }

    func message(for error: Error) -> String {
        if error is TokenStoreError {
            return l10n.text(.errorKeychain)
        }
        guard let tokenError = error as? TokenError else {
            return error.localizedDescription
        }
        switch tokenError {
        case .emptyToken:
            return l10n.text(.tokenErrorEmpty)
        case .invalidBase64:
            return l10n.text(.tokenErrorInvalidBase64)
        case .brotliDecompressionFailed:
            return l10n.text(.tokenErrorBrotli)
        case .invalidJSON:
            return l10n.text(.tokenErrorInvalidJSON)
        case .missingUsername:
            return l10n.text(.tokenErrorMissingUsername)
        case .missingPassword:
            return l10n.text(.tokenErrorMissingPassword)
        case .noServers:
            return l10n.text(.tokenErrorNoServers)
        case let .invalidServerName(index):
            return l10n.text(.tokenErrorInvalidServerName, index + 1)
        case let .invalidServerHost(index):
            return l10n.text(.tokenErrorInvalidServerHost, index + 1)
        case let .invalidServerPort(index):
            return l10n.text(.tokenErrorInvalidServerPort, index + 1)
        }
    }

    /// Re-applies the persisted mode after `refreshStatus()` has loaded an
    /// existing profile, so an upgrade from a build without on-demand gets the
    /// new default without waiting for the next manual connect.
    func syncOnDemandSetting() async {
        guard token != nil else { return }
        await applyOnDemandSetting(settings.onDemandEnabled)
    }

    func toggleConnection() async {
        if isConnected || isTransitioning {
            await disconnect()
        } else {
            await connect()
        }
    }
}
