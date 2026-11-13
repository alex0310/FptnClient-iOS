import Foundation
import NetworkExtension
import FptnShared

@MainActor
final class VPNController {
    static let providerBundleIdentifier = "com.example.fptnclient.tunnel"

    private var manager: NETunnelProviderManager?

    var status: NEVPNStatus {
        manager?.connection.status ?? .invalid
    }

    func start(settings: SharedSettings, token: String) async throws {
        let manager = try await loadManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleIdentifier
        proto.serverAddress = "FPTN"
        proto.providerConfiguration = [
            "token": token,
            "strategy": settings.strategy,
            "securityMode": settings.securityMode,
            "splitTunnel": settings.splitTunnelEnabled,
            "splitCIDRs": settings.splitCIDRs,
            "onDemand": settings.onDemandEnabled
        ]
        manager.protocolConfiguration = proto
        manager.localizedDescription = "FPTN"
        manager.isEnabled = true
        Self.applyOnDemand(enabled: settings.onDemandEnabled, to: manager)
        try await save(manager)
        try manager.connection.startVPNTunnel()
    }

    /// Applies the on-demand mode to an existing profile. If no profile has
    /// been created yet, the next `start(settings:token:)` picks the value up.
    func updateOnDemand(enabled: Bool) async throws {
        guard let manager, manager.protocolConfiguration != nil else { return }
        manager.isEnabled = true
        Self.applyOnDemand(enabled: enabled, to: manager)
        try await save(manager)
    }

    /// Removes the bearer token from the saved VPN profile. The profile itself
    /// is kept so the user can import another token without re-adding the VPN
    /// configuration. Best effort: the caller should stop the tunnel first.
    func clearStoredToken() async throws {
        guard let manager else { return }
        manager.isOnDemandEnabled = false
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            var configuration = proto.providerConfiguration ?? [:]
            configuration.removeValue(forKey: "token")
            proto.providerConfiguration = configuration
            manager.protocolConfiguration = proto
        }
        try await save(manager)
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    private static func applyOnDemand(enabled: Bool, to manager: NETunnelProviderManager) {
        manager.isOnDemandEnabled = enabled
        manager.onDemandRules = OnDemandPolicy.rules(enabled: enabled).map { descriptor -> NEOnDemandRule in
            let rule = NEOnDemandRuleConnect()
            switch descriptor.interfaceType {
            case .any:
                rule.interfaceTypeMatch = .any
            }
            return rule
        }
    }

    func reloadStatus() async {
        do {
            let managers = try await Self.loadAll()
            manager = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == Self.providerBundleIdentifier
            })
        } catch {
            // Status refresh is best effort; the UI keeps the previous state.
        }
    }

    private func loadManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        let managers = try await Self.loadAll()
        let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == Self.providerBundleIdentifier
        }) ?? NETunnelProviderManager()
        self.manager = manager
        return manager
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private static func loadAll() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }
}
