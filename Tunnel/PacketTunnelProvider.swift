import Foundation
import NetworkExtension
import FptnCore
import FptnShared

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var runtime: TunnelRuntime?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = SharedStore.load()
        let providerConfiguration =
            (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let providerToken = providerConfiguration?["token"] as? String
        let legacyToken = SharedStore.loadLegacyToken()
        guard let rawToken = TokenMigration.preferredToken(
            stored: providerToken,
            legacy: legacyToken,
            isValid: { candidate in
                (try? TokenParser.parse(candidate)) != nil
            }
        ) else {
            completionHandler(TunnelRuntimeError.missingToken)
            return
        }
        let token: FPTNAccessToken
        do {
            token = try TokenParser.parse(rawToken)
        } catch {
            completionHandler(error)
            return
        }
        let runtime = TunnelRuntime(
            provider: self,
            settings: settings,
            token: token
        )
        self.runtime = runtime
        runtime.start(completion: completionHandler)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        runtime?.stop()
        runtime = nil
        completionHandler()
    }
}
