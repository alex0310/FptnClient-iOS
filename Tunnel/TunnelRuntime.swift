import Foundation
import NetworkExtension
import FptnCore
import FptnShared

enum TunnelRuntimeError: Error, LocalizedError {
    case missingToken
    case noAssignedAddress
    case networkSettings(String)
    case clientFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingToken: return "The provider configuration has no access token."
        case .noAssignedAddress: return "The server did not assign a tunnel address."
        case let .networkSettings(message): return "Could not apply network settings: \(message)"
        case let .clientFailed(message): return "The tunnel pool failed: \(message)"
        }
    }
}

/// Owns the FPTN client and the three concurrent loops used by the extension:
/// TUN -> WebSocket, WebSocket -> TUN, and the maintenance timer.
final class TunnelRuntime {
    private let provider: NEPacketTunnelProvider
    private let settings: SharedSettings
    private let token: FPTNAccessToken
    private let controlQueue = DispatchQueue(label: "com.example.fptnclient.control")
    private let outgoingQueue = DispatchQueue(label: "com.example.fptnclient.outgoing")
    private let stateLock = NSLock()

    private var client: FPTNClient?
    private var device: PacketFlowDevice?
    private var relay: FPTNRelay?
    private var splitTunnel: SplitTunnel?
    private var routeStore: SplitTunnelRouteStore?
    private var lastDNS: FPTNDNSSettings?
    private var remoteAddress = "fptn"
    private var routeUpdateWorkItem: DispatchWorkItem?
    private var timer: DispatchSourceTimer?
    private var readers: Set<ObjectIdentifier> = []
    private var stopped = false

    init(provider: NEPacketTunnelProvider, settings: SharedSettings, token: FPTNAccessToken) {
        self.provider = provider
        self.settings = settings
        self.token = token
    }

    func start(completion: @escaping (Error?) -> Void) {
        controlQueue.async { [weak self] in
            guard let self else { return }
            do {
                let split = try SplitTunnel(
                    rules: SplitTunnelRules.load(custom: self.settings.splitDomains),
                    cidrs: self.settings.effectiveSplitCIDRs,
                    policy: .exclude,
                    enabled: self.settings.splitTunnelEnabled
                )
                let strategy = TunnelPoolStrategy(rawValue: self.settings.strategy) ?? .dual
                let mode = FPTNSecurityMode(rawValue: self.settings.securityMode) ?? .obfuscated
                let configuration = FPTNClientConfiguration(
                    pool: TunnelPoolConfiguration(strategy: strategy),
                    securityMode: mode,
                    splitTunnel: split,
                    preferredServerID: self.settings.preferredServerID
                )
                let client = FPTNClient(accessToken: self.token, configuration: configuration)
                let dns = try client.start()
                guard let slot = client.pool?.activeSlots.first,
                      let ipv4 = slot.assignedIPv4 else {
                    throw TunnelRuntimeError.noAssignedAddress
                }
                let routeStore = self.settings.splitTunnelEnabled
                    ? SplitTunnelRouteStore()
                    : nil
                let dnsSettings = dns ?? FPTNDNSSettings(
                    dns: "1.1.1.1",
                    dnsIPv6: "2606:4700:4700::1111"
                )
                let remote = client.selectedServer?.host ?? "fptn"
                self.splitTunnel = split
                self.routeStore = routeStore
                self.lastDNS = dnsSettings
                self.remoteAddress = remote
                let device = PacketFlowDevice(flow: self.provider.packetFlow)
                try self.applyNetworkSettings(
                    ipv4: ipv4,
                    ipv6: slot.assignedIPv6,
                    dns: dnsSettings,
                    remote: remote
                )
                self.client = client
                self.device = device
                self.relay = FPTNRelay(
                    sender: client,
                    sink: device,
                    splitTunnel: split,
                    routeStore: routeStore,
                    onExcludedAddressesChanged: { [weak self] in
                        self?.controlQueue.async {
                            self?.scheduleRouteRefresh()
                        }
                    }
                )
                self.startTimer()
                self.startReaders()
                self.startOutgoing()
                completion(nil)
            } catch {
                self.setStopped()
                completion(error)
            }
        }
    }

    func stop() {
        setStopped()
        routeUpdateWorkItem?.cancel()
        routeUpdateWorkItem = nil
        timer?.cancel()
        timer = nil
        client?.stop()
        client = nil
    }

    // MARK: - Network settings

    private func applyNetworkSettings(
        ipv4: IPAddress,
        ipv6: IPAddress?,
        dns: FPTNDNSSettings,
        remote: String
    ) throws {
        let network = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)
        network.mtu = NSNumber(value: 1400)

        let v4 = NEIPv4Settings(addresses: [ipv4.text], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = [NEIPv4Route.default()]
        v4.excludedRoutes = excludedIPv4Routes()
        network.ipv4Settings = v4

        if let ipv6 {
            let v6 = NEIPv6Settings(
                addresses: [ipv6.text],
                networkPrefixLengths: [NSNumber(value: 128)]
            )
            v6.includedRoutes = [NEIPv6Route.default()]
            v6.excludedRoutes = excludedIPv6Routes()
            network.ipv6Settings = v6
        }

        var servers = [dns.dns]
        if let dnsIPv6 = dns.dnsIPv6, !dnsIPv6.isEmpty {
            servers.append(dnsIPv6)
        }
        network.dnsSettings = NEDNSSettings(servers: servers)

        let semaphore = DispatchSemaphore(value: 0)
        var error: Error?
        provider.setTunnelNetworkSettings(network) { settingsError in
            error = settingsError
            semaphore.signal()
        }
        semaphore.wait()
        if let error {
            throw TunnelRuntimeError.networkSettings(error.localizedDescription)
        }
    }

    /// DNS answers arrive continuously, so route refreshes are debounced. The
    /// extension keeps running if a refresh fails; the next learned address
    /// schedules another attempt.
    private func scheduleRouteRefresh() {
        guard !isStopped, routeStore != nil else { return }
        routeUpdateWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.refreshNetworkSettings()
        }
        routeUpdateWorkItem = work
        controlQueue.asyncAfter(deadline: .now() + 0.35, execute: work)
    }

    private func refreshNetworkSettings() {
        guard !isStopped,
              let client,
              let slot = client.pool?.activeSlots.first,
              let ipv4 = slot.assignedIPv4,
              let dns = lastDNS else {
            return
        }
        do {
            try applyNetworkSettings(
                ipv4: ipv4,
                ipv6: slot.assignedIPv6,
                dns: dns,
                remote: remoteAddress
            )
        } catch {
            // Keep the tunnel alive; a later DNS/SNI event retries the update.
        }
    }

    private func excludedIPv4Routes() -> [NEIPv4Route] {
        guard settings.splitTunnelEnabled else { return [] }
        var routes: [NEIPv4Route] = []
        var seen = Set<String>()

        for value in settings.effectiveSplitCIDRs {
            guard let prefix = IPPrefix(value),
                  case let .ipv4(address) = prefix.address else { continue }
            let network = Self.maskedIPv4(address, prefixLength: prefix.prefixLength)
            let destination = IPAddress.ipv4(network).text
            let key = "\(destination)/\(prefix.prefixLength)"
            guard seen.insert(key).inserted else { continue }
            routes.append(
                NEIPv4Route(
                    destinationAddress: destination,
                    subnetMask: Self.ipv4Mask(prefix.prefixLength)
                )
            )
        }

        for address in routeStore?.snapshot() ?? [] {
            guard case .ipv4 = address,
                  splitTunnel?.shouldBypass(address: address) != true else {
                continue
            }
            let key = "\(address.text)/32"
            guard seen.insert(key).inserted else { continue }
            routes.append(
                NEIPv4Route(
                    destinationAddress: address.text,
                    subnetMask: "255.255.255.255"
                )
            )
        }
        return routes
    }

    private func excludedIPv6Routes() -> [NEIPv6Route] {
        guard settings.splitTunnelEnabled else { return [] }
        var routes: [NEIPv6Route] = []
        var seen = Set<String>()

        for value in settings.effectiveSplitCIDRs {
            guard let prefix = IPPrefix(value),
                  case .ipv6 = prefix.address else { continue }
            let key = "\(prefix.address.text)/\(prefix.prefixLength)"
            guard seen.insert(key).inserted else { continue }
            routes.append(
                NEIPv6Route(
                    destinationAddress: prefix.address.text,
                    networkPrefixLength: NSNumber(value: prefix.prefixLength)
                )
            )
        }

        for address in routeStore?.snapshot() ?? [] {
            guard case .ipv6 = address,
                  splitTunnel?.shouldBypass(address: address) != true else {
                continue
            }
            let key = "\(address.text)/128"
            guard seen.insert(key).inserted else { continue }
            routes.append(
                NEIPv6Route(
                    destinationAddress: address.text,
                    networkPrefixLength: NSNumber(value: 128)
                )
            )
        }
        return routes
    }

    private static func maskedIPv4(_ address: UInt32, prefixLength: Int) -> UInt32 {
        let clamped = max(0, min(32, prefixLength))
        let mask: UInt32 = clamped == 0 ? 0 : ~(UInt32.max >> UInt32(clamped))
        return address & mask
    }

    private static func ipv4Mask(_ length: Int) -> String {
        let clamped = max(0, min(32, length))
        let value: UInt32 = clamped == 0 ? 0 : ~(UInt32.max >> UInt32(clamped))
        return [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ].map(String.init).joined(separator: ".")
    }

    // MARK: - Loops

    private func startTimer() {
        let source = DispatchSource.makeTimerSource(queue: controlQueue)
        source.schedule(deadline: .now() + 1, repeating: 1)
        source.setEventHandler { [weak self] in
            guard let self, !self.isStopped else { return }
            if let state = self.client?.maintain(), case let .failed(message) = state {
                self.provider.cancelTunnelWithError(TunnelRuntimeError.clientFailed(message))
                return
            }
            self.startReaders()
        }
        source.resume()
        timer = source
    }

    private func startReaders() {
        guard let client, let device, !isStopped else { return }
        for slot in client.pool?.activeSlots ?? [] {
            guard let tunnel = slot.tunnel else { continue }
            let id = ObjectIdentifier(tunnel as AnyObject)
            guard !readers.contains(id) else { continue }
            readers.insert(id)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.readLoop(tunnel: tunnel, device: device, id: id)
            }
        }
    }

    private func readLoop(tunnel: any PoolTunnel, device: PacketFlowDevice, id: ObjectIdentifier) {
        while !isStopped {
            do {
                let packets = try tunnel.receivePackets()
                if !packets.isEmpty {
                    if let relay = self.relay {
                        try relay.forwardIncoming(packets)
                    } else {
                        try device.writePackets(packets)
                    }
                }
            } catch TransportError.timeout {
                continue
            } catch {
                break
            }
        }
        controlQueue.async { [weak self] in
            self?.readers.remove(id)
        }
    }

    private func startOutgoing() {
        guard let relay, let device else { return }
        outgoingQueue.async { [weak self] in
            guard let self else { return }
            while !self.isStopped {
                do {
                    let packets = try device.readPackets()
                    guard !packets.isEmpty else { continue }
                    _ = try self.controlQueue.sync {
                        try relay.forwardOutgoing(packets)
                    }
                } catch {
                    if self.isStopped { break }
                    self.controlQueue.async { self.client?.maintain() }
                    Thread.sleep(forTimeInterval: 0.1)
                }
            }
        }
    }

    // MARK: - State

    private var isStopped: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stopped
    }

    private func setStopped() {
        stateLock.lock()
        stopped = true
        stateLock.unlock()
    }
}
