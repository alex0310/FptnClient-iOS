import Foundation

public enum FPTNClientState: Equatable, Sendable {
    case idle
    case loggingIn
    case connecting
    case connected
    case reconnecting
    case stopped
    case failed(String)
}

public enum FPTNClientError: Error, Equatable, LocalizedError {
    case noServers
    case loginFailed
    case dnsFailed
    case noTunnel
    case notStarted

    public var errorDescription: String? {
        switch self {
        case .noServers: return "The access token contains no servers."
        case .loginFailed: return "Every candidate server rejected the login."
        case .dnsFailed: return "Could not fetch DNS settings from the selected server."
        case .noTunnel: return "No tunnel could be opened."
        case .notStarted: return "The FPTN client has not been started."
        }
    }
}

public struct FPTNClientConfiguration: Sendable {
    public var pool: TunnelPoolConfiguration
    public var securityMode: FPTNSecurityMode
    public var apiSecurityMode: FPTNSecurityMode?
    public var clientAgent: String
    public var connectTimeout: TimeInterval
    public var loginTimeout: TimeInterval
    public var handshakeTimeout: TimeInterval
    public var tunIPv4: IPAddress?
    public var tunIPv6: IPAddress?
    public var splitTunnel: SplitTunnel?
    /// Server id (`host:port`) tried before the random login race.
    public var preferredServerID: String?

    public init(
        pool: TunnelPoolConfiguration = TunnelPoolConfiguration(),
        securityMode: FPTNSecurityMode = .obfuscated,
        apiSecurityMode: FPTNSecurityMode? = nil,
        clientAgent: String = "FptnClient(iOS/1.0.0)",
        connectTimeout: TimeInterval = 10,
        loginTimeout: TimeInterval = 10,
        handshakeTimeout: TimeInterval = 10,
        tunIPv4: IPAddress? = nil,
        tunIPv6: IPAddress? = nil,
        splitTunnel: SplitTunnel? = nil,
        preferredServerID: String? = nil
    ) {
        self.pool = pool
        self.securityMode = securityMode
        self.apiSecurityMode = apiSecurityMode
        self.clientAgent = clientAgent
        self.connectTimeout = connectTimeout
        self.loginTimeout = loginTimeout
        self.handshakeTimeout = handshakeTimeout
        self.tunIPv4 = tunIPv4
        self.tunIPv6 = tunIPv6
        self.splitTunnel = splitTunnel
        self.preferredServerID = preferredServerID
    }
}

/// End-to-end FPTN client orchestration: token login race, DNS bootstrap,
/// rolling pool creation, reconnect budget and packet dispatch.
public final class FPTNClient {
    public typealias TunnelConnector = (
        FPTNServer,
        String,
        FPTNSecurityMode,
        String
    ) throws -> any PoolTunnel

    public let accessToken: FPTNAccessToken
    public let configuration: FPTNClientConfiguration
    public private(set) var state: FPTNClientState = .idle
    public private(set) var dns: FPTNDNSSettings?
    public private(set) var selectedServer: FPTNServer?
    public private(set) var jwt: String?
    public private(set) var pool: TunnelPool?
    public private(set) var reconnectPolicy: ReconnectPolicy
    public var onStateChange: ((FPTNClientState) -> Void)?

    private let api: FPTNAPIClient
    private let connector: TunnelConnector
    private let clock: () -> TimeInterval
    private let sessionID: String

    public init(
        accessToken: FPTNAccessToken,
        configuration: FPTNClientConfiguration = FPTNClientConfiguration(),
        sessionID: String = TunnelPool.randomSessionID(),
        reconnectPolicy: ReconnectPolicy = ReconnectPolicy(),
        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        apiTransport: FPTNAPIClient.Transport? = nil,
        tunnelConnector: TunnelConnector? = nil
    ) {
        self.accessToken = accessToken
        self.configuration = configuration
        self.sessionID = sessionID
        self.reconnectPolicy = reconnectPolicy
        self.clock = clock
        let apiMode = configuration.apiSecurityMode ?? configuration.securityMode
        self.api = FPTNAPIClient(
            configuration: FPTNAPIConfiguration(clientAgent: configuration.clientAgent),
            transport: apiTransport ?? FPTNAPITransport.transport(
                securityMode: apiMode,
                connectTimeout: configuration.connectTimeout
            )
        )
        self.connector = tunnelConnector ?? Self.defaultConnector(
            configuration: configuration,
            sessionID: sessionID
        )
    }

    @discardableResult
    public func start() throws -> FPTNDNSSettings? {
        guard !accessToken.servers.isEmpty else {
            throw fail(.noServers)
        }
        setState(.loggingIn)
        guard let race = LoginRace.find(
            servers: accessToken.servers,
            preferredServerID: configuration.preferredServerID,
            timeout: configuration.loginTimeout,
            login: { [api, accessToken] server in
                try api.login(
                    server: server,
                    username: accessToken.username,
                    password: accessToken.password
                )
            }
        ) else {
            throw fail(.loginFailed)
        }
        selectedServer = race.server
        jwt = race.token
        setState(.connecting)

        do {
            dns = try api.dns(server: race.server, token: race.token)
        } catch {
            dns = nil
        }

        let sharedSessionID = sessionID
        let pool = TunnelPool(
            configuration: configuration.pool,
            sessionID: sharedSessionID,
            connector: { [connector, configuration, sharedSessionID] in
                try connector(
                    race.server,
                    race.token,
                    configuration.securityMode,
                    sharedSessionID
                )
            },
            clock: clock
        )
        self.pool = pool
        if !pool.maintain(now: clock()) {
            setState(.failed(FPTNClientError.noTunnel.localizedDescription))
            throw FPTNClientError.noTunnel
        }
        setState(.connected)
        return dns
    }

    /// Drives rolling replacements and the reconnect budget. Returns the new
    /// state after maintenance.
    @discardableResult
    public func maintain() -> FPTNClientState {
        guard let pool else {
            setState(.failed(FPTNClientError.notStarted.localizedDescription))
            return state
        }
        let now = clock()
        if !pool.isEmpty {
            pool.tick(now: now)
            if !pool.isEmpty {
                if state != .connected { setState(.connected) }
                return state
            }
        }
        guard reconnectPolicy.canAttempt(at: now) else {
            setState(.failed("Reconnect budget exhausted"))
            return state
        }
        reconnectPolicy.recordAttempt(at: now)
        setState(.reconnecting)
        if pool.maintain(now: now) {
            setState(.connected)
        }
        return state
    }

    @discardableResult
    public func send(packets: [[UInt8]]) throws -> Int {
        guard let pool, state == .connected || state == .reconnecting else {
            throw FPTNClientError.notStarted
        }
        do {
            return try pool.send(packets: packets, now: clock())
        } catch {
            setState(.reconnecting)
            _ = maintain()
            throw error
        }
    }

    public func stop() {
        pool?.close()
        pool = nil
        setState(.stopped)
    }

    private func setState(_ newState: FPTNClientState) {
        state = newState
        onStateChange?(newState)
    }

    private func fail(_ error: FPTNClientError) -> FPTNClientError {
        setState(.failed(error.localizedDescription))
        return error
    }

    private static func defaultConnector(
        configuration: FPTNClientConfiguration,
        sessionID: String
    ) -> TunnelConnector {
        let tunnelConfiguration = FPTNTunnelConfiguration(
            clientAgent: configuration.clientAgent,
            maxBatchSize: configuration.pool.maxBatchSize,
            handshakeTimeout: configuration.handshakeTimeout,
            keepaliveIdle: configuration.pool.keepaliveIdle,
            connectionLifetime: configuration.pool.lifetime,
            tunIPv4: configuration.tunIPv4,
            tunIPv6: configuration.tunIPv6
        )
        return { server, token, mode, _ in
            try FPTNTunnelFactory.connect(
                server: server,
                token: token,
                securityMode: mode,
                configuration: tunnelConfiguration,
                connectTimeout: configuration.connectTimeout,
                clientAgent: configuration.clientAgent,
                sessionID: sessionID
            )
        }
    }
}
