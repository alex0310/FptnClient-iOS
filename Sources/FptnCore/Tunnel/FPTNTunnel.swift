import Foundation

public enum FPTNTunnelError: Error, Equatable, LocalizedError {
    case handshakeTimeout
    case malformedMessage
    case unexpectedMessage(String)
    case invalidAssignment
    case serverError(kind: FPTNErrorKind, message: String)
    case closed
    case notReady
    case batchTooLarge(Int)

    public var errorDescription: String? {
        switch self {
        case .handshakeTimeout: return "The FPTN server did not send an IP assignment."
        case .malformedMessage: return "The FPTN server sent a malformed YAFF message."
        case let .unexpectedMessage(kind): return "Unexpected FPTN message during handshake: \(kind)."
        case .invalidAssignment: return "The FPTN server sent an invalid IP assignment."
        case let .serverError(kind, message):
            return "FPTN server error \(kind.rawValue): \(message)"
        case .closed: return "The FPTN tunnel was closed."
        case .notReady: return "The FPTN tunnel handshake has not completed."
        case let .batchTooLarge(count): return "The FPTN batch has \(count) packets."
        }
    }
}

public enum FPTNTunnelStatus: Equatable, Sendable {
    case active
    case rotate
    case dead
}

public struct FPTNTunnelConfiguration: Sendable {
    public var clientAgent: String
    public var maxBatchSize: Int
    public var handshakeTimeout: TimeInterval
    public var pollTimeout: TimeInterval
    public var keepaliveIdle: TimeInterval
    public var deadAfter: TimeInterval?
    public var connectionLifetime: TimeInterval?
    public var tunIPv4: IPAddress?
    public var tunIPv6: IPAddress?
    public var sendDurationMilliseconds: Int?
    public var ttlMilliseconds: Int?

    public init(
        clientAgent: String = "FptnClient(iOS/1.0.0)",
        maxBatchSize: Int = 64,
        handshakeTimeout: TimeInterval = 10,
        pollTimeout: TimeInterval = 0.5,
        keepaliveIdle: TimeInterval = Keepalive.defaultPingIdle,
        deadAfter: TimeInterval? = nil,
        connectionLifetime: TimeInterval? = 540,
        tunIPv4: IPAddress? = nil,
        tunIPv6: IPAddress? = nil,
        sendDurationMilliseconds: Int? = nil,
        ttlMilliseconds: Int? = nil
    ) {
        self.clientAgent = clientAgent
        self.maxBatchSize = max(1, min(maxBatchSize, 1024))
        self.handshakeTimeout = max(0.1, handshakeTimeout)
        self.pollTimeout = max(0.01, pollTimeout)
        self.keepaliveIdle = max(0, keepaliveIdle)
        self.deadAfter = deadAfter
        self.connectionLifetime = connectionLifetime
        self.tunIPv4 = tunIPv4
        self.tunIPv6 = tunIPv6
        self.sendDurationMilliseconds = sendDurationMilliseconds
        self.ttlMilliseconds = ttlMilliseconds
    }
}

/// Typed FPTN relay over a WebSocket connection. It owns the IP assignment,
/// outgoing/incoming address rewriting, batching, WebSocket keep-alive and the
/// rolling lifetime. It deliberately has no knowledge of a TUN device: the
/// caller supplies packets and consumes packets, which keeps the transport
/// testable on Linux.
public final class FPTNTunnel {
    public let webSocket: WebSocketConnection
    public let configuration: FPTNTunnelConfiguration
    public private(set) var assignedIPv4: IPAddress?
    public private(set) var assignedIPv6: IPAddress?
    public private(set) var keepalive: Keepalive
    public let startedAt: TimeInterval
    public private(set) var isReady = false
    public private(set) var isClosed = false

    private let clock: () -> TimeInterval

    public init(
        webSocket: WebSocketConnection,
        configuration: FPTNTunnelConfiguration = FPTNTunnelConfiguration(),
        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.webSocket = webSocket
        self.configuration = configuration
        self.clock = clock
        self.startedAt = clock()
        self.keepalive = Keepalive(
            now: startedAt,
            pingIdle: configuration.keepaliveIdle,
            deadAfter: configuration.deadAfter
        )
    }

    /// Reads the initial `MSG_IP_ASSIGNMENT`. Control frames are answered while
    /// waiting; a server error aborts the handshake.
    public func performHandshake() throws {
        guard !isReady else { return }
        try webSocket.connection.setReadTimeout(configuration.handshakeTimeout)
        let deadline = clock() + configuration.handshakeTimeout
        while clock() < deadline {
            let frame = try webSocket.receiveFrame()
            let now = clock()
            switch frame {
            case let .binary(data):
                keepalive.received(at: now, pong: false)
                guard let message = FPTNMessage.decode(data) else {
                    throw FPTNTunnelError.malformedMessage
                }
                switch message {
                case let .ipAssignment(ipv4, ipv6):
                    try applyAssignment(ipv4: ipv4, ipv6: ipv6)
                    isReady = true
                    try webSocket.connection.setReadTimeout(configuration.pollTimeout)
                    return
                case let .error(kind, message):
                    throw FPTNTunnelError.serverError(kind: kind, message: message)
                case .batch, .ipPacket:
                    throw FPTNTunnelError.unexpectedMessage("data before IP assignment")
                }
            case let .ping(payload):
                try webSocket.sendPong(payload)
                keepalive.received(at: now, pong: false)
                keepalive.sent(at: now)
            case .pong:
                keepalive.received(at: now, pong: true)
            case .close:
                throw FPTNTunnelError.closed
            case .text:
                throw FPTNTunnelError.unexpectedMessage("text frame")
            }
        }
        throw FPTNTunnelError.handshakeTimeout
    }

    /// Rewrites, batches and sends TUN packets to the server.
    @discardableResult
    public func send(packets: [[UInt8]]) throws -> Int {
        guard isReady, !isClosed else { throw FPTNTunnelError.notReady }
        var batch: [[UInt8]] = []
        batch.reserveCapacity(configuration.maxBatchSize)
        var sent = 0
        for packet in packets {
            var rewritten = packet
            IPPacket.rewriteOutgoing(
                &rewritten,
                assignedIPv4: assignedIPv4,
                assignedIPv6: assignedIPv6
            )
            guard !rewritten.isEmpty else { continue }
            batch.append(rewritten)
            if batch.count == configuration.maxBatchSize {
                let count = batch.count
                try flush(&batch)
                sent += count
            }
        }
        let remaining = batch.count
        try flush(&batch)
        return sent + remaining
    }

    /// Reads one binary message and returns the IP packets after destination
    /// rewriting. Ping/pong and assignment frames are handled internally.
    public func receivePackets() throws -> [[UInt8]] {
        guard isReady, !isClosed else { throw FPTNTunnelError.notReady }
        while true {
            let frame = try webSocket.receiveFrame()
            let now = clock()
            switch frame {
            case let .binary(data):
                keepalive.received(at: now, pong: false)
                guard let message = FPTNMessage.decode(data) else {
                    throw FPTNTunnelError.malformedMessage
                }
                switch message {
                case let .batch(packets):
                    return rewriteIncoming(packets)
                case let .ipPacket(packet):
                    return rewriteIncoming([packet])
                case let .ipAssignment(ipv4, ipv6):
                    try applyAssignment(ipv4: ipv4, ipv6: ipv6)
                case let .error(kind, message):
                    throw FPTNTunnelError.serverError(kind: kind, message: message)
                }
            case let .ping(payload):
                try webSocket.sendPong(payload)
                keepalive.received(at: now, pong: false)
                keepalive.sent(at: now)
            case .pong:
                keepalive.received(at: now, pong: true)
            case .close:
                isClosed = true
                throw FPTNTunnelError.closed
            case .text:
                throw FPTNTunnelError.unexpectedMessage("text frame")
            }
        }
    }

    /// Sends a WebSocket ping if the tunnel has been quiet long enough.
    /// Returns `.rotate` once the rolling lifetime expires and `.dead` when no
    /// frame has arrived for the dead-peer window.
    public func tick() throws -> FPTNTunnelStatus {
        guard isReady, !isClosed else { return .dead }
        let now = clock()
        if let lifetime = configuration.connectionLifetime,
           now - startedAt >= lifetime {
            return .rotate
        }
        if keepalive.isDead(at: now) {
            return .dead
        }
        if case let .ping(_, sequence) = keepalive.poll(at: now) {
            var payload: [UInt8] = []
            payload.reserveCapacity(8)
            for shift in stride(from: 56, through: 0, by: -8) {
                payload.append(UInt8((sequence >> UInt64(shift)) & 0xff))
            }
            try webSocket.sendPing(payload)
        }
        return .active
    }

    public func close() {
        guard !isClosed else { return }
        isClosed = true
        try? webSocket.sendClose()
        webSocket.close()
    }

    // MARK: - Internals

    private func flush(_ batch: inout [[UInt8]]) throws {
        guard !batch.isEmpty else { return }
        guard let encoded = FPTNMessage.encodeBatch(batch) else {
            throw FPTNTunnelError.batchTooLarge(batch.count)
        }
        try webSocket.sendBinary(encoded)
        keepalive.sent(at: clock())
        batch.removeAll(keepingCapacity: true)
    }

    private func rewriteIncoming(_ packets: [[UInt8]]) -> [[UInt8]] {
        packets.map { packet in
            var rewritten = packet
            IPPacket.rewriteIncoming(
                &rewritten,
                tunIPv4: configuration.tunIPv4,
                tunIPv6: configuration.tunIPv6
            )
            return rewritten
        }
    }

    private func applyAssignment(ipv4: String, ipv6: String) throws {
        guard let v4 = IPAddress(ipv4), let v6 = IPAddress(ipv6) else {
            throw FPTNTunnelError.invalidAssignment
        }
        assignedIPv4 = v4
        assignedIPv6 = v6
    }
}

/// Opens a WebSocket tunnel over a freshly connected TLS transport.
public enum FPTNTunnelFactory {
    public static func connect(
        server: FPTNServer,
        token: String,
        securityMode: FPTNSecurityMode,
        configuration: FPTNTunnelConfiguration = FPTNTunnelConfiguration(),
        connectTimeout: TimeInterval = 10,
        clientAgent: String = "FptnClient(iOS/1.0.0)",
        sessionID: String? = nil,
        certificatePolicy: CertificateValidationPolicy? = nil,
        certificateSecurity: CertificateSecurityOptions = .default
    ) throws -> FPTNTunnel {
        let socket = try POSIXSocket.connect(
            host: server.host,
            port: server.port,
            timeout: connectTimeout
        )
        let tls = try TLSConnection(
            transport: socket,
            configuration: TLSConnectionConfiguration(
                serverName: server.host,
                expectedCertificateMD5: server.md5Fingerprint,
                certificatePolicy: certificatePolicy,
                certificateSecurity: certificateSecurity.addingSPKIPin(server.spkiSHA256),
                securityMode: securityMode
            )
        )
        do {
            try tls.connect()
            let webSocket = try WebSocketHandshake.upgrade(
                connection: tls,
                hostHeader: "\(server.host):\(server.port)",
                token: token,
                clientAgent: clientAgent,
                sessionID: sessionID,
                sendDurationMilliseconds: configuration.sendDurationMilliseconds,
                ttlMilliseconds: configuration.ttlMilliseconds
            )
            let tunnel = FPTNTunnel(webSocket: webSocket, configuration: configuration)
            try tunnel.performHandshake()
            return tunnel
        } catch {
            tls.close()
            throw error
        }
    }
}
