import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum FPTNSecurityMode: String, CaseIterable, Sendable {
    /// Plain TLS 1.3. The FPTN key is stamped at the end of the session id.
    case plain
    /// The whole TLS handshake is wrapped in `TlsObfuscator2`.
    case obfuscated
    /// A decoy ClientHello is followed by a real obfuscated handshake.
    case reality
}

public struct TLSConnectionConfiguration: Sendable {
    public var serverName: String
    public var expectedCertificateMD5: String?
    /// `nil` keeps the upstream MD5-pinning behaviour derived from
    /// `expectedCertificateMD5`; a strict policy enables full X.509 validation.
    public var certificatePolicy: CertificateValidationPolicy?
    public var certificateSecurity: CertificateSecurityOptions
    public var cipherSuites: [TLSCipherSuite]
    public var securityMode: FPTNSecurityMode
    public var handshakeTimeout: TimeInterval
    public var readTimeout: TimeInterval
    public var writeTimeout: TimeInterval
    public var postHandshakeDelay: TimeInterval
    public var realityDecoyTimeout: TimeInterval
    public var realityQuietPeriod: TimeInterval
    public var realityHandshakeDelay: TimeInterval

    public init(
        serverName: String,
        expectedCertificateMD5: String? = nil,
        certificatePolicy: CertificateValidationPolicy? = nil,
        certificateSecurity: CertificateSecurityOptions = .default,
        cipherSuites: [TLSCipherSuite] = TLSCipherSuite.allCases,
        securityMode: FPTNSecurityMode = .plain,
        handshakeTimeout: TimeInterval = 10,
        readTimeout: TimeInterval = 30,
        writeTimeout: TimeInterval = 30,
        postHandshakeDelay: TimeInterval = 0.150,
        realityDecoyTimeout: TimeInterval = 6,
        realityQuietPeriod: TimeInterval = 0.300,
        realityHandshakeDelay: TimeInterval = 0.150
    ) {
        self.serverName = serverName
        self.expectedCertificateMD5 = expectedCertificateMD5
        self.certificatePolicy = certificatePolicy
        self.certificateSecurity = certificateSecurity
        self.cipherSuites = cipherSuites
        self.securityMode = securityMode
        self.handshakeTimeout = handshakeTimeout
        self.readTimeout = readTimeout
        self.writeTimeout = writeTimeout
        self.postHandshakeDelay = postHandshakeDelay
        self.realityDecoyTimeout = realityDecoyTimeout
        self.realityQuietPeriod = realityQuietPeriod
        self.realityHandshakeDelay = realityHandshakeDelay
    }
}

public enum TLSConnectionError: Error, Equatable, LocalizedError {
    case realityDecoyMissing
    case notConnected
    case closed

    public var errorDescription: String? {
        switch self {
        case .realityDecoyMissing: return "The reality decoy server did not answer."
        case .notConnected: return "The TLS connection is not established."
        case .closed: return "The TLS connection is closed."
        }
    }
}

/// TLS 1.3 connection with optional FPTN handshake obfuscation and reality
/// decoy handshake. After the handshake, all bytes are plain TLS records; the
/// obfuscator is dropped exactly like upstream does.
public final class TLSConnection: HTTPConnection, ByteTransport {
    public let transport: ByteTransport
    public let configuration: TLSConnectionConfiguration
    public private(set) var handshakeEvents: [TLSClientEvent] = []

    private let session: TLSClientSession
    private let sleeper: (TimeInterval) -> Void
    private let timestampProvider: () -> UInt32
    private var obfuscator = TlsObfuscator2()
    private var pendingApplicationData: [UInt8] = []
    private var connected = false
    private var closed = false

    public init(
        transport: ByteTransport,
        configuration: TLSConnectionConfiguration,
        clientRandom: [UInt8]? = nil,
        sessionIDRandom: [UInt8]? = nil,
        timestamp: UInt32? = nil,
        sleeper: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) },
        timestampProvider: @escaping () -> UInt32 = {
            UInt32(Date().timeIntervalSince1970)
        }
    ) throws {
        self.transport = transport
        self.configuration = configuration
        self.sleeper = sleeper
        self.timestampProvider = timestampProvider
        self.session = try TLSClientSession(
            configuration: TLSClientConfiguration(
                serverName: configuration.serverName,
                cipherSuites: configuration.cipherSuites,
                expectedCertificateMD5: configuration.expectedCertificateMD5,
                certificatePolicy: configuration.certificatePolicy,
                certificateSecurity: configuration.certificateSecurity
            ),
            clientRandom: clientRandom,
            sessionIDRandom: sessionIDRandom,
            timestamp: timestamp
        )
    }

    public var isConnected: Bool { connected }

    public func connect() throws {
        guard !connected else { return }
        try transport.setReadTimeout(configuration.handshakeTimeout)
        try transport.setWriteTimeout(configuration.handshakeTimeout)

        if configuration.securityMode == .reality {
            try performRealityDecoy()
        }

        let start = try session.start()
        try sendHandshake(start.output)
        while !session.isConnected {
            let raw = try transport.read(maxBytes: 16_384)
            if raw.isEmpty { throw TLSConnectionError.closed }
            if configuration.securityMode == .plain {
                try feedHandshake(raw)
            } else {
                obfuscator.push(raw)
                while let payload = obfuscator.nextPayload(now: timestampProvider()) {
                    try feedHandshake(payload)
                }
            }
        }

        sleeper(configuration.postHandshakeDelay)
        obfuscator.reset()
        connected = true
        for event in handshakeEvents {
            if case let .applicationData(data) = event {
                pendingApplicationData.append(contentsOf: data)
            }
        }
        try transport.setReadTimeout(configuration.readTimeout)
        try transport.setWriteTimeout(configuration.writeTimeout)
    }

    // MARK: - ByteTransport / HTTPConnection

    public func read(maxBytes: Int) throws -> [UInt8] {
        guard connected, !closed else { throw TLSConnectionError.notConnected }
        if !pendingApplicationData.isEmpty {
            return takePending(maxBytes: maxBytes)
        }
        while true {
            let raw = try transport.read(maxBytes: 16_384)
            if raw.isEmpty { throw TLSConnectionError.closed }
            let step = try session.receive(raw)
            if !step.output.isEmpty {
                try transport.write(step.output)
            }
            for event in step.events {
                switch event {
                case let .applicationData(data):
                    pendingApplicationData.append(contentsOf: data)
                case .closed:
                    closed = true
                    throw TLSConnectionError.closed
                case .handshakeCompleted:
                    break
                }
            }
            if !pendingApplicationData.isEmpty {
                return takePending(maxBytes: maxBytes)
            }
        }
    }

    public func write(_ bytes: [UInt8]) throws {
        guard connected, !closed else { throw TLSConnectionError.notConnected }
        let encrypted = try session.encryptApplicationData(bytes)
        if !encrypted.isEmpty {
            try transport.write(encrypted)
        }
    }

    public func close() {
        guard !closed else { return }
        closed = true
        connected = false
        if let alert = try? session.close() {
            try? transport.write(alert)
        }
        transport.close()
    }

    public func setReadTimeout(_ seconds: TimeInterval) throws {
        try transport.setReadTimeout(seconds)
    }

    public func setWriteTimeout(_ seconds: TimeInterval) throws {
        try transport.setWriteTimeout(seconds)
    }

    // MARK: - Handshake internals

    private func sendHandshake(_ bytes: [UInt8]) throws {
        guard !bytes.isEmpty else { return }
        switch configuration.securityMode {
        case .plain:
            try transport.write(bytes)
        case .obfuscated, .reality:
            try transport.write(obfuscator.encode(
                payload: bytes,
                timestamp: timestampProvider()
            ))
        }
    }

    private func feedHandshake(_ bytes: [UInt8]) throws {
        let step = try session.receive(bytes)
        handshakeEvents.append(contentsOf: step.events)
        if !step.output.isEmpty {
            try sendHandshake(step.output)
        }
    }

    private func takePending(maxBytes: Int) -> [UInt8] {
        let count = min(maxBytes, pendingApplicationData.count)
        let result = Array(pendingApplicationData.prefix(count))
        pendingApplicationData.removeFirst(count)
        return result
    }

    private func performRealityDecoy() throws {
        let now = timestampProvider()
        let decoyRandom = SecureRandom.bytes(32)
        let decoySessionID = try FPTNSessionKey.decoySessionID(
            random: SecureRandom.bytes(32),
            timestamp: now
        )
        let decoyKey = Curve25519.KeyAgreement.PrivateKey()
        let builder = TLSClientHelloBuilder(
            serverName: configuration.serverName,
            random: decoyRandom,
            sessionID: decoySessionID,
            keyShare: Array(decoyKey.publicKey.rawRepresentation),
            cipherSuites: configuration.cipherSuites
        )
        let hello = try builder.build()
        let record = TLSRecord(
            type: .handshake,
            version: 0x0301,
            fragment: hello.encoded()
        ).encoded()
        try transport.write(record)

        try transport.setReadTimeout(configuration.realityQuietPeriod)
        let deadline = Date().addingTimeInterval(configuration.realityDecoyTimeout)
        var received = 0
        while Date() < deadline {
            do {
                let chunk = try transport.read(maxBytes: 16_384)
                if chunk.isEmpty { break }
                received += chunk.count
            } catch TransportError.timeout {
                break
            } catch TransportError.closed {
                break
            }
        }
        guard received > 0 else {
            throw TLSConnectionError.realityDecoyMissing
        }

        let changeCipherSpec: [UInt8] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        try transport.write(changeCipherSpec)
        sleeper(configuration.realityHandshakeDelay)
        try transport.setReadTimeout(configuration.handshakeTimeout)
    }
}
