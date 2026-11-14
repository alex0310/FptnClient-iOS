import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A minimal TLS 1.3 client tailored for FPTN.
///
/// Authentication follows `CertificateValidationPolicy`: the default
/// `.pinnedMD5` matches upstream C++ (MD5 leaf pin + TLS Finished), while
/// `.strictChain` performs full X.509 path validation and verifies the
/// `CertificateVerify` signature with the leaf public key. See
/// `docs/SECURITY.md` for the trust model.
public final class TLSClientSession {
    public let clientRandom: [UInt8]
    public let sessionID: [UInt8]
    public private(set) var state: TLSClientState = .idle
    public private(set) var negotiatedCipherSuite: TLSCipherSuite?

    public var isConnected: Bool { state == .connected }

    private let configuration: TLSClientConfiguration
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let recordDecoder: TLSRecordDecoder
    private let handshakeDecoder: TLSHandshakeDecoder
    private let policy: CertificateValidationPolicy
    private var leafCertificate: X509Certificate?

    private var keySchedule: TLSKeySchedule?
    private var trafficSecrets: TLSTrafficSecrets?
    private var applicationSecrets: TLSApplicationSecrets?
    private var clientApplicationSecret: [UInt8]?
    private var serverApplicationSecret: [UInt8]?

    private var clientHandshakeProtector: TLSRecordProtector?
    private var serverHandshakeProtector: TLSRecordProtector?
    private var clientApplicationProtector: TLSRecordProtector?
    private var serverApplicationProtector: TLSRecordProtector?

    private var clientHelloBytes: [UInt8] = []
    private var pendingOutput: [UInt8] = []
    private var phase: Phase = .idle
    private var didEmitHandshakeCompleted = false

    private enum Phase {
        case idle
        case waitServerHello
        case waitEncryptedExtensions
        case waitCertificate
        case waitCertificateVerify
        case waitFinished
        case connected
    }

    public init(
        configuration: TLSClientConfiguration,
        clientRandom: [UInt8]? = nil,
        sessionIDRandom: [UInt8]? = nil,
        timestamp: UInt32? = nil,
        privateKey: Curve25519.KeyAgreement.PrivateKey? = nil
    ) throws {
        guard !configuration.serverName.isEmpty else {
            throw TLSError.invalidConfiguration("server name is empty")
        }
        guard !configuration.cipherSuites.isEmpty else {
            throw TLSError.invalidConfiguration("no cipher suites configured")
        }
        self.configuration = configuration
        self.clientRandom = clientRandom ?? SecureRandom.bytes(32)
        guard self.clientRandom.count == 32 else {
            throw TLSError.invalidConfiguration("ClientHello random must be 32 bytes")
        }
        let random = sessionIDRandom ?? SecureRandom.bytes(32)
        let stamp = timestamp ?? UInt32(Date().timeIntervalSince1970)
        self.sessionID = try FPTNSessionKey.realSessionID(random: random, timestamp: stamp)
        self.privateKey = privateKey ?? Curve25519.KeyAgreement.PrivateKey()
        self.recordDecoder = TLSRecordDecoder()
        self.handshakeDecoder = TLSHandshakeDecoder(
            maxHandshakeSize: configuration.maxHandshakeSize
        )
        self.policy = configuration.certificatePolicy
    }

    /// Produces the ClientHello and a compatibility ChangeCipherSpec record.
    public func start() throws -> TLSClientStep {
        guard state == .idle else { throw TLSError.invalidState(state.rawValue) }
        let builder = TLSClientHelloBuilder(
            serverName: configuration.serverName,
            random: clientRandom,
            sessionID: sessionID,
            keyShare: Array(privateKey.publicKey.rawRepresentation),
            cipherSuites: configuration.cipherSuites
        )
        let hello = try builder.build()
        clientHelloBytes = hello.encoded()
        let helloRecord = TLSRecord(
            type: .handshake,
            version: 0x0301,
            fragment: clientHelloBytes
        ).encoded()
        let changeCipherSpec = TLSRecord(
            type: .changeCipherSpec,
            fragment: [0x01]
        ).encoded()
        state = .waitServerHello
        phase = .waitServerHello
        return TLSClientStep(output: helloRecord + changeCipherSpec, events: [])
    }

    /// Feeds bytes received from the network and returns bytes to send back.
    public func receive(_ bytes: [UInt8]) throws -> TLSClientStep {
        guard state != .idle else { throw TLSError.invalidState(state.rawValue) }
        guard state != .closed, state != .failed else {
            throw TLSError.invalidState(state.rawValue)
        }
        recordDecoder.append(bytes)
        var events: [TLSClientEvent] = []
        do {
            while let record = try recordDecoder.nextRecord() {
                try process(record: record, events: &events)
            }
        } catch {
            state = .failed
            phase = .idle
            throw error
        }
        let output = pendingOutput
        pendingOutput.removeAll(keepingCapacity: true)
        return TLSClientStep(output: output, events: events)
    }

    /// Encrypts application data, splitting it into TLS record sized chunks.
    public func encryptApplicationData(_ data: [UInt8]) throws -> [UInt8] {
        guard state == .connected, let protector = clientApplicationProtector else {
            throw TLSError.invalidState(state.rawValue)
        }
        guard !data.isEmpty else { return [] }
        var output: [UInt8] = []
        var offset = 0
        while offset < data.count {
            let end = min(offset + TLSRecordProtector.maximumPlaintextLength, data.count)
            output.append(contentsOf: try protector.seal(
                contentType: .applicationData,
                plaintext: Array(data[offset..<end])
            ))
            offset = end
        }
        return output
    }

    /// Sends `close_notify` and marks the session as closed.
    public func close() throws -> [UInt8] {
        guard state == .connected, let protector = clientApplicationProtector else {
            return []
        }
        let alert = try protector.seal(contentType: .alert, plaintext: [1, 0])
        state = .closed
        phase = .idle
        return alert
    }

    /// The current transcript hash, exposed for diagnostics and tests.
    public var transcriptHash: [UInt8]? {
        keySchedule?.transcriptHash()
    }

    // MARK: - Record processing

    private func process(record: TLSRecord, events: inout [TLSClientEvent]) throws {
        switch record.type {
        case .changeCipherSpec:
            guard record.fragment == [0x01] else {
                throw TLSError.unexpectedMessage("ChangeCipherSpec")
            }
        case .alert:
            try handleAlert(record.fragment, events: &events)
        case .handshake:
            guard phase == .waitServerHello else {
                throw TLSError.unexpectedMessage("plaintext handshake after ServerHello")
            }
            handshakeDecoder.append(record.fragment)
            try processHandshakeMessages(events: &events)
        case .applicationData:
            let protector: TLSRecordProtector?
            if phase == .connected {
                protector = serverApplicationProtector
            } else {
                protector = serverHandshakeProtector
            }
            guard let protector else {
                throw TLSError.unexpectedMessage("encrypted record before keys are ready")
            }
            let opened = try protector.open(
                fragment: record.fragment,
                type: record.type,
                version: record.version
            )
            switch opened.contentType {
            case .handshake:
                handshakeDecoder.append(opened.plaintext)
                try processHandshakeMessages(events: &events)
            case .applicationData:
                if !opened.plaintext.isEmpty {
                    events.append(.applicationData(opened.plaintext))
                }
            case .alert:
                try handleAlert(opened.plaintext, events: &events)
            case .changeCipherSpec:
                break
            }
        }
    }

    private func processHandshakeMessages(events: inout [TLSClientEvent]) throws {
        while let message = try handshakeDecoder.nextMessage() {
            switch message.type {
            case .serverHello:
                try handleServerHello(message)
            case .encryptedExtensions:
                guard phase == .waitEncryptedExtensions else {
                    throw TLSError.unexpectedMessage("EncryptedExtensions")
                }
                _ = try TLSExtensions.parse(message.body)
                appendTranscript(message.encoded())
                phase = .waitCertificate
            case .certificate:
                guard phase == .waitCertificate else {
                    throw TLSError.unexpectedMessage("Certificate")
                }
                let entries = try TLSCertificateMessage.parse(message)
                leafCertificate = try CertificateAuthenticator.verify(
                    chainDER: entries.map(\.der),
                    hostname: configuration.serverName,
                    policy: policy
                )
                appendTranscript(message.encoded())
                phase = .waitCertificateVerify
            case .certificateVerify:
                guard phase == .waitCertificateVerify else {
                    throw TLSError.unexpectedMessage("CertificateVerify")
                }
                try validateCertificateVerify(message)
                appendTranscript(message.encoded())
                phase = .waitFinished
            case .finished:
                guard phase == .waitFinished else {
                    throw TLSError.unexpectedMessage("Finished")
                }
                try handleServerFinished(message, events: &events)
            case .newSessionTicket:
                guard phase == .connected else {
                    throw TLSError.unexpectedMessage("NewSessionTicket")
                }
            case .keyUpdate:
                guard phase == .connected else {
                    throw TLSError.unexpectedMessage("KeyUpdate")
                }
                try handleKeyUpdate(message)
            case .clientHello, .certificateRequest:
                throw TLSError.unexpectedMessage("\(message.type)")
            }
        }
    }

    // MARK: - Handshake steps

    private func handleServerHello(_ message: TLSHandshakeMessage) throws {
        guard phase == .waitServerHello else {
            throw TLSError.unexpectedMessage("ServerHello")
        }
        let hello = try TLSServerHello.parse(message)
        guard !hello.isHelloRetryRequest else {
            throw TLSError.unexpectedMessage("HelloRetryRequest is not supported")
        }
        guard hello.legacyVersion == 0x0303 else {
            throw TLSError.unsupportedVersion(hello.legacyVersion)
        }
        guard hello.sessionID == sessionID else { throw TLSError.sessionIDMismatch }
        guard hello.selectedVersion == 0x0304 else {
            throw TLSError.unsupportedVersion(hello.selectedVersion ?? 0)
        }
        guard hello.compressionMethod == 0 else {
            throw TLSError.unexpectedMessage("non-zero compression method")
        }
        guard let suite = TLSCipherSuite(rawValue: hello.cipherSuite),
              configuration.cipherSuites.contains(suite) else {
            throw TLSError.unsupportedCipherSuite(hello.cipherSuite)
        }
        guard let keyShare = hello.keyShare,
              keyShare.group == 0x001d,
              keyShare.key.count == 32 else {
            throw TLSError.invalidKeyShare
        }

        let serverPublicKey: Curve25519.KeyAgreement.PublicKey
        do {
            serverPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: keyShare.key
            )
        } catch {
            throw TLSError.invalidKeyShare
        }
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        let sharedBytes = shared.withUnsafeBytes { Array($0) }

        var schedule = TLSKeySchedule(hash: suite.hash)
        schedule.appendTranscript(clientHelloBytes)
        schedule.appendTranscript(message.encoded())
        let secrets = schedule.handshakeSecrets(sharedSecret: sharedBytes)
        let clientKeys = schedule.trafficKeys(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            keyLength: suite.keyLength
        )
        let serverKeys = schedule.trafficKeys(
            trafficSecret: secrets.serverHandshakeTrafficSecret,
            keyLength: suite.keyLength
        )

        keySchedule = schedule
        trafficSecrets = secrets
        negotiatedCipherSuite = suite
        clientHandshakeProtector = try TLSRecordProtector(
            suite: suite,
            key: clientKeys.key,
            iv: clientKeys.iv
        )
        serverHandshakeProtector = try TLSRecordProtector(
            suite: suite,
            key: serverKeys.key,
            iv: serverKeys.iv
        )
        state = .handshaking
        phase = .waitEncryptedExtensions
    }

    private func validateCertificateVerify(_ message: TLSHandshakeMessage) throws {
        var reader = ByteReader(message.body)
        let schemeRaw = try reader.readUInt16()
        let signature = try reader.readLengthPrefixed16()
        guard !signature.isEmpty, reader.isAtEnd else {
            throw TLSError.unexpectedMessage("malformed CertificateVerify")
        }
        guard case .strictChain = policy else {
            // Upstream FPTN behaviour: the MD5 pin plus TLS Finished are the
            // only authentication when strict X.509 validation is disabled.
            return
        }
        guard let leaf = leafCertificate,
              let hash = keySchedule?.transcriptHash(),
              let scheme = TLSSignatureScheme(rawValue: schemeRaw) else {
            throw TLSError.invalidState("missing data for CertificateVerify")
        }
        let signedContent = CertificateVerifyContext.signedContent(transcriptHash: hash)
        guard try CertificateSignature.verifyCertificateVerify(
            signature: signature,
            scheme: scheme,
            signedContent: signedContent,
            leaf: leaf
        ) else {
            throw TLSError.certificateVerifyMismatch
        }
    }

    private func handleServerFinished(
        _ message: TLSHandshakeMessage,
        events: inout [TLSClientEvent]
    ) throws {
        guard let schedule = keySchedule,
              let secrets = trafficSecrets,
              let suite = negotiatedCipherSuite else {
            throw TLSError.invalidState("missing handshake keys")
        }
        let expected = schedule.finishedVerifyData(
            trafficSecret: secrets.serverHandshakeTrafficSecret,
            transcriptHash: schedule.transcriptHash()
        )
        guard message.body.count == suite.hash.length,
              Digests.constantTimeEquals(message.body, expected) else {
            throw TLSError.serverFinishedMismatch
        }

        var updated = schedule
        updated.appendTranscript(message.encoded())
        let application = updated.applicationSecrets(masterSecret: secrets.masterSecret)
        let clientKeys = updated.trafficKeys(
            trafficSecret: application.clientApplicationTrafficSecret,
            keyLength: suite.keyLength
        )
        let serverKeys = updated.trafficKeys(
            trafficSecret: application.serverApplicationTrafficSecret,
            keyLength: suite.keyLength
        )
        let clientProtector = try TLSRecordProtector(
            suite: suite,
            key: clientKeys.key,
            iv: clientKeys.iv
        )
        let serverProtector = try TLSRecordProtector(
            suite: suite,
            key: serverKeys.key,
            iv: serverKeys.iv
        )

        let clientVerify = updated.finishedVerifyData(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            transcriptHash: updated.transcriptHash()
        )
        let clientFinished = TLSHandshakeMessage(type: .finished, body: clientVerify)
        guard let handshakeProtector = clientHandshakeProtector else {
            throw TLSError.invalidState("missing client handshake keys")
        }
        pendingOutput.append(contentsOf: try handshakeProtector.seal(
            contentType: .handshake,
            plaintext: clientFinished.encoded()
        ))
        updated.appendTranscript(clientFinished.encoded())

        keySchedule = updated
        applicationSecrets = application
        clientApplicationSecret = application.clientApplicationTrafficSecret
        serverApplicationSecret = application.serverApplicationTrafficSecret
        clientApplicationProtector = clientProtector
        serverApplicationProtector = serverProtector
        clientHandshakeProtector = nil
        serverHandshakeProtector = nil
        state = .connected
        phase = .connected
        if !didEmitHandshakeCompleted {
            didEmitHandshakeCompleted = true
            events.append(.handshakeCompleted)
        }
    }

    private func handleKeyUpdate(_ message: TLSHandshakeMessage) throws {
        guard let schedule = keySchedule,
              let suite = negotiatedCipherSuite,
              let serverSecret = serverApplicationSecret,
              let clientSecret = clientApplicationSecret,
              let serverProtector = serverApplicationProtector,
              let clientProtector = clientApplicationProtector else {
            throw TLSError.invalidState("missing application keys")
        }
        guard message.body.count == 1, message.body[0] <= 1 else {
            throw TLSError.unexpectedMessage("malformed KeyUpdate")
        }

        let nextServer = schedule.nextTrafficSecret(serverSecret)
        let serverKeys = schedule.trafficKeys(
            trafficSecret: nextServer,
            keyLength: suite.keyLength
        )
        try serverProtector.reset(
            suite: suite,
            key: serverKeys.key,
            iv: serverKeys.iv
        )
        serverApplicationSecret = nextServer

        if message.body[0] == 1 {
            let response = TLSHandshakeMessage(type: .keyUpdate, body: [0])
            pendingOutput.append(contentsOf: try clientProtector.seal(
                contentType: .handshake,
                plaintext: response.encoded()
            ))
            let nextClient = schedule.nextTrafficSecret(clientSecret)
            let clientKeys = schedule.trafficKeys(
                trafficSecret: nextClient,
                keyLength: suite.keyLength
            )
            try clientProtector.reset(
                suite: suite,
                key: clientKeys.key,
                iv: clientKeys.iv
            )
            clientApplicationSecret = nextClient
        }
    }

    private func handleAlert(_ fragment: [UInt8], events: inout [TLSClientEvent]) throws {
        guard fragment.count == 2 else {
            throw TLSError.unexpectedMessage("malformed alert")
        }
        if fragment[1] == 0 {
            state = .closed
            phase = .idle
            events.append(.closed)
            return
        }
        throw TLSError.invalidAlert(level: fragment[0], description: fragment[1])
    }

    private func appendTranscript(_ bytes: [UInt8]) {
        guard var schedule = keySchedule else { return }
        schedule.appendTranscript(bytes)
        keySchedule = schedule
    }
}
