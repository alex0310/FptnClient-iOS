import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

/// A deterministic TLS 1.3 server used to exercise `TLSClientSession` without
/// network access. It implements only the parts of RFC 8446 the FPTN client
/// relies on and deliberately mirrors its transcript handling.
final class SimulatedTLSServer {
    static let testCertificateDER: [UInt8] = {
        let body = Array("FPTN simulated leaf certificate".utf8)
        return [0x30, 0x2a, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1f]
            + body
    }()

    let suite: TLSCipherSuite
    let certificateDER: [UInt8]
    private let privateKey = Curve25519.KeyAgreement.PrivateKey()

    private var schedule: TLSKeySchedule?
    private var secrets: TLSTrafficSecrets?
    private var applicationSecrets: TLSApplicationSecrets?
    private var serverHandshakeProtector: TLSRecordProtector?
    private var clientHandshakeProtector: TLSRecordProtector?
    private var serverAppProtector: TLSRecordProtector?
    private var clientAppProtector: TLSRecordProtector?

    private(set) var clientSessionID: [UInt8] = []
    private(set) var clientKeyShare: [UInt8] = []
    private(set) var clientFinishedReceived = false

    /// Test hooks that let a test simulate a misbehaving server.
    var sessionIDOverride: [UInt8]?
    var corruptServerFinished = false
    var sendHelloRetryRequest = false
    /// Strict X.509 tests supply a real chain and a real CertificateVerify
    /// signature; the defaults keep the existing MD5-pinning tests unchanged.
    var certificateChainDER: [[UInt8]] = []
    var certificateVerifyScheme: UInt16 = 0x0403
    var certificateVerifySigner: (([UInt8]) throws -> [UInt8])?

    init(
        suite: TLSCipherSuite = .aes128GcmSha256,
        certificateDER: [UInt8] = SimulatedTLSServer.testCertificateDER
    ) {
        self.suite = suite
        self.certificateDER = certificateDER
    }

    /// Consumes the client's ClientHello (and compatibility CCS) and returns
    /// the server flight: ServerHello, CCS, and two encrypted records.
    func accept(clientOutput: [UInt8]) throws -> [UInt8] {
        let (record, helloMessage) = try firstHandshakeRecord(in: clientOutput)
        let hello = try TLSClientHello.parse(helloMessage)
        clientSessionID = hello.sessionID
        clientKeyShare = try parseKeyShare(hello)

        let shared = try privateKey.sharedSecretFromKeyAgreement(
            with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientKeyShare)
        )
        let sharedBytes = shared.withUnsafeBytes { Array($0) }

        let serverHello = TLSServerHello(
            legacyVersion: 0x0303,
            random: sendHelloRetryRequest
                ? TLSServerHello.helloRetryRequestRandom
                : SecureRandom.bytes(32),
            sessionID: sessionIDOverride ?? hello.sessionID,
            cipherSuite: suite.rawValue,
            compressionMethod: 0,
            extensions: [
                TLSExtensionType.supportedVersions: [0x03, 0x04],
                TLSExtensionType.keyShare: keyShareExtension()
            ]
        )
        let serverHelloBytes = serverHello.encoded()

        var transcript = TLSKeySchedule(hash: suite.hash)
        transcript.appendTranscript(record.fragment)
        transcript.appendTranscript(serverHelloBytes)
        let handshakeSecrets = transcript.handshakeSecrets(sharedSecret: sharedBytes)
        let clientKeys = transcript.trafficKeys(
            trafficSecret: handshakeSecrets.clientHandshakeTrafficSecret,
            keyLength: suite.keyLength
        )
        let serverKeys = transcript.trafficKeys(
            trafficSecret: handshakeSecrets.serverHandshakeTrafficSecret,
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

        let encryptedExtensions = TLSHandshakeMessage(
            type: .encryptedExtensions,
            body: [0x00, 0x00]
        )
        let certificate = certificateMessage()
        transcript.appendTranscript(encryptedExtensions.encoded())
        transcript.appendTranscript(certificate.encoded())
        let verifyContent = CertificateVerifyContext.signedContent(
            transcriptHash: transcript.transcriptHash()
        )
        let certificateVerify = try certificateVerifyMessage(signedContent: verifyContent)
        transcript.appendTranscript(certificateVerify.encoded())

        let finishedVerify = transcript.finishedVerifyData(
            trafficSecret: handshakeSecrets.serverHandshakeTrafficSecret,
            transcriptHash: transcript.transcriptHash()
        )
        var finishedBody = finishedVerify
        if corruptServerFinished, !finishedBody.isEmpty {
            finishedBody[0] ^= 0xff
        }
        let finished = TLSHandshakeMessage(type: .finished, body: finishedBody)
        transcript.appendTranscript(finished.encoded())

        let application = transcript.applicationSecrets(
            masterSecret: handshakeSecrets.masterSecret
        )
        let serverAppKeys = transcript.trafficKeys(
            trafficSecret: application.serverApplicationTrafficSecret,
            keyLength: suite.keyLength
        )
        let clientAppKeys = transcript.trafficKeys(
            trafficSecret: application.clientApplicationTrafficSecret,
            keyLength: suite.keyLength
        )

        let encryptedFlight = try serverProtector.seal(
            contentType: .handshake,
            plaintext: encryptedExtensions.encoded() + certificate.encoded()
        ) + serverProtector.seal(
            contentType: .handshake,
            plaintext: certificateVerify.encoded() + finished.encoded()
        )

        schedule = transcript
        secrets = handshakeSecrets
        applicationSecrets = application
        serverHandshakeProtector = serverProtector
        clientHandshakeProtector = clientProtector
        serverAppProtector = try TLSRecordProtector(
            suite: suite,
            key: serverAppKeys.key,
            iv: serverAppKeys.iv
        )
        clientAppProtector = try TLSRecordProtector(
            suite: suite,
            key: clientAppKeys.key,
            iv: clientAppKeys.iv
        )

        let serverHelloRecord = TLSRecord(
            type: .handshake,
            fragment: serverHelloBytes
        ).encoded()
        let changeCipherSpec = TLSRecord(
            type: .changeCipherSpec,
            fragment: [0x01]
        ).encoded()
        return serverHelloRecord + changeCipherSpec + encryptedFlight
    }

    /// Verifies the client's Finished message and finalizes application keys.
    func receiveClientFinished(_ bytes: [UInt8]) throws {
        guard let schedule, let secrets, let clientProtector = clientHandshakeProtector else {
            throw TLSError.invalidState("server is not ready for Finished")
        }
        let opened = try openHandshakeRecord(bytes, protector: clientProtector)
        let decoder = TLSHandshakeDecoder()
        decoder.append(opened)
        guard let message = try decoder.nextMessage(), message.type == .finished else {
            throw TLSError.unexpectedMessage("client Finished expected")
        }
        let expected = schedule.finishedVerifyData(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            transcriptHash: schedule.transcriptHash()
        )
        guard Digests.constantTimeEquals(message.body, expected) else {
            throw TLSError.serverFinishedMismatch
        }
        clientFinishedReceived = true
        clientHandshakeProtector = nil
        serverHandshakeProtector = nil
    }

    func sealApplicationData(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let protector = serverAppProtector else {
            throw TLSError.invalidState("server application keys are not ready")
        }
        return try protector.seal(contentType: .applicationData, plaintext: plaintext)
    }

    func openApplicationData(_ bytes: [UInt8]) throws -> [UInt8] {
        guard let protector = clientAppProtector else {
            throw TLSError.invalidState("client application keys are not ready")
        }
        let decoder = TLSRecordDecoder()
        decoder.append(bytes)
        var plaintext: [UInt8] = []
        while let record = try decoder.nextRecord() {
            let opened = try protector.open(
                fragment: record.fragment,
                type: record.type,
                version: record.version
            )
            guard opened.contentType == .applicationData else {
                throw TLSError.unexpectedMessage("application data expected")
            }
            plaintext.append(contentsOf: opened.plaintext)
        }
        return plaintext
    }

    /// Opens the first client record and returns its inner content type.
    func openClientRecord(
        _ bytes: [UInt8]
    ) throws -> (contentType: TLSContentType, plaintext: [UInt8]) {
        guard let protector = clientAppProtector else {
            throw TLSError.invalidState("client application keys are not ready")
        }
        let decoder = TLSRecordDecoder()
        decoder.append(bytes)
        guard let record = try decoder.nextRecord() else {
            throw TLSError.truncatedRecord
        }
        return try protector.open(
            fragment: record.fragment,
            type: record.type,
            version: record.version
        )
    }

    /// Opens every client record in `bytes` in order.
    func openClientRecords(
        _ bytes: [UInt8]
    ) throws -> [(contentType: TLSContentType, plaintext: [UInt8])] {
        guard let protector = clientAppProtector else {
            throw TLSError.invalidState("client application keys are not ready")
        }
        let decoder = TLSRecordDecoder()
        decoder.append(bytes)
        var output: [(contentType: TLSContentType, plaintext: [UInt8])] = []
        while let record = try decoder.nextRecord() {
            output.append(try protector.open(
                fragment: record.fragment,
                type: record.type,
                version: record.version
            ))
        }
        return output
    }

    /// Sends a KeyUpdate under the current server keys, then rotates them.
    func sendKeyUpdate(requestUpdate: Bool) throws -> [UInt8] {
        guard let schedule,
              let applicationSecrets,
              let protector = serverAppProtector else {
            throw TLSError.invalidState("server application keys are not ready")
        }
        let message = TLSHandshakeMessage(
            type: .keyUpdate,
            body: [requestUpdate ? 1 : 0]
        )
        let record = try protector.seal(
            contentType: .handshake,
            plaintext: message.encoded()
        )
        let next = schedule.nextTrafficSecret(
            applicationSecrets.serverApplicationTrafficSecret
        )
        let keys = schedule.trafficKeys(trafficSecret: next, keyLength: suite.keyLength)
        try protector.reset(suite: suite, key: keys.key, iv: keys.iv)
        self.applicationSecrets = TLSApplicationSecrets(
            clientApplicationTrafficSecret: applicationSecrets.clientApplicationTrafficSecret,
            serverApplicationTrafficSecret: next
        )
        return record
    }

    /// Consumes a client KeyUpdate response and rotates the client app keys.
    func receiveClientKeyUpdate(_ bytes: [UInt8]) throws {
        guard let schedule,
              let applicationSecrets,
              let protector = clientAppProtector else {
            throw TLSError.invalidState("client application keys are not ready")
        }
        let opened = try openHandshakeRecord(bytes, protector: protector)
        let decoder = TLSHandshakeDecoder()
        decoder.append(opened)
        guard let message = try decoder.nextMessage(), message.type == .keyUpdate else {
            throw TLSError.unexpectedMessage("client KeyUpdate expected")
        }
        let next = schedule.nextTrafficSecret(
            applicationSecrets.clientApplicationTrafficSecret
        )
        let keys = schedule.trafficKeys(trafficSecret: next, keyLength: suite.keyLength)
        try protector.reset(suite: suite, key: keys.key, iv: keys.iv)
        self.applicationSecrets = TLSApplicationSecrets(
            clientApplicationTrafficSecret: next,
            serverApplicationTrafficSecret: applicationSecrets.serverApplicationTrafficSecret
        )
    }

    // MARK: - Helpers

    private func firstHandshakeRecord(
        in bytes: [UInt8]
    ) throws -> (TLSRecord, TLSHandshakeMessage) {
        let decoder = TLSRecordDecoder()
        decoder.append(bytes)
        while let record = try decoder.nextRecord() {
            guard record.type == .handshake else { continue }
            let handshakeDecoder = TLSHandshakeDecoder()
            handshakeDecoder.append(record.fragment)
            guard let message = try handshakeDecoder.nextMessage() else { continue }
            return (record, message)
        }
        throw TLSError.unexpectedMessage("ClientHello expected")
    }

    private func parseKeyShare(_ hello: TLSClientHello) throws -> [UInt8] {
        guard let data = hello.extensions[TLSExtensionType.keyShare] else {
            throw TLSError.missingExtension(TLSExtensionType.keyShare)
        }
        var reader = ByteReader(data)
        let listLength = Int(try reader.readUInt16())
        guard listLength == reader.remaining else { throw TLSError.invalidExtension(0x0033) }
        let group = try reader.readUInt16()
        let key = try reader.readLengthPrefixed16()
        guard group == 0x001d, key.count == 32, reader.isAtEnd else {
            throw TLSError.invalidKeyShare
        }
        return key
    }

    private func keyShareExtension() -> [UInt8] {
        let key = Array(privateKey.publicKey.rawRepresentation)
        return [0x00, 0x1d, 0x00, UInt8(key.count)] + key
    }

    private func certificateMessage() -> TLSHandshakeMessage {
        var body = ByteWriter()
        body.writeLengthPrefixed8([])
        var entries = ByteWriter()
        for der in certificateChainDER.isEmpty ? [certificateDER] : certificateChainDER {
            entries.writeLengthPrefixed24(der)
            entries.writeLengthPrefixed16([])
        }
        body.writeLengthPrefixed24(entries.bytes)
        return TLSHandshakeMessage(type: .certificate, body: body.bytes)
    }

    private func certificateVerifyMessage(signedContent: [UInt8]) throws -> TLSHandshakeMessage {
        var body = ByteWriter()
        body.writeUInt16(certificateVerifyScheme)
        let signature = try certificateVerifySigner?(signedContent) ?? [0xde, 0xad, 0xbe, 0xef]
        body.writeLengthPrefixed16(signature)
        return TLSHandshakeMessage(type: .certificateVerify, body: body.bytes)
    }

    private func openHandshakeRecord(
        _ bytes: [UInt8],
        protector: TLSRecordProtector
    ) throws -> [UInt8] {
        let decoder = TLSRecordDecoder()
        decoder.append(bytes)
        var plaintext: [UInt8] = []
        while let record = try decoder.nextRecord() {
            let opened = try protector.open(
                fragment: record.fragment,
                type: record.type,
                version: record.version
            )
            guard opened.contentType == .handshake else {
                throw TLSError.unexpectedMessage("handshake record expected")
            }
            plaintext.append(contentsOf: opened.plaintext)
        }
        return plaintext
    }
}
