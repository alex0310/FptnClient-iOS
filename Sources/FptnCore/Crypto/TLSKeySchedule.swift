import Foundation

public struct TLSTrafficSecrets: Equatable, Sendable {
    public let handshakeSecret: [UInt8]
    public let masterSecret: [UInt8]
    public let clientHandshakeTrafficSecret: [UInt8]
    public let serverHandshakeTrafficSecret: [UInt8]

    public init(
        handshakeSecret: [UInt8],
        masterSecret: [UInt8],
        clientHandshakeTrafficSecret: [UInt8],
        serverHandshakeTrafficSecret: [UInt8]
    ) {
        self.handshakeSecret = handshakeSecret
        self.masterSecret = masterSecret
        self.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
        self.serverHandshakeTrafficSecret = serverHandshakeTrafficSecret
    }
}

public struct TLSApplicationSecrets: Equatable, Sendable {
    public let clientApplicationTrafficSecret: [UInt8]
    public let serverApplicationTrafficSecret: [UInt8]

    public init(clientApplicationTrafficSecret: [UInt8], serverApplicationTrafficSecret: [UInt8]) {
        self.clientApplicationTrafficSecret = clientApplicationTrafficSecret
        self.serverApplicationTrafficSecret = serverApplicationTrafficSecret
    }
}

public struct TLSTrafficKeys: Equatable, Sendable {
    public let key: [UInt8]
    public let iv: [UInt8]

    public init(key: [UInt8], iv: [UInt8]) {
        self.key = key
        self.iv = iv
    }
}

/// The TLS 1.3 key schedule from RFC 8446 section 7.1.
public struct TLSKeySchedule {
    public let hash: TLSHash
    private var transcript: [UInt8] = []
    private let emptyHash: [UInt8]

    public init(hash: TLSHash) {
        self.hash = hash
        self.emptyHash = hash.hash([])
    }

    public mutating func appendTranscript(_ handshakeMessage: [UInt8]) {
        transcript.append(contentsOf: handshakeMessage)
    }

    public func transcriptHash() -> [UInt8] {
        hash.hash(transcript)
    }

    public func earlySecret() -> [UInt8] {
        HKDF.extract(
            hash: hash,
            salt: [UInt8](repeating: 0, count: hash.length),
            inputKeyMaterial: [UInt8](repeating: 0, count: hash.length)
        )
    }

    public func handshakeSecrets(sharedSecret: [UInt8]) -> TLSTrafficSecrets {
        let early = earlySecret()
        let derived = HKDF.expandLabel(
            hash: hash,
            secret: early,
            label: "derived",
            context: emptyHash,
            length: hash.length
        )
        let handshakeSecret = HKDF.extract(hash: hash, salt: derived, inputKeyMaterial: sharedSecret)
        let transcriptHash = self.transcriptHash()
        let client = HKDF.deriveSecret(
            hash: hash,
            secret: handshakeSecret,
            label: "c hs traffic",
            transcriptHash: transcriptHash
        )
        let server = HKDF.deriveSecret(
            hash: hash,
            secret: handshakeSecret,
            label: "s hs traffic",
            transcriptHash: transcriptHash
        )
        let masterDerived = HKDF.expandLabel(
            hash: hash,
            secret: handshakeSecret,
            label: "derived",
            context: emptyHash,
            length: hash.length
        )
        let masterSecret = HKDF.extract(
            hash: hash,
            salt: masterDerived,
            inputKeyMaterial: [UInt8](repeating: 0, count: hash.length)
        )
        return TLSTrafficSecrets(
            handshakeSecret: handshakeSecret,
            masterSecret: masterSecret,
            clientHandshakeTrafficSecret: client,
            serverHandshakeTrafficSecret: server
        )
    }

    public func applicationSecrets(masterSecret: [UInt8]) -> TLSApplicationSecrets {
        let transcriptHash = self.transcriptHash()
        let client = HKDF.deriveSecret(
            hash: hash,
            secret: masterSecret,
            label: "c ap traffic",
            transcriptHash: transcriptHash
        )
        let server = HKDF.deriveSecret(
            hash: hash,
            secret: masterSecret,
            label: "s ap traffic",
            transcriptHash: transcriptHash
        )
        return TLSApplicationSecrets(
            clientApplicationTrafficSecret: client,
            serverApplicationTrafficSecret: server
        )
    }

    public func trafficKeys(trafficSecret: [UInt8], keyLength: Int) -> TLSTrafficKeys {
        let key = HKDF.expandLabel(
            hash: hash,
            secret: trafficSecret,
            label: "key",
            context: [],
            length: keyLength
        )
        let iv = HKDF.expandLabel(
            hash: hash,
            secret: trafficSecret,
            label: "iv",
            context: [],
            length: 12
        )
        return TLSTrafficKeys(key: key, iv: iv)
    }

    public func finishedKey(trafficSecret: [UInt8]) -> [UInt8] {
        HKDF.expandLabel(
            hash: hash,
            secret: trafficSecret,
            label: "finished",
            context: [],
            length: hash.length
        )
    }

    public func finishedVerifyData(trafficSecret: [UInt8], transcriptHash: [UInt8]) -> [UInt8] {
        hash.hmac(key: finishedKey(trafficSecret: trafficSecret), data: transcriptHash)
    }

    public func nextTrafficSecret(_ trafficSecret: [UInt8]) -> [UInt8] {
        HKDF.deriveSecret(
            hash: hash,
            secret: trafficSecret,
            label: "traffic upd",
            transcriptHash: emptyHash
        )
    }
}
