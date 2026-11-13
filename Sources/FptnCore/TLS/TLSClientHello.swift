import Foundation

/// TLS 1.3 ClientHello construction and parsing.
public struct TLSClientHello: Equatable, Sendable {
    public let legacyVersion: UInt16
    public let random: [UInt8]
    public let sessionID: [UInt8]
    public let cipherSuites: [UInt16]
    public let compressionMethods: [UInt8]
    public let extensions: [UInt16: [UInt8]]

    public init(
        legacyVersion: UInt16,
        random: [UInt8],
        sessionID: [UInt8],
        cipherSuites: [UInt16],
        compressionMethods: [UInt8],
        extensions: [UInt16: [UInt8]]
    ) {
        self.legacyVersion = legacyVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuites = cipherSuites
        self.compressionMethods = compressionMethods
        self.extensions = extensions
    }

    public func encoded() -> [UInt8] {
        var body: [UInt8] = []
        body.append(UInt8((legacyVersion >> 8) & 0xff))
        body.append(UInt8(legacyVersion & 0xff))
        body.append(contentsOf: random)
        body.append(UInt8(sessionID.count))
        body.append(contentsOf: sessionID)
        body.append(UInt8((cipherSuites.count * 2 >> 8) & 0xff))
        body.append(UInt8((cipherSuites.count * 2) & 0xff))
        for suite in cipherSuites {
            body.append(UInt8((suite >> 8) & 0xff))
            body.append(UInt8(suite & 0xff))
        }
        body.append(UInt8(compressionMethods.count))
        body.append(contentsOf: compressionMethods)
        body.append(contentsOf: TLSExtensions.encode(extensions.map {
            TLSExtension(type: $0.key, data: $0.value)
        }.sorted { $0.type < $1.type }))
        return TLSHandshakeMessage(type: .clientHello, body: body).encoded()
    }

    public static func parse(_ message: TLSHandshakeMessage) throws -> TLSClientHello {
        guard message.type == .clientHello else {
            throw TLSError.unexpectedMessage("ClientHello expected")
        }
        var reader = ByteReader(message.body)
        let legacyVersion = try reader.readUInt16()
        let random = try reader.readBytes(32)
        let sessionID = try reader.readLengthPrefixed8()
        guard sessionID.count <= 32 else { throw TLSError.invalidConfiguration("session id too long") }
        let suitesLength = Int(try reader.readUInt16())
        guard suitesLength.isMultiple(of: 2) else { throw TLSError.invalidExtension(0) }
        var suites: [UInt16] = []
        for _ in 0..<(suitesLength / 2) {
            suites.append(try reader.readUInt16())
        }
        let compression = try reader.readLengthPrefixed8()
        let remaining = reader.remaining
        let extensions = try TLSExtensions.parse(reader.readBytes(remaining))
        return TLSClientHello(
            legacyVersion: legacyVersion,
            random: random,
            sessionID: sessionID,
            cipherSuites: suites,
            compressionMethods: compression,
            extensions: extensions
        )
    }
}

public struct TLSClientHelloBuilder {
    public var serverName: String
    public var random: [UInt8]
    public var sessionID: [UInt8]
    public var keyShare: [UInt8]
    public var cipherSuites: [TLSCipherSuite]

    public init(
        serverName: String,
        random: [UInt8],
        sessionID: [UInt8],
        keyShare: [UInt8],
        cipherSuites: [TLSCipherSuite] = TLSCipherSuite.allCases
    ) {
        self.serverName = serverName
        self.random = random
        self.sessionID = sessionID
        self.keyShare = keyShare
        self.cipherSuites = cipherSuites
    }

    public func build() throws -> TLSHandshakeMessage {
        guard random.count == 32 else {
            throw TLSError.invalidConfiguration("ClientHello random must be 32 bytes")
        }
        guard sessionID.count <= 32 else {
            throw TLSError.invalidConfiguration("ClientHello session id must be at most 32 bytes")
        }
        guard keyShare.count == 32 else {
            throw TLSError.invalidConfiguration("x25519 key share must be 32 bytes")
        }
        guard !serverName.isEmpty, serverName.utf8.count <= 255 else {
            throw TLSError.invalidConfiguration("invalid server name")
        }
        guard !cipherSuites.isEmpty else {
            throw TLSError.invalidConfiguration("no cipher suites configured")
        }

        let sniList = [UInt8(0)] + bigEndian16(UInt16(serverName.utf8.count)) + Array(serverName.utf8)
        let sni = bigEndian16(UInt16(sniList.count)) + sniList

        let groups: [UInt16] = [0x001d, 0x0017, 0x0018]
        var groupBytes: [UInt8] = []
        for group in groups { groupBytes.append(contentsOf: bigEndian16(group)) }
        let supportedGroups = bigEndian16(UInt16(groupBytes.count)) + groupBytes

        let schemes: [UInt16] = [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0201
        ]
        var schemeBytes: [UInt8] = []
        for scheme in schemes { schemeBytes.append(contentsOf: bigEndian16(scheme)) }
        let signatureAlgorithms = bigEndian16(UInt16(schemeBytes.count)) + schemeBytes

        let supportedVersions: [UInt8] = [2, 0x03, 0x04]
        let keyShareData = bigEndian16(UInt16(4 + keyShare.count))
            + bigEndian16(0x001d)
            + bigEndian16(UInt16(keyShare.count))
            + keyShare
        let pointFormats: [UInt8] = [1, 0]

        let extensions: [TLSExtension] = [
            TLSExtension(type: TLSExtensionType.serverName, data: sni),
            TLSExtension(type: TLSExtensionType.ecPointFormats, data: pointFormats),
            TLSExtension(type: TLSExtensionType.supportedGroups, data: supportedGroups),
            TLSExtension(type: TLSExtensionType.signatureAlgorithms, data: signatureAlgorithms),
            TLSExtension(type: TLSExtensionType.supportedVersions, data: supportedVersions),
            TLSExtension(type: TLSExtensionType.keyShare, data: keyShareData),
            TLSExtension(type: TLSExtensionType.sessionTicket, data: [])
        ]

        var body: [UInt8] = []
        body.append(contentsOf: bigEndian16(0x0303))
        body.append(contentsOf: random)
        body.append(UInt8(sessionID.count))
        body.append(contentsOf: sessionID)
        let suitesLength = UInt16(cipherSuites.count * 2)
        body.append(contentsOf: bigEndian16(suitesLength))
        for suite in cipherSuites {
            body.append(contentsOf: bigEndian16(suite.rawValue))
        }
        body.append(1)
        body.append(0)
        body.append(contentsOf: TLSExtensions.encode(extensions))
        return TLSHandshakeMessage(type: .clientHello, body: body)
    }

    private func bigEndian16(_ value: UInt16) -> [UInt8] {
        [UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
    }
}
