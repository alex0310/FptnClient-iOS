import Foundation

public struct TLSServerHello: Equatable, Sendable {
    public static let helloRetryRequestRandom = hexBytes(
        "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    )

    public let legacyVersion: UInt16
    public let random: [UInt8]
    public let sessionID: [UInt8]
    public let cipherSuite: UInt16
    public let compressionMethod: UInt8
    public let extensions: [UInt16: [UInt8]]

    public var isHelloRetryRequest: Bool {
        random == Self.helloRetryRequestRandom
    }

    public var selectedVersion: UInt16? {
        guard let data = extensions[TLSExtensionType.supportedVersions], data.count == 2 else {
            return nil
        }
        return UInt16(data[0]) << 8 | UInt16(data[1])
    }

    public var keyShare: (group: UInt16, key: [UInt8])? {
        guard let data = extensions[TLSExtensionType.keyShare] else { return nil }
        var reader = ByteReader(data)
        guard let group = try? reader.readUInt16(),
              let key = try? reader.readLengthPrefixed16(),
              reader.isAtEnd else { return nil }
        return (group, key)
    }

    public func encoded() -> [UInt8] {
        var body: [UInt8] = []
        body.append(UInt8((legacyVersion >> 8) & 0xff))
        body.append(UInt8(legacyVersion & 0xff))
        body.append(contentsOf: random)
        body.append(UInt8(sessionID.count))
        body.append(contentsOf: sessionID)
        body.append(UInt8((cipherSuite >> 8) & 0xff))
        body.append(UInt8(cipherSuite & 0xff))
        body.append(compressionMethod)
        body.append(contentsOf: TLSExtensions.encode(extensions.map {
            TLSExtension(type: $0.key, data: $0.value)
        }.sorted { $0.type < $1.type }))
        return TLSHandshakeMessage(type: .serverHello, body: body).encoded()
    }

    public static func parse(_ message: TLSHandshakeMessage) throws -> TLSServerHello {
        guard message.type == .serverHello else {
            throw TLSError.unexpectedMessage("ServerHello expected")
        }
        var reader = ByteReader(message.body)
        let legacyVersion = try reader.readUInt16()
        let random = try reader.readBytes(32)
        let sessionID = try reader.readLengthPrefixed8()
        let cipherSuite = try reader.readUInt16()
        let compression = try reader.readUInt8()
        let remaining = reader.remaining
        let extensions = try TLSExtensions.parse(reader.readBytes(remaining))
        return TLSServerHello(
            legacyVersion: legacyVersion,
            random: random,
            sessionID: sessionID,
            cipherSuite: cipherSuite,
            compressionMethod: compression,
            extensions: extensions
        )
    }
}

private func hexBytes(_ string: String) -> [UInt8] {
    Hex.decode(string) ?? []
}
