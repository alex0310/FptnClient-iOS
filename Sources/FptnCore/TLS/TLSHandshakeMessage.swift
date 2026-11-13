import Foundation

public enum TLSHandshakeType: UInt8, Sendable {
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case encryptedExtensions = 8
    case certificate = 11
    case certificateRequest = 13
    case certificateVerify = 15
    case finished = 20
    case keyUpdate = 24
}

public struct TLSHandshakeMessage: Equatable, Sendable {
    public let type: TLSHandshakeType
    public let body: [UInt8]

    public init(type: TLSHandshakeType, body: [UInt8]) {
        self.type = type
        self.body = body
    }

    public func encoded() -> [UInt8] {
        var output: [UInt8] = [type.rawValue]
        let length = body.count
        output.append(UInt8((length >> 16) & 0xff))
        output.append(UInt8((length >> 8) & 0xff))
        output.append(UInt8(length & 0xff))
        output.append(contentsOf: body)
        return output
    }
}

/// Reassembles TLS handshake messages that may span record boundaries.
public final class TLSHandshakeDecoder {
    public let maxHandshakeSize: Int
    private var buffer: [UInt8] = []
    private var cursor = 0

    public init(maxHandshakeSize: Int = 1 << 20) {
        self.maxHandshakeSize = maxHandshakeSize
    }

    public func append(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    public var bufferedByteCount: Int { buffer.count - cursor }

    public func nextMessage() throws -> TLSHandshakeMessage? {
        let available = buffer.count - cursor
        guard available >= 4 else { return nil }

        let rawType = buffer[cursor]
        guard let type = TLSHandshakeType(rawValue: rawType) else {
            throw TLSError.invalidHandshakeType(rawType)
        }
        let length = Int(buffer[cursor + 1]) << 16
            | Int(buffer[cursor + 2]) << 8
            | Int(buffer[cursor + 3])
        guard length <= maxHandshakeSize else { throw TLSError.handshakeTooLarge(length) }
        guard available >= 4 + length else { return nil }

        let start = cursor + 4
        let end = start + length
        let body = Array(buffer[start..<end])
        cursor = end
        compactIfNeeded()
        return TLSHandshakeMessage(type: type, body: body)
    }

    private func compactIfNeeded() {
        guard cursor > 0 else { return }
        if cursor == buffer.count {
            buffer.removeAll(keepingCapacity: true)
            cursor = 0
        } else if cursor >= 4096 {
            buffer.removeFirst(cursor)
            cursor = 0
        }
    }
}

public struct TLSExtension: Equatable, Sendable {
    public let type: UInt16
    public let data: [UInt8]

    public init(type: UInt16, data: [UInt8]) {
        self.type = type
        self.data = data
    }

    public func encoded() -> [UInt8] {
        var output: [UInt8] = [
            UInt8((type >> 8) & 0xff),
            UInt8(type & 0xff),
            UInt8((data.count >> 8) & 0xff),
            UInt8(data.count & 0xff)
        ]
        output.append(contentsOf: data)
        return output
    }
}

public enum TLSExtensionType {
    public static let serverName: UInt16 = 0x0000
    public static let supportedGroups: UInt16 = 0x000a
    public static let signatureAlgorithms: UInt16 = 0x000d
    public static let supportedVersions: UInt16 = 0x002b
    public static let keyShare: UInt16 = 0x0033
    public static let preSharedKey: UInt16 = 0x0029
    public static let sessionTicket: UInt16 = 0x0023
    public static let ecPointFormats: UInt16 = 0x000b
}

public enum TLSExtensions {
    public static func encode(_ extensions: [TLSExtension]) -> [UInt8] {
        var body: [UInt8] = []
        for ext in extensions {
            body.append(contentsOf: ext.encoded())
        }
        return [UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)] + body
    }

    /// Parses a complete `Extensions` block, including its outer `u16` length.
    public static func parse(_ bytes: [UInt8]) throws -> [UInt16: [UInt8]] {
        var outer = ByteReader(bytes)
        let block = try outer.readLengthPrefixed16()
        guard outer.isAtEnd else { throw TLSError.invalidExtension(0) }
        var reader = ByteReader(block)
        var result: [UInt16: [UInt8]] = [:]
        while !reader.isAtEnd {
            let type = try reader.readUInt16()
            let data = try reader.readLengthPrefixed16()
            guard result[type] == nil else { throw TLSError.invalidExtension(type) }
            result[type] = data
        }
        return result
    }
}
