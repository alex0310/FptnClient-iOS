import Foundation

public enum TlsObfuscatorError: Error, Equatable, LocalizedError {
    case payloadTooLarge(Int)

    public var errorDescription: String? {
        switch self {
        case let .payloadTooLarge(size):
            return "TLS obfuscator payload is too large (\(size) bytes)."
        }
    }
}

/// FPTN `TlsObfuscator2`: wraps each handshake chunk into a fake TLS
/// application-data record with random padding and a single-byte XOR key.
///
/// The 22-byte header is:
/// `17 03 03 | content length (u16) | 8 random bytes | timestamp (u32) |
///  xor key (u8) | payload length (u16) | padding length (u16)`.
/// `content length` counts everything after the five-byte TLS header, i.e.
/// `17 + payload + padding`.
public struct TlsObfuscator2 {
    public static let headerSize = 22
    public static let maximumContentLength = 16_384
    public static let minimumPadding = 4_095
    public static let maximumPadding = 8_192
    public static let timestampWindow: UInt32 = 120

    private var buffer: [UInt8] = []

    public init() {}

    public var hasPendingData: Bool { !buffer.isEmpty }

    public mutating func push(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    public mutating func reset() {
        buffer.removeAll(keepingCapacity: false)
    }

    public func encode(payload: [UInt8], timestamp: UInt32) throws -> [UInt8] {
        guard payload.count <= 0xffff else {
            throw TlsObfuscatorError.payloadTooLarge(payload.count)
        }
        let fixed = Self.headerSize - 5 + payload.count
        guard fixed <= Self.maximumContentLength else {
            throw TlsObfuscatorError.payloadTooLarge(payload.count)
        }
        let maximumPadding = min(
            Self.maximumPadding,
            Self.maximumContentLength - fixed
        )
        let minimumPadding = min(Self.minimumPadding, maximumPadding)
        var generator = SystemRandomNumberGenerator()
        let paddingLength = Int.random(
            in: minimumPadding...maximumPadding,
            using: &generator
        )
        let xorKey = UInt8.random(in: .min ... .max, using: &generator)
        let contentLength = fixed + paddingLength

        var output: [UInt8] = []
        output.reserveCapacity(Self.headerSize + payload.count + paddingLength)
        output.append(0x17)
        output.append(0x03)
        output.append(0x03)
        output.append(UInt8((contentLength >> 8) & 0xff))
        output.append(UInt8(contentLength & 0xff))
        output.append(contentsOf: SecureRandom.bytes(8))
        output.append(UInt8((timestamp >> 24) & 0xff))
        output.append(UInt8((timestamp >> 16) & 0xff))
        output.append(UInt8((timestamp >> 8) & 0xff))
        output.append(UInt8(timestamp & 0xff))
        output.append(xorKey)
        output.append(UInt8((payload.count >> 8) & 0xff))
        output.append(UInt8(payload.count & 0xff))
        output.append(UInt8((paddingLength >> 8) & 0xff))
        output.append(UInt8(paddingLength & 0xff))
        output.append(contentsOf: payload.map { $0 ^ xorKey })
        output.append(contentsOf: SecureRandom.bytes(paddingLength))
        return output
    }

    /// Returns one deobfuscated payload, or `nil` when more bytes are needed.
    /// Garbage before a valid header is skipped, mirroring upstream.
    public mutating func nextPayload(now: UInt32) -> [UInt8]? {
        var searchOffset = 0
        while buffer.count - searchOffset >= Self.headerSize {
            let header = Array(buffer[searchOffset..<(searchOffset + Self.headerSize)])
            let contentLength = Int(header[3]) << 8 | Int(header[4])
            let timestamp = UInt32(header[13]) << 24
                | UInt32(header[14]) << 16
                | UInt32(header[15]) << 8
                | UInt32(header[16])
            let xorKey = header[17]
            let payloadLength = Int(header[18]) << 8 | Int(header[19])
            let paddingLength = Int(header[20]) << 8 | Int(header[21])

            let looksValid = header[0] == 0x17 && header[1] == 0x03 && header[2] == 0x03
            let minimumContent = Self.headerSize - 5 + payloadLength + paddingLength
            let timestampValid = timestamp <= now &+ Self.timestampWindow
                && timestamp &+ Self.timestampWindow >= now
            guard looksValid,
                  timestampValid,
                  contentLength >= minimumContent,
                  contentLength <= Self.maximumContentLength else {
                searchOffset += 1
                continue
            }

            let recordSize = Self.headerSize + payloadLength + paddingLength
            guard buffer.count - searchOffset >= recordSize else {
                if searchOffset > 0 {
                    buffer.removeFirst(searchOffset)
                }
                return nil
            }

            let start = searchOffset + Self.headerSize
            let end = start + payloadLength
            let payload = buffer[start..<end].map { $0 ^ xorKey }
            buffer.removeFirst(searchOffset + recordSize)
            return payload
        }

        if searchOffset > 0 {
            buffer.removeFirst(searchOffset)
        }
        return nil
    }
}
