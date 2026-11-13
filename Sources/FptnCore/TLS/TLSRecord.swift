import Foundation

public enum TLSRecordType: UInt8, Sendable {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
}

public struct TLSRecord: Equatable, Sendable {
    public let type: TLSRecordType
    public let version: UInt16
    public let fragment: [UInt8]

    public init(type: TLSRecordType, version: UInt16 = 0x0303, fragment: [UInt8]) {
        self.type = type
        self.version = version
        self.fragment = fragment
    }

    public func encoded() -> [UInt8] {
        var output: [UInt8] = [
            type.rawValue,
            UInt8((version >> 8) & 0xff),
            UInt8(version & 0xff),
            UInt8((fragment.count >> 8) & 0xff),
            UInt8(fragment.count & 0xff)
        ]
        output.append(contentsOf: fragment)
        return output
    }
}

/// Incrementally decodes TLS records from a byte stream.
public final class TLSRecordDecoder {
    /// Maximum ciphertext size: 2^14 plaintext + 256 bytes of expansion.
    public static let maximumCiphertextLength = 16_384 + 256

    public let maxRecordSize: Int
    private var buffer: [UInt8] = []
    private var cursor = 0

    public init(maxRecordSize: Int = TLSRecordDecoder.maximumCiphertextLength) {
        self.maxRecordSize = maxRecordSize
    }

    public func append(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    public var bufferedByteCount: Int { buffer.count - cursor }

    public func nextRecord() throws -> TLSRecord? {
        let available = buffer.count - cursor
        guard available >= 5 else { return nil }

        let typeByte = buffer[cursor]
        guard let type = TLSRecordType(rawValue: typeByte) else {
            throw TLSError.invalidRecordType(typeByte)
        }
        let version = UInt16(buffer[cursor + 1]) << 8 | UInt16(buffer[cursor + 2])
        let length = Int(buffer[cursor + 3]) << 8 | Int(buffer[cursor + 4])
        guard length <= maxRecordSize else { throw TLSError.recordTooLarge(length) }
        guard available >= 5 + length else { return nil }

        let start = cursor + 5
        let end = start + length
        let fragment = Array(buffer[start..<end])
        cursor = end
        compactIfNeeded()
        return TLSRecord(type: type, version: version, fragment: fragment)
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
