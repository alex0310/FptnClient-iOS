import Foundation

public enum ByteReaderError: Error, Equatable {
    case outOfBounds(offset: Int, needed: Int, available: Int)
    case invalidVarint
}

/// Bounds-checked big-endian reader used by protocol and TLS codecs.
public struct ByteReader {
    public let bytes: [UInt8]
    public private(set) var offset: Int

    public init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    public var remaining: Int { bytes.count - offset }
    public var isAtEnd: Bool { offset >= bytes.count }

    public mutating func readUInt8() throws -> UInt8 {
        try require(1)
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func readUInt16() throws -> UInt16 {
        try require(2)
        defer { offset += 2 }
        return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    public mutating func readUInt24() throws -> UInt32 {
        try require(3)
        defer { offset += 3 }
        return UInt32(bytes[offset]) << 16
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2])
    }

    public mutating func readUInt32() throws -> UInt32 {
        try require(4)
        defer { offset += 4 }
        return UInt32(bytes[offset]) << 24
            | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8
            | UInt32(bytes[offset + 3])
    }

    public mutating func readUInt64() throws -> UInt64 {
        try require(8)
        defer { offset += 8 }
        var value: UInt64 = 0
        for index in 0..<8 {
            value = value << 8 | UInt64(bytes[offset + index])
        }
        return value
    }

    public mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count >= 0 else { throw ByteReaderError.outOfBounds(offset: offset, needed: count, available: remaining) }
        try require(count)
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    public mutating func readSlice(_ count: Int) throws -> ArraySlice<UInt8> {
        guard count >= 0 else { throw ByteReaderError.outOfBounds(offset: offset, needed: count, available: remaining) }
        try require(count)
        defer { offset += count }
        return bytes[offset..<offset + count]
    }

    public mutating func readLengthPrefixed8() throws -> [UInt8] {
        try readBytes(Int(try readUInt8()))
    }

    public mutating func readLengthPrefixed16() throws -> [UInt8] {
        try readBytes(Int(try readUInt16()))
    }

    public mutating func readLengthPrefixed24() throws -> [UInt8] {
        try readBytes(Int(try readUInt24()))
    }

    public mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard shift < 64 else { throw ByteReaderError.invalidVarint }
            let byte = try readUInt8()
            result |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
    }

    public mutating func skip(_ count: Int) throws {
        guard count >= 0 else { throw ByteReaderError.outOfBounds(offset: offset, needed: count, available: remaining) }
        try require(count)
        offset += count
    }

    private func require(_ count: Int) throws {
        guard count <= remaining else {
            throw ByteReaderError.outOfBounds(offset: offset, needed: count, available: remaining)
        }
    }
}
