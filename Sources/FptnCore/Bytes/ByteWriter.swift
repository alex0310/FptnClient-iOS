import Foundation

/// Small big-endian writer shared by protocol and TLS codecs.
public struct ByteWriter {
    public private(set) var bytes: [UInt8]

    public init(reservingCapacity: Int = 0) {
        bytes = []
        bytes.reserveCapacity(reservingCapacity)
    }

    public mutating func write(_ byte: UInt8) {
        bytes.append(byte)
    }

    public mutating func write(contentsOf newBytes: [UInt8]) {
        bytes.append(contentsOf: newBytes)
    }

    public mutating func write(contentsOf slice: ArraySlice<UInt8>) {
        bytes.append(contentsOf: slice)
    }

    public mutating func writeUInt16(_ value: UInt16) {
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    public mutating func writeUInt24(_ value: UInt32) {
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    public mutating func writeUInt64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    public mutating func writeVarint(_ value: UInt64) {
        var remaining = value
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            bytes.append(byte)
        } while remaining != 0
    }

    public mutating func writeLengthPrefixed8(_ payload: [UInt8]) {
        precondition(payload.count <= 0xff)
        write(UInt8(payload.count))
        write(contentsOf: payload)
    }

    public mutating func writeLengthPrefixed16(_ payload: [UInt8]) {
        precondition(payload.count <= 0xffff)
        writeUInt16(UInt16(payload.count))
        write(contentsOf: payload)
    }

    public mutating func writeLengthPrefixed24(_ payload: [UInt8]) {
        precondition(payload.count <= 0xff_ffff)
        writeUInt24(UInt32(payload.count))
        write(contentsOf: payload)
    }

    /// Writes a length placeholder and returns its byte offset.
    public mutating func reserveUInt16Length() -> Int {
        let offset = bytes.count
        writeUInt16(0)
        return offset
    }

    public mutating func reserveUInt24Length() -> Int {
        let offset = bytes.count
        writeUInt24(0)
        return offset
    }

    public mutating func patchUInt16Length(at offset: Int, length: Int) {
        precondition(length <= 0xffff)
        bytes[offset] = UInt8((length >> 8) & 0xff)
        bytes[offset + 1] = UInt8(length & 0xff)
    }

    public mutating func patchUInt24Length(at offset: Int, length: Int) {
        precondition(length <= 0xff_ffff)
        bytes[offset] = UInt8((length >> 16) & 0xff)
        bytes[offset + 1] = UInt8((length >> 8) & 0xff)
        bytes[offset + 2] = UInt8(length & 0xff)
    }
}
