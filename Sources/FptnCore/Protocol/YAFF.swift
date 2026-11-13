import Foundation

/// Swift port of the YAFF subset used by the FPTN wire protocol.
///
/// The reference implementation writes into a buffer that grows downwards, so
/// nested objects are addressed by their offset from the end of the frame. To
/// keep the port auditable we mirror that model literally: `ReversedBuffer`
/// stores the output backwards and `push` prepends logically.
public enum YAFF {
    public static let protocolVersion: Int32 = 1

    public static let msgError: Int32 = 0
    public static let msgIpPacket: Int32 = 1
    public static let msgIpAssignment: Int32 = 2
    public static let msgBatchIpPacket: Int32 = 3

    public struct IPPacketData: Equatable {
        public let payload: [UInt8]
        public let paddingData: [UInt8]?

        public init(payload: [UInt8], paddingData: [UInt8]? = nil) {
            self.payload = payload
            self.paddingData = paddingData
        }
    }

    public enum Incoming: Equatable {
        case batch([[UInt8]])
        case ipPacket([UInt8])
        case ipAssignment(ipv4: [UInt8], ipv6: [UInt8])
        case error(errorType: Int32, message: String)
    }

    private static let messageOffsets: [UInt16] = [0, 4, 8, 12, 16, 20, 24]
    private static let ipPacketOffsets: [UInt16] = [0, 4, 8]
    private static let ipAssignmentOffsets: [UInt16] = [0, 4, 8]
    private static let batchOffsets: [UInt16] = [0, 4]

    // MARK: - Encoding

    public static func serializeIpPacketMessage(
        payload: [UInt8],
        paddingData: [UInt8]? = nil
    ) -> [UInt8] {
        var buffer = ReversedBuffer()
        let payloadOffset = serializeString(&buffer, payload)
        let paddingOffset = paddingData.map { serializeString(&buffer, $0) } ?? 0

        let packet = serializeFlat(
            &buffer,
            offsets: ipPacketOffsets,
            fields: [
                .offset(id: 2, offset: paddingOffset),
                .offset(id: 1, offset: payloadOffset)
            ]
        )

        let message = serializeFlat(
            &buffer,
            offsets: messageOffsets,
            fields: [
                .offset(id: 6, offset: 0),
                .offset(id: 5, offset: 0),
                .offset(id: 4, offset: packet),
                .offset(id: 3, offset: 0),
                .scalar(id: 2, value: msgIpPacket, defaultValue: 0),
                .scalar(id: 1, value: protocolVersion, defaultValue: 0)
            ]
        )
        return buffer.finish(rootEnd: message)
    }

    public static func serializeErrorMessage(errorType: Int32, message: String) -> [UInt8] {
        var buffer = ReversedBuffer()
        let messageOffset = serializeString(&buffer, Array(message.utf8))

        let error = serializeFlat(
            &buffer,
            offsets: [0, 4, 8],
            fields: [
                .offset(id: 2, offset: messageOffset),
                .scalar(id: 1, value: errorType, defaultValue: 0)
            ]
        )

        let top = serializeFlat(
            &buffer,
            offsets: messageOffsets,
            fields: [
                .offset(id: 6, offset: 0),
                .offset(id: 5, offset: 0),
                .offset(id: 4, offset: 0),
                .offset(id: 3, offset: error),
                .scalar(id: 2, value: msgError, defaultValue: 0),
                .scalar(id: 1, value: protocolVersion, defaultValue: 0)
            ]
        )
        return buffer.finish(rootEnd: top)
    }

    public static func serializeIpAssignmentMessage(ipv4: [UInt8], ipv6: [UInt8]) -> [UInt8] {
        var buffer = ReversedBuffer()
        let ipv4Offset = serializeString(&buffer, ipv4)
        let ipv6Offset = serializeString(&buffer, ipv6)

        let assignment = serializeFlat(
            &buffer,
            offsets: ipAssignmentOffsets,
            fields: [
                .offset(id: 2, offset: ipv6Offset),
                .offset(id: 1, offset: ipv4Offset)
            ]
        )

        let message = serializeFlat(
            &buffer,
            offsets: messageOffsets,
            fields: [
                .offset(id: 6, offset: 0),
                .offset(id: 5, offset: assignment),
                .offset(id: 4, offset: 0),
                .offset(id: 3, offset: 0),
                .scalar(id: 2, value: msgIpAssignment, defaultValue: 0),
                .scalar(id: 1, value: protocolVersion, defaultValue: 0)
            ]
        )
        return buffer.finish(rootEnd: message)
    }

    public static func serializeBatchMessage(_ packets: [IPPacketData]) -> [UInt8]? {
        var blobs: [[UInt8]] = []
        blobs.reserveCapacity(packets.count)
        for packet in packets where !packet.payload.isEmpty {
            blobs.append(serializeIpPacketMessage(payload: packet.payload, paddingData: packet.paddingData))
        }
        guard !blobs.isEmpty else { return nil }

        var buffer = ReversedBuffer()
        var elementOffsets: [Int] = []
        elementOffsets.reserveCapacity(blobs.count)
        for blob in blobs {
            elementOffsets.append(serializeString(&buffer, blob))
        }
        let array = serializeOffsetArray(&buffer, elements: elementOffsets)

        let batch = serializeFlat(
            &buffer,
            offsets: batchOffsets,
            fields: [.offset(id: 1, offset: array)]
        )

        let message = serializeFlat(
            &buffer,
            offsets: messageOffsets,
            fields: [
                .offset(id: 6, offset: batch),
                .offset(id: 5, offset: 0),
                .offset(id: 4, offset: 0),
                .offset(id: 3, offset: 0),
                .scalar(id: 2, value: msgBatchIpPacket, defaultValue: 0),
                .scalar(id: 1, value: protocolVersion, defaultValue: 0)
            ]
        )
        return buffer.finish(rootEnd: message)
    }

    // MARK: - Decoding

    public static func parseMessage(_ data: [UInt8]) -> Incoming? {
        guard let root = readU32(data[...], 0), Int(root) <= data.count else {
            return nil
        }
        let message = data.dropFirst(Int(root))
        guard let reader = FlatReader(message) else { return nil }
        guard let messageType = reader.scalar(id: 2, offset: 4, defaultValue: 0) else { return nil }

        switch messageType {
        case msgBatchIpPacket:
            guard
                let batchSlice = reader.nested(id: 6, offset: 20),
                let batch = FlatReader(batchSlice),
                let array = batch.nested(id: 1, offset: 0),
                let blobs = parseOffsetArray(array)
            else { return nil }
            let payloads = blobs.compactMap(parseInnerPayload)
            return .batch(payloads)

        case msgIpAssignment:
            guard
                let assignmentSlice = reader.nested(id: 5, offset: 16),
                let assignment = FlatReader(assignmentSlice),
                let ipv4Slice = assignment.nested(id: 1, offset: 0),
                let ipv6Slice = assignment.nested(id: 2, offset: 4),
                let ipv4 = parseString(ipv4Slice),
                let ipv6 = parseString(ipv6Slice)
            else { return nil }
            return .ipAssignment(ipv4: Array(ipv4), ipv6: Array(ipv6))

        case msgError:
            guard
                let errorSlice = reader.nested(id: 3, offset: 8),
                let error = FlatReader(errorSlice),
                let errorType = error.scalar(id: 1, offset: 0, defaultValue: 0)
            else { return nil }
            let message: String
            if let stringSlice = error.nested(id: 2, offset: 4), let raw = parseString(stringSlice) {
                message = String(decoding: raw, as: UTF8.self)
            } else {
                message = ""
            }
            return .error(errorType: errorType, message: message)

        case msgIpPacket:
            guard
                let packetSlice = reader.nested(id: 4, offset: 12),
                let packet = FlatReader(packetSlice),
                let payloadSlice = packet.nested(id: 1, offset: 0),
                let payload = parseString(payloadSlice)
            else { return nil }
            return .ipPacket(Array(payload))

        default:
            return nil
        }
    }

    private static func parseInnerPayload(_ blob: ArraySlice<UInt8>) -> [UInt8]? {
        guard let root = readU32(blob, 0) else { return nil }
        let message = blob.dropFirst(Int(root))
        guard
            let reader = FlatReader(message),
            reader.scalar(id: 2, offset: 4, defaultValue: 0) == msgIpPacket,
            let packetSlice = reader.nested(id: 4, offset: 12),
            let packet = FlatReader(packetSlice),
            let payloadSlice = packet.nested(id: 1, offset: 0),
            let payload = parseString(payloadSlice)
        else { return nil }
        return Array(payload)
    }

    private static func parseString(_ data: ArraySlice<UInt8>) -> ArraySlice<UInt8>? {
        guard let length = readU32(data, 0) else { return nil }
        guard length <= UInt32(data.count - 4) else { return nil }
        return data.dropFirst(4).prefix(Int(length))
    }

    private static func parseOffsetArray(_ data: ArraySlice<UInt8>) -> [ArraySlice<UInt8>]? {
        guard let count = readU32(data, 0), count <= 1024 else { return nil }
        var output: [ArraySlice<UInt8>] = []
        output.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            guard let pointer = readU32(data, 4 + index * 4) else { return nil }
            let elementStart = 4 + Int(pointer)
            guard elementStart <= data.count, let string = parseString(data.dropFirst(elementStart)) else {
                return nil
            }
            output.append(string)
        }
        return output
    }

    // MARK: - YAFF primitives

    private enum Field {
        case scalar(id: UInt16, value: Int32, defaultValue: Int32)
        case offset(id: UInt16, offset: Int)

        var id: UInt16 {
            switch self {
            case let .scalar(id, _, _): return id
            case let .offset(id, _): return id
            }
        }

        var isWritten: Bool {
            switch self {
            case .scalar: return true
            case let .offset(_, offset): return offset != 0
            }
        }
    }

    private static func serializeFlat(
        _ buffer: inout ReversedBuffer,
        offsets: [UInt16],
        fields: [Field]
    ) -> Int {
        guard let first = fields.first(where: { $0.isWritten }) else {
            preconditionFailure("a flat YAFF message needs at least one field")
        }
        let firstID = first.id
        let dataSize = 2 + Int(offsets[Int(firstID) - 1]) + 4
        let start = buffer.size
        let end = start + dataSize
        let maxID = firstID + 1

        var payload = [UInt8](repeating: 0, count: dataSize)
        for field in fields {
            switch field {
            case let .scalar(id, value, defaultValue):
                let position = 2 + Int(offsets[Int(id) - 1])
                putU32(&payload, position, UInt32(bitPattern: value ^ defaultValue))
            case let .offset(id, offset):
                if offset != 0 {
                    let relative = UInt32(end - offset)
                    let position = 2 + Int(offsets[Int(id) - 1])
                    putU32(&payload, position, relative)
                }
            }
        }

        let typedLimit = (maxID << 2) | 0x8000 | 0x0002
        payload[0] = UInt8(typedLimit & 0xff)
        payload[1] = UInt8(typedLimit >> 8)
        buffer.push(payload)

        let count = offsets.count
        let fullLength = (((count - 1) * 2) + 7) >> 3
        var mask = [UInt8](repeating: 0, count: max(fullLength, 1))
        for index in 0..<(count - 1) {
            let size = Int(offsets[index + 1]) - Int(offsets[index])
            let code = correction(size)
            let bit = index * 2
            mask[bit >> 3] |= code << (bit & 7)
        }

        let bits = (Int(maxID) - 1) * 2
        let metaSize = (bits + 7) >> 3
        var maskOut = [UInt8](repeating: 0, count: metaSize)
        if metaSize > 0 {
            let tailBits = bits - ((metaSize - 1) * 8)
            let tailMask: UInt8 = tailBits >= 8 ? 0xff : UInt8((1 << tailBits) - 1)
            for index in 0..<metaSize {
                let byte = index + 1 < metaSize ? mask[index] : mask[index] & tailMask
                maskOut[metaSize - 1 - index] = byte
            }
        }
        buffer.push(maskOut)
        return end
    }

    private static func serializeString(_ buffer: inout ReversedBuffer, _ data: [UInt8]) -> Int {
        buffer.push([0])
        buffer.push(data)
        buffer.push(le32(UInt32(data.count)))
        return buffer.size
    }

    private static func serializeOffsetArray(_ buffer: inout ReversedBuffer, elements: [Int]) -> Int {
        guard !elements.isEmpty else { return 0 }
        let start = buffer.size
        let objectStart = start + elements.count * 4
        for element in elements.reversed() {
            buffer.push(le32(UInt32(objectStart - element)))
        }
        buffer.push(le32(UInt32(elements.count)))
        return buffer.size
    }

    private static func correction(_ size: Int) -> UInt8 {
        (size > 0 ? 1 : 0) + (size > 1 ? 1 : 0) + (size > 4 ? 1 : 0)
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xff), UInt8((value >> 8) & 0xff), UInt8((value >> 16) & 0xff), UInt8(value >> 24)]
    }

    private static func putU32(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
        bytes[offset + 2] = UInt8((value >> 16) & 0xff)
        bytes[offset + 3] = UInt8(value >> 24)
    }

    fileprivate static func readU32(_ data: ArraySlice<UInt8>, _ offset: Int) -> UInt32? {
        guard offset >= 0, offset <= data.count - 4 else { return nil }
        let base = data.startIndex + offset
        return UInt32(data[base])
            | UInt32(data[base + 1]) << 8
            | UInt32(data[base + 2]) << 16
            | UInt32(data[base + 3]) << 24
    }
}

// MARK: - Helpers

private struct ReversedBuffer {
    private(set) var storage: [UInt8] = []

    var size: Int { storage.count }

    mutating func push(_ bytes: [UInt8]) {
        storage.append(contentsOf: bytes.reversed())
    }

    func finish(rootEnd: Int) -> [UInt8] {
        var copy = self
        copy.push(YAFF.le32Public(UInt32(copy.size + 4 - rootEnd)))
        return copy.storage.reversed()
    }
}

private struct FlatReader {
    let message: ArraySlice<UInt8>
    let maxID: UInt16

    init?(_ message: ArraySlice<UInt8>) {
        guard let typedLimit = YAFF.readU16(message, 0) else { return nil }
        guard typedLimit & 0x8000 != 0 else { return nil }
        self.message = message
        self.maxID = (typedLimit >> 2) & 0x1fff
    }

    func scalar(id: UInt16, offset: UInt16, defaultValue: Int32) -> Int32? {
        guard id < maxID else { return defaultValue }
        guard let raw = YAFF.readU32(message, 2 + Int(offset)) else { return nil }
        return Int32(bitPattern: raw ^ UInt32(bitPattern: defaultValue))
    }

    func nested(id: UInt16, offset: UInt16) -> ArraySlice<UInt8>? {
        guard id < maxID else { return nil }
        guard let pointer = YAFF.readU32(message, 2 + Int(offset)), pointer != 0 else { return nil }
        guard pointer <= UInt32(message.count) else { return nil }
        return message.dropFirst(Int(pointer))
    }
}

extension YAFF {
    fileprivate static func readU16(_ data: ArraySlice<UInt8>, _ offset: Int) -> UInt16? {
        guard offset >= 0, offset <= data.count - 2 else { return nil }
        let base = data.startIndex + offset
        return UInt16(data[base]) | UInt16(data[base + 1]) << 8
    }

    fileprivate static func le32Public(_ value: UInt32) -> [UInt8] {
        le32(value)
    }
}
