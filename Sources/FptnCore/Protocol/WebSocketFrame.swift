import Foundation

public enum WebSocketOpcode: UInt8, Sendable {
    case continuation = 0x0
    case text = 0x1
    case binary = 0x2
    case close = 0x8
    case ping = 0x9
    case pong = 0xa
}

public enum WebSocketFrame: Equatable, Sendable {
    case text(String)
    case binary([UInt8])
    case ping([UInt8])
    case pong([UInt8])
    case close(code: UInt16?, reason: String)

    public var opcode: WebSocketOpcode {
        switch self {
        case .text: return .text
        case .binary: return .binary
        case .ping: return .ping
        case .pong: return .pong
        case .close: return .close
        }
    }

    public var payload: [UInt8] {
        switch self {
        case let .text(value): return Array(value.utf8)
        case let .binary(value): return value
        case let .ping(value): return value
        case let .pong(value): return value
        case let .close(code, reason):
            var output: [UInt8] = []
            if let code {
                output.append(UInt8((code >> 8) & 0xff))
                output.append(UInt8(code & 0xff))
                output.append(contentsOf: reason.utf8)
            }
            return output
        }
    }
}

public enum WebSocketError: Error, Equatable, LocalizedError {
    case invalidFrame
    case reservedBitsSet
    case maskedServerFrame
    case controlFrameTooLong
    case fragmentedControlFrame
    case unexpectedContinuation
    case frameTooLarge
    case invalidUTF8
    case invalidCloseFrame

    public var errorDescription: String? {
        switch self {
        case .invalidFrame: return "Malformed WebSocket frame."
        case .reservedBitsSet: return "WebSocket RSV bits are not supported."
        case .maskedServerFrame: return "Server WebSocket frames must not be masked."
        case .controlFrameTooLong: return "WebSocket control frame exceeds 125 bytes."
        case .fragmentedControlFrame: return "WebSocket control frames must not be fragmented."
        case .unexpectedContinuation: return "Unexpected WebSocket continuation frame."
        case .frameTooLarge: return "WebSocket frame exceeds the configured limit."
        case .invalidUTF8: return "WebSocket text frame is not valid UTF-8."
        case .invalidCloseFrame: return "Malformed WebSocket close frame."
        }
    }
}

public enum WebSocketFrameEncoder {
    public static func encode(_ frame: WebSocketFrame, maskKey: [UInt8]? = nil) -> [UInt8] {
        let payload = frame.payload
        let mask = maskKey ?? SecureRandom.bytes(4)
        precondition(mask.count == 4)

        var output: [UInt8] = []
        output.reserveCapacity(14 + payload.count)
        output.append(0x80 | frame.opcode.rawValue)

        let maskBit: UInt8 = 0x80
        if payload.count < 126 {
            output.append(maskBit | UInt8(payload.count))
        } else if payload.count <= 0xffff {
            output.append(maskBit | 126)
            output.append(UInt8((payload.count >> 8) & 0xff))
            output.append(UInt8(payload.count & 0xff))
        } else {
            output.append(maskBit | 127)
            let length = UInt64(payload.count)
            for shift in stride(from: 56, through: 0, by: -8) {
                output.append(UInt8((length >> UInt64(shift)) & 0xff))
            }
        }

        output.append(contentsOf: mask)
        output.reserveCapacity(output.count + payload.count)
        for (index, byte) in payload.enumerated() {
            output.append(byte ^ mask[index & 3])
        }
        return output
    }
}

public final class WebSocketFrameDecoder {
    public let maxFrameSize: Int
    private var buffer: [UInt8] = []
    private var cursor = 0
    private var fragmentOpcode: WebSocketOpcode?
    private var fragments: [UInt8] = []

    public init(maxFrameSize: Int = 16 * 1024 * 1024) {
        self.maxFrameSize = maxFrameSize
    }

    public func append(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    public func nextFrame() throws -> WebSocketFrame? {
        while true {
            guard let frame = try parseOne() else {
                compactIfNeeded()
                return nil
            }
            if let frame { return frame }
        }
    }

    /// Returns `nil` when more bytes are needed, `.some(nil)` when a
    /// non-final fragment was consumed, and `.some(frame)` for a complete frame.
    private func parseOne() throws -> WebSocketFrame?? {
        let available = buffer.count - cursor
        guard available >= 2 else { return nil }

        let first = buffer[cursor]
        let second = buffer[cursor + 1]
        let fin = first & 0x80 != 0
        guard first & 0x70 == 0 else { throw WebSocketError.reservedBitsSet }
        guard let opcode = WebSocketOpcode(rawValue: first & 0x0f) else {
            throw WebSocketError.invalidFrame
        }
        let masked = second & 0x80 != 0
        guard !masked else { throw WebSocketError.maskedServerFrame }

        var offset = cursor + 2
        let length7 = Int(second & 0x7f)
        let payloadLength: Int
        if length7 < 126 {
            payloadLength = length7
        } else if length7 == 126 {
            guard available >= 4 else { return nil }
            payloadLength = Int(buffer[offset]) << 8 | Int(buffer[offset + 1])
            offset += 2
        } else {
            guard available >= 10 else { return nil }
            var value: UInt64 = 0
            for index in 0..<8 {
                value = value << 8 | UInt64(buffer[offset + index])
            }
            guard value <= UInt64(Int.max) else { throw WebSocketError.frameTooLarge }
            payloadLength = Int(value)
            offset += 8
        }

        guard payloadLength <= maxFrameSize else { throw WebSocketError.frameTooLarge }
        let isControl = opcode.rawValue >= 0x8
        if isControl {
            guard fin else { throw WebSocketError.fragmentedControlFrame }
            guard payloadLength <= 125 else { throw WebSocketError.controlFrameTooLong }
        }

        let frameEnd = offset + payloadLength
        guard frameEnd <= buffer.count else { return nil }
        let payload = Array(buffer[offset..<frameEnd])
        cursor = frameEnd

        switch opcode {
        case .continuation:
            guard fragmentOpcode != nil else { throw WebSocketError.unexpectedContinuation }
            fragments.append(contentsOf: payload)
            guard fragments.count <= maxFrameSize else { throw WebSocketError.frameTooLarge }
            guard fin else { return .some(nil) }
            let complete = fragments
            let type = fragmentOpcode
            fragments.removeAll(keepingCapacity: true)
            fragmentOpcode = nil
            switch type {
            case .text:
                guard let string = String(bytes: complete, encoding: .utf8) else {
                    throw WebSocketError.invalidUTF8
                }
                return .some(.text(string))
            case .binary:
                return .some(.binary(complete))
            default:
                throw WebSocketError.invalidFrame
            }

        case .text, .binary:
            guard fragmentOpcode == nil else { throw WebSocketError.invalidFrame }
            guard fin else {
                fragmentOpcode = opcode
                fragments = payload
                return .some(nil)
            }
            if opcode == .text {
                guard let string = String(bytes: payload, encoding: .utf8) else {
                    throw WebSocketError.invalidUTF8
                }
                return .some(.text(string))
            }
            return .some(.binary(payload))

        case .ping:
            return .some(.ping(payload))

        case .pong:
            return .some(.pong(payload))

        case .close:
            if payload.isEmpty {
                return .some(.close(code: nil, reason: ""))
            }
            guard payload.count >= 2 else { throw WebSocketError.invalidCloseFrame }
            let code = UInt16(payload[0]) << 8 | UInt16(payload[1])
            guard let reason = String(bytes: payload.dropFirst(2), encoding: .utf8) else {
                throw WebSocketError.invalidUTF8
            }
            return .some(.close(code: code, reason: reason))
        }
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
