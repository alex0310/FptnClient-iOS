import XCTest

@testable import FptnCore

final class FPTNTunnelTests: XCTestCase {
    private func serverFrame(_ frame: WebSocketFrame) -> [UInt8] {
        let payload = frame.payload
        var output: [UInt8] = [0x80 | frame.opcode.rawValue]
        if payload.count < 126 {
            output.append(UInt8(payload.count))
        } else if payload.count <= 0xffff {
            output.append(126)
            output.append(UInt8((payload.count >> 8) & 0xff))
            output.append(UInt8(payload.count & 0xff))
        } else {
            output.append(127)
            let length = UInt64(payload.count)
            for shift in stride(from: 56, through: 0, by: -8) {
                output.append(UInt8((length >> UInt64(shift)) & 0xff))
            }
        }
        output.append(contentsOf: payload)
        return output
    }

    private func clientFrame(_ data: [UInt8]) -> WebSocketFrame? {
        guard data.count >= 2 else { return nil }
        let first = data[0]
        let second = data[1]
        guard second & 0x80 != 0 else { return nil }
        guard let opcode = WebSocketOpcode(rawValue: first & 0x0f) else { return nil }
        var offset = 2
        let length7 = Int(second & 0x7f)
        let length: Int
        if length7 < 126 {
            length = length7
        } else if length7 == 126 {
            guard data.count >= 4 else { return nil }
            length = Int(data[2]) << 8 | Int(data[3])
            offset = 4
        } else {
            guard data.count >= 10 else { return nil }
            var value: UInt64 = 0
            for index in 0..<8 {
                value = value << 8 | UInt64(data[offset + index])
            }
            length = Int(value)
            offset = 10
        }
        guard data.count >= offset + 4 + length else { return nil }
        let mask = Array(data[offset..<(offset + 4)])
        offset += 4
        let payload = (0..<length).map { data[offset + $0] ^ mask[$0 & 3] }
        switch opcode {
        case .binary: return .binary(payload)
        case .ping: return .ping(payload)
        case .pong: return .pong(payload)
        case .close: return .close(code: nil, reason: "")
        case .text: return .text(String(decoding: payload, as: UTF8.self))
        case .continuation: return nil
        }
    }

    private func assignmentFrame(ipv4: String = "10.0.0.2", ipv6: String = "fd00::2") -> [UInt8] {
        serverFrame(.binary(FPTNMessage.encodeAssignment(ipv4: ipv4, ipv6: ipv6)))
    }

    private func ipv4UDPPacket(source: [UInt8], destination: [UInt8]) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 28)
        packet[0] = 0x45
        packet[3] = 28
        packet[8] = 64
        packet[9] = IPPacket.protocolUDP
        packet.replaceSubrange(12..<16, with: source)
        packet.replaceSubrange(16..<20, with: destination)
        packet[20] = 0x04
        packet[21] = 0xd2
        packet[22] = 0
        packet[23] = 53
        packet[24] = 0
        packet[25] = 8
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    private func makeTunnel(
        connection: MemoryHTTPConnection,
        clock: @escaping () -> TimeInterval,
        configuration: FPTNTunnelConfiguration = FPTNTunnelConfiguration()
    ) -> FPTNTunnel {
        FPTNTunnel(
            webSocket: WebSocketConnection(connection: connection),
            configuration: configuration,
            clock: clock
        )
    }

    func testHandshakeReadsAssignmentAndAnswersPing() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = serverFrame(.ping([1, 2])) + assignmentFrame()
        let tunnel = makeTunnel(connection: connection, clock: { 0 })
        try tunnel.performHandshake()
        XCTAssertTrue(tunnel.isReady)
        XCTAssertEqual(tunnel.assignedIPv4, IPAddress("10.0.0.2"))
        XCTAssertEqual(tunnel.assignedIPv6, IPAddress("fd00::2"))
        let frames = connection.drainClientFrames()
        XCTAssertEqual(frames.count, 1)
        if case let .pong(payload)? = frames.first {
            XCTAssertEqual(payload, [1, 2])
        } else {
            XCTFail("expected pong")
        }
    }

    func testHandshakeRejectsServerErrorAndMalformedFrames() {
        let errorConnection = MemoryHTTPConnection()
        errorConnection.incoming = serverFrame(.binary(
            FPTNMessage.encodeError(kind: .sessionExpired, message: "expired")
        ))
        let errorTunnel = makeTunnel(connection: errorConnection, clock: { 0 })
        XCTAssertThrowsError(try errorTunnel.performHandshake()) { error in
            XCTAssertEqual(
                error as? FPTNTunnelError,
                .serverError(kind: .sessionExpired, message: "expired")
            )
        }

        let malformedConnection = MemoryHTTPConnection()
        malformedConnection.incoming = serverFrame(.binary([0xff, 0xff, 0xff, 0xff]))
        let malformedTunnel = makeTunnel(connection: malformedConnection, clock: { 0 })
        XCTAssertThrowsError(try malformedTunnel.performHandshake()) { error in
            XCTAssertEqual(error as? FPTNTunnelError, .malformedMessage)
        }
    }

    func testHandshakeRejectsInvalidAssignment() {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame(ipv4: "not-an-ip")
        let tunnel = makeTunnel(connection: connection, clock: { 0 })
        XCTAssertThrowsError(try tunnel.performHandshake()) { error in
            XCTAssertEqual(error as? FPTNTunnelError, .invalidAssignment)
        }
    }

    func testIncomingPacketsAreRewrittenToTunAddress() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame()
        let tunnel = makeTunnel(
            connection: connection,
            clock: { 0 },
            configuration: FPTNTunnelConfiguration(tunIPv4: IPAddress("10.0.0.2"))
        )
        try tunnel.performHandshake()
        let packet = ipv4UDPPacket(source: [8, 8, 8, 8], destination: [1, 1, 1, 1])
        connection.incoming += serverFrame(.binary(FPTNMessage.encodeBatch([packet])!))
        let received = try tunnel.receivePackets()
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(Array(received[0][16...19]), [10, 0, 0, 2])
    }

    func testOutgoingPacketsAreBatchedAndRewritten() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame()
        let tunnel = makeTunnel(
            connection: connection,
            clock: { 0 },
            configuration: FPTNTunnelConfiguration(maxBatchSize: 2)
        )
        try tunnel.performHandshake()
        let packets = [
            ipv4UDPPacket(source: [10, 0, 0, 1], destination: [8, 8, 8, 8]),
            ipv4UDPPacket(source: [10, 0, 0, 1], destination: [8, 8, 4, 4]),
            ipv4UDPPacket(source: [10, 0, 0, 1], destination: [1, 1, 1, 1])
        ]
        XCTAssertEqual(try tunnel.send(packets: packets), 3)
        let frames = connection.drainClientFrames()
        XCTAssertEqual(frames.count, 2)
        let first = try XCTUnwrap(frames[0])
        guard case let .binary(firstPayload) = first else {
            return XCTFail("expected binary")
        }
        guard case let .batch(firstBatch)? = FPTNMessage.decode(firstPayload) else {
            return XCTFail("expected batch")
        }
        XCTAssertEqual(firstBatch.count, 2)
        XCTAssertEqual(Array(firstBatch[0][12...15]), [10, 0, 0, 2])
        let second = try XCTUnwrap(frames[1])
        guard case let .binary(secondPayload) = second else {
            return XCTFail("expected binary")
        }
        guard case let .batch(secondBatch)? = FPTNMessage.decode(secondPayload) else {
            return XCTFail("expected batch")
        }
        XCTAssertEqual(secondBatch.count, 1)
    }

    func testKeepaliveSendsPingAndPongClearsWatchdog() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame()
        var now: TimeInterval = 0
        let tunnel = makeTunnel(
            connection: connection,
            clock: { now },
            configuration: FPTNTunnelConfiguration(keepaliveIdle: 15, deadAfter: 90)
        )
        try tunnel.performHandshake()
        now = 15
        XCTAssertEqual(try tunnel.tick(), .active)
        let frames = connection.drainClientFrames()
        XCTAssertEqual(frames.count, 1)
        guard case let .ping(payload)? = frames.first else {
            return XCTFail("expected ping")
        }
        XCTAssertEqual(payload.count, 8)

        connection.incoming += serverFrame(.pong(payload))
        XCTAssertThrowsError(try tunnel.receivePackets()) { error in
            XCTAssertEqual(error as? TransportError, .timeout)
        }
        XCTAssertEqual(tunnel.keepalive.pongs, 1)

        now = 105
        XCTAssertEqual(try tunnel.tick(), .dead)
    }

    func testLifetimeRotatesBeforeDeadWatchdog() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame()
        var now: TimeInterval = 0
        let tunnel = makeTunnel(
            connection: connection,
            clock: { now },
            configuration: FPTNTunnelConfiguration(keepaliveIdle: 15, connectionLifetime: 540)
        )
        try tunnel.performHandshake()
        now = 540
        XCTAssertEqual(try tunnel.tick(), .rotate)
    }

    func testCloseFrameEndsTunnel() throws {
        let connection = MemoryHTTPConnection()
        connection.incoming = assignmentFrame()
        let tunnel = makeTunnel(connection: connection, clock: { 0 })
        try tunnel.performHandshake()
        connection.incoming += serverFrame(.close(code: 1000, reason: ""))
        XCTAssertThrowsError(try tunnel.receivePackets()) { error in
            XCTAssertEqual(error as? FPTNTunnelError, .closed)
        }
        XCTAssertTrue(tunnel.isClosed)
    }

    func testTickBeforeHandshakeIsDead() {
        let connection = MemoryHTTPConnection()
        let tunnel = makeTunnel(connection: connection, clock: { 0 })
        XCTAssertEqual(try? tunnel.tick(), .dead)
    }
}

private final class MemoryHTTPConnection: HTTPConnection {
    var incoming: [UInt8] = []
    var outgoing: [UInt8] = []
    var isClosed = false
    private(set) var readTimeouts: [TimeInterval] = []

    func write(_ bytes: [UInt8]) throws {
        outgoing.append(contentsOf: bytes)
    }

    func read(maxBytes: Int) throws -> [UInt8] {
        guard !incoming.isEmpty else { throw TransportError.timeout }
        let count = min(maxBytes, incoming.count)
        let result = Array(incoming.prefix(count))
        incoming.removeFirst(count)
        return result
    }

    func close() {
        isClosed = true
    }

    func setReadTimeout(_ seconds: TimeInterval) throws {
        readTimeouts.append(seconds)
    }

    func drainClientFrames() -> [WebSocketFrame?] {
        var frames: [WebSocketFrame?] = []
        var cursor = 0
        while cursor < outgoing.count {
            let remaining = Array(outgoing[cursor...])
            guard let frame = parseFrame(remaining) else { break }
            frames.append(frame)
            cursor += frameLength(remaining)
        }
        outgoing.removeAll(keepingCapacity: true)
        return frames
    }

    private func parseFrame(_ data: [UInt8]) -> WebSocketFrame? {
        guard data.count >= 2 else { return nil }
        let first = data[0]
        let second = data[1]
        guard second & 0x80 != 0, let opcode = WebSocketOpcode(rawValue: first & 0x0f) else {
            return nil
        }
        var offset = 2
        let length7 = Int(second & 0x7f)
        let length: Int
        if length7 < 126 {
            length = length7
        } else if length7 == 126 {
            guard data.count >= 4 else { return nil }
            length = Int(data[2]) << 8 | Int(data[3])
            offset = 4
        } else {
            guard data.count >= 10 else { return nil }
            var value: UInt64 = 0
            for index in 0..<8 {
                value = value << 8 | UInt64(data[offset + index])
            }
            length = Int(value)
            offset = 10
        }
        guard data.count >= offset + 4 + length else { return nil }
        let mask = Array(data[offset..<(offset + 4)])
        offset += 4
        let payload = (0..<length).map { data[offset + $0] ^ mask[$0 & 3] }
        switch opcode {
        case .binary: return .binary(payload)
        case .ping: return .ping(payload)
        case .pong: return .pong(payload)
        case .close: return .close(code: nil, reason: "")
        case .text: return .text(String(decoding: payload, as: UTF8.self))
        case .continuation: return nil
        }
    }

    private func frameLength(_ data: [UInt8]) -> Int {
        guard data.count >= 2 else { return data.count }
        let second = data[1]
        var offset = 2
        let length7 = Int(second & 0x7f)
        let length: Int
        if length7 < 126 {
            length = length7
        } else if length7 == 126 {
            length = Int(data[2]) << 8 | Int(data[3])
            offset = 4
        } else {
            var value: UInt64 = 0
            for index in 0..<8 {
                value = value << 8 | UInt64(data[offset + index])
            }
            length = Int(value)
            offset = 10
        }
        return offset + 4 + length
    }
}
