import XCTest
@testable import FptnCore

final class WebSocketFrameTests: XCTestCase {
    /// Builds an unmasked server-to-client frame.
    private func serverFrame(
        fin: Bool = true,
        opcode: UInt8,
        payload: [UInt8],
        rsv: UInt8 = 0
    ) -> [UInt8] {
        var frame: [UInt8] = [(fin ? 0x80 : 0x00) | rsv | opcode]
        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else if payload.count <= 0xffff {
            frame.append(126)
            frame.append(UInt8((payload.count >> 8) & 0xff))
            frame.append(UInt8(payload.count & 0xff))
        } else {
            frame.append(127)
            let length = UInt64(payload.count)
            for shift in stride(from: 56, through: 0, by: -8) {
                frame.append(UInt8((length >> UInt64(shift)) & 0xff))
            }
        }
        frame.append(contentsOf: payload)
        return frame
    }

    private func decode(_ bytes: [UInt8], maxFrameSize: Int = 16 * 1024 * 1024) throws -> WebSocketFrame? {
        let decoder = WebSocketFrameDecoder(maxFrameSize: maxFrameSize)
        decoder.append(bytes)
        return try decoder.nextFrame()
    }

    func testDecodesTextFrame() throws {
        let frame = try decode(serverFrame(opcode: 0x1, payload: Array("hello".utf8)))
        XCTAssertEqual(frame, .text("hello"))
    }

    func testDecodesBinaryFrame() throws {
        let frame = try decode(serverFrame(opcode: 0x2, payload: [0x00, 0xff, 0x10]))
        XCTAssertEqual(frame, .binary([0x00, 0xff, 0x10]))
    }

    func testDecodesPingAndPong() throws {
        XCTAssertEqual(
            try decode(serverFrame(opcode: 0x9, payload: [1, 2, 3])),
            .ping([1, 2, 3])
        )
        XCTAssertEqual(
            try decode(serverFrame(opcode: 0xa, payload: [4, 5])),
            .pong([4, 5])
        )
    }

    func testDecodesCloseWithCodeAndReason() throws {
        let payload: [UInt8] = [0x03, 0xe8] + Array("bye".utf8)
        XCTAssertEqual(
            try decode(serverFrame(opcode: 0x8, payload: payload)),
            .close(code: 1000, reason: "bye")
        )
    }

    func testDecodesEmptyClose() throws {
        XCTAssertEqual(
            try decode(serverFrame(opcode: 0x8, payload: [])),
            .close(code: nil, reason: "")
        )
    }

    func testReassemblesFragmentedText() throws {
        var bytes = serverFrame(fin: false, opcode: 0x1, payload: Array("Hel".utf8))
        bytes += serverFrame(fin: false, opcode: 0x0, payload: Array("lo ".utf8))
        bytes += serverFrame(fin: true, opcode: 0x0, payload: Array("world".utf8))
        XCTAssertEqual(try decode(bytes), .text("Hello world"))
    }

    func testReassemblesFragmentedBinary() throws {
        var bytes = serverFrame(fin: false, opcode: 0x2, payload: [1, 2])
        bytes += serverFrame(fin: true, opcode: 0x0, payload: [3, 4])
        XCTAssertEqual(try decode(bytes), .binary([1, 2, 3, 4]))
    }

    func testControlFrameBetweenFragments() throws {
        var bytes = serverFrame(fin: false, opcode: 0x2, payload: [1])
        bytes += serverFrame(opcode: 0x9, payload: [9])
        bytes += serverFrame(fin: true, opcode: 0x0, payload: [2])

        let decoder = WebSocketFrameDecoder()
        decoder.append(bytes)
        XCTAssertEqual(try decoder.nextFrame(), .ping([9]))
        XCTAssertEqual(try decoder.nextFrame(), .binary([1, 2]))
    }

    func testDecodesExtended16BitLength() throws {
        let payload = [UInt8](repeating: 0x41, count: 200)
        let frame = try decode(serverFrame(opcode: 0x2, payload: payload))
        XCTAssertEqual(frame, .binary(payload))
    }

    func testDecodesExtended64BitLength() throws {
        let payload = [UInt8](repeating: 0x42, count: 70_000)
        let frame = try decode(serverFrame(opcode: 0x2, payload: payload))
        XCTAssertEqual(frame, .binary(payload))
    }

    func testTruncatedFrameReturnsNilUntilComplete() throws {
        let frame = serverFrame(opcode: 0x1, payload: Array("partial".utf8))
        let decoder = WebSocketFrameDecoder()
        decoder.append(Array(frame.prefix(3)))
        XCTAssertNil(try decoder.nextFrame())
        decoder.append(Array(frame.dropFirst(3)))
        XCTAssertEqual(try decoder.nextFrame(), .text("partial"))
    }

    func testByteByByteDelivery() throws {
        let frame = serverFrame(opcode: 0x2, payload: [10, 20, 30, 40])
        let decoder = WebSocketFrameDecoder()
        for byte in frame.dropLast() {
            decoder.append([byte])
            XCTAssertNil(try decoder.nextFrame())
        }
        decoder.append([frame.last!])
        XCTAssertEqual(try decoder.nextFrame(), .binary([10, 20, 30, 40]))
    }

    func testTwoFramesInOneChunk() throws {
        var bytes = serverFrame(opcode: 0x1, payload: Array("one".utf8))
        bytes += serverFrame(opcode: 0x1, payload: Array("two".utf8))
        let decoder = WebSocketFrameDecoder()
        decoder.append(bytes)
        XCTAssertEqual(try decoder.nextFrame(), .text("one"))
        XCTAssertEqual(try decoder.nextFrame(), .text("two"))
        XCTAssertNil(try decoder.nextFrame())
    }

    func testRejectsMaskedServerFrame() {
        // Client-to-server frame, masked with a zero key.
        let bytes: [UInt8] = [0x81, 0x85, 0, 0, 0, 0] + Array("hello".utf8)
        XCTAssertThrowsError(try decode(bytes)) { error in
            XCTAssertEqual(error as? WebSocketError, .maskedServerFrame)
        }
    }

    func testRejectsReservedBits() {
        XCTAssertThrowsError(
            try decode(serverFrame(opcode: 0x1, payload: [1], rsv: 0x40))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .reservedBitsSet)
        }
    }

    func testRejectsFragmentedControlFrame() {
        XCTAssertThrowsError(
            try decode(serverFrame(fin: false, opcode: 0x9, payload: []))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .fragmentedControlFrame)
        }
    }

    func testRejectsOversizedControlFrame() {
        XCTAssertThrowsError(
            try decode(serverFrame(opcode: 0x9, payload: [UInt8](repeating: 0, count: 126)))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .controlFrameTooLong)
        }
    }

    func testRejectsUnexpectedContinuation() {
        XCTAssertThrowsError(
            try decode(serverFrame(opcode: 0x0, payload: [1]))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .unexpectedContinuation)
        }
    }

    func testRejectsNewDataFrameDuringFragmentation() {
        var bytes = serverFrame(fin: false, opcode: 0x2, payload: [1])
        bytes += serverFrame(fin: true, opcode: 0x2, payload: [2])
        XCTAssertThrowsError(try decode(bytes)) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidFrame)
        }
    }

    func testRejectsInvalidUTF8Text() {
        XCTAssertThrowsError(
            try decode(serverFrame(opcode: 0x1, payload: [0xff, 0xfe]))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidUTF8)
        }
    }

    func testRejectsInvalidUTF8InFragment() {
        var bytes = serverFrame(fin: false, opcode: 0x1, payload: [0x41])
        bytes += serverFrame(fin: true, opcode: 0x0, payload: [0xff])
        XCTAssertThrowsError(try decode(bytes)) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidUTF8)
        }
    }

    func testRejectsInvalidClosePayload() {
        XCTAssertThrowsError(
            try decode(serverFrame(opcode: 0x8, payload: [0x03]))
        ) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidCloseFrame)
        }
    }

    func testRejectsInvalidCloseReasonUTF8() {
        let payload: [UInt8] = [0x03, 0xe8, 0xff]
        XCTAssertThrowsError(try decode(serverFrame(opcode: 0x8, payload: payload))) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidUTF8)
        }
    }

    func testRejectsUnknownOpcode() {
        XCTAssertThrowsError(try decode([0x83, 0x00])) { error in
            XCTAssertEqual(error as? WebSocketError, .invalidFrame)
        }
    }

    func testRejectsFrameAboveSizeLimit() {
        let bytes = serverFrame(opcode: 0x2, payload: [UInt8](repeating: 0, count: 11))
        XCTAssertThrowsError(try decode(bytes, maxFrameSize: 10)) { error in
            XCTAssertEqual(error as? WebSocketError, .frameTooLarge)
        }
    }

    func testRejectsFragmentsAboveSizeLimit() {
        var bytes = serverFrame(fin: false, opcode: 0x2, payload: [UInt8](repeating: 0, count: 6))
        bytes += serverFrame(fin: true, opcode: 0x0, payload: [UInt8](repeating: 0, count: 6))
        XCTAssertThrowsError(try decode(bytes, maxFrameSize: 10)) { error in
            XCTAssertEqual(error as? WebSocketError, .frameTooLarge)
        }
    }

    func testEncoderProducesMaskedFrame() {
        let mask: [UInt8] = [0x37, 0xfa, 0x21, 0x3d]
        let encoded = WebSocketFrameEncoder.encode(.text("Hello"), maskKey: mask)
        XCTAssertEqual(
            encoded,
            [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d]
                + Array("Hello".utf8).enumerated().map { $0.element ^ mask[$0.offset & 3] }
        )
    }

    func testEncoderUses16BitLengthFor126Bytes() {
        let payload = [UInt8](repeating: 0x2a, count: 126)
        let encoded = WebSocketFrameEncoder.encode(.binary(payload), maskKey: [1, 2, 3, 4])
        XCTAssertEqual(encoded[0], 0x82)
        XCTAssertEqual(encoded[1], 0x80 | 126)
        XCTAssertEqual(encoded[2], 0x00)
        XCTAssertEqual(encoded[3], 126)
    }

    func testEncoderUses64BitLengthAbove65535() {
        let payload = [UInt8](repeating: 0x2a, count: 65_536)
        let encoded = WebSocketFrameEncoder.encode(.binary(payload), maskKey: [1, 2, 3, 4])
        XCTAssertEqual(encoded[0], 0x82)
        XCTAssertEqual(encoded[1], 0x80 | 127)
        XCTAssertEqual(Array(encoded[2..<10]), [0, 0, 0, 0, 0, 1, 0, 0])
        XCTAssertEqual(encoded.count, 14 + payload.count)
    }

    func testEncoderCloseFramePayload() {
        let encoded = WebSocketFrameEncoder.encode(
            .close(code: 1000, reason: "bye"),
            maskKey: [0, 0, 0, 0]
        )
        XCTAssertEqual(encoded[0], 0x88)
        XCTAssertEqual(Array(encoded[6...]), [0x03, 0xe8] + Array("bye".utf8))
    }

    func testEncoderEmptyCloseFrameHasNoPayload() {
        let encoded = WebSocketFrameEncoder.encode(.close(code: nil, reason: ""), maskKey: [1, 1, 1, 1])
        XCTAssertEqual(encoded, [0x88, 0x80, 1, 1, 1, 1])
    }

    func testClientEncodedFrameIsRejectedByServerDecoder() {
        let encoded = WebSocketFrameEncoder.encode(.binary([1, 2, 3]))
        XCTAssertThrowsError(try decode(encoded)) { error in
            XCTAssertEqual(error as? WebSocketError, .maskedServerFrame)
        }
    }

    func testPayloadAccessors() {
        XCTAssertEqual(WebSocketFrame.text("ab").payload, [0x61, 0x62])
        XCTAssertEqual(WebSocketFrame.binary([1]).payload, [1])
        XCTAssertEqual(WebSocketFrame.ping([2]).payload, [2])
        XCTAssertEqual(WebSocketFrame.pong([3]).payload, [3])
        XCTAssertEqual(WebSocketFrame.close(code: 0x03e8, reason: "x").payload, [0x03, 0xe8, 0x78])
        XCTAssertEqual(WebSocketFrame.close(code: nil, reason: "").payload, [])
        XCTAssertEqual(WebSocketFrame.text("x").opcode, .text)
        XCTAssertEqual(WebSocketFrame.binary([]).opcode, .binary)
        XCTAssertEqual(WebSocketFrame.ping([]).opcode, .ping)
        XCTAssertEqual(WebSocketFrame.pong([]).opcode, .pong)
        XCTAssertEqual(WebSocketFrame.close(code: nil, reason: "").opcode, .close)
    }

    func testErrorDescriptionsAreUserReadable() {
        let errors: [WebSocketError] = [
            .invalidFrame, .reservedBitsSet, .maskedServerFrame, .controlFrameTooLong,
            .fragmentedControlFrame, .unexpectedContinuation, .frameTooLarge,
            .invalidUTF8, .invalidCloseFrame
        ]
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }
}
