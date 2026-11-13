import XCTest

@testable import FptnCore

final class SNTPTests: XCTestCase {
    private func ntpTimestamp(unix: Double) -> [UInt8] {
        let seconds = UInt32(unix + Double(SNTP.unixEpochDelta))
        let fractionValue = (unix - floor(unix)) * 4_294_967_296.0
        let fraction = UInt32(max(0, min(fractionValue, 4_294_967_295.0)))
        return [
            UInt8((seconds >> 24) & 0xff),
            UInt8((seconds >> 16) & 0xff),
            UInt8((seconds >> 8) & 0xff),
            UInt8(seconds & 0xff),
            UInt8((fraction >> 24) & 0xff),
            UInt8((fraction >> 16) & 0xff),
            UInt8((fraction >> 8) & 0xff),
            UInt8(fraction & 0xff)
        ]
    }

    private func response(
        request: [UInt8],
        receive: Double,
        transmit: Double,
        mode: UInt8 = 4,
        stratum: UInt8 = 1
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: SNTP.packetLength)
        packet[0] = (0 << 6) | (4 << 3) | (mode & 0x07)
        packet[1] = stratum
        packet.replaceSubrange(24..<32, with: request[40..<48])
        packet.replaceSubrange(32..<40, with: ntpTimestamp(unix: receive))
        packet.replaceSubrange(40..<48, with: ntpTimestamp(unix: transmit))
        return packet
    }

    func testMakeRequestHasClientModeAndTimestamp() {
        let timestamp: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let request = SNTP.makeRequest(transmitTimestamp: timestamp)
        XCTAssertEqual(request.count, 48)
        XCTAssertEqual(request[0], 0x23)
        XCTAssertEqual(Array(request[40..<48]), timestamp)
    }

    func testParseResponseComputesOffsetAndDelay() throws {
        let request = SNTP.makeRequest(transmitTimestamp: [9, 8, 7, 6, 5, 4, 3, 2])
        let packet = response(request: request, receive: 1001.0, transmit: 1001.0)
        let sample = try XCTUnwrap(SNTP.parseResponse(
            request: request,
            response: packet,
            sentAt: 1000.0,
            receivedAt: 1000.1,
            monotonicTime: 50
        ))
        XCTAssertEqual(sample.offset, 0.95, accuracy: 0.0001)
        XCTAssertEqual(sample.delay, 0.1, accuracy: 0.0001)
        XCTAssertEqual(sample.unixTime, 1001.05, accuracy: 0.0001)
        XCTAssertEqual(sample.monotonicTime, 50)
    }

    func testParseRejectsWrongOriginateTimestamp() {
        let request = SNTP.makeRequest(transmitTimestamp: [1, 2, 3, 4, 5, 6, 7, 8])
        var packet = response(request: request, receive: 1001, transmit: 1001)
        packet[24] ^= 0xff
        XCTAssertNil(SNTP.parseResponse(
            request: request,
            response: packet,
            sentAt: 1000,
            receivedAt: 1001,
            monotonicTime: 0
        ))
    }

    func testParseRejectsInvalidModeVersionAndStratum() {
        let request = SNTP.makeRequest(transmitTimestamp: [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertNil(SNTP.parseResponse(
            request: request,
            response: response(request: request, receive: 1, transmit: 1, mode: 3),
            sentAt: 0,
            receivedAt: 1,
            monotonicTime: 0
        ))
        XCTAssertNil(SNTP.parseResponse(
            request: request,
            response: response(request: request, receive: 1, transmit: 1, stratum: 0),
            sentAt: 0,
            receivedAt: 1,
            monotonicTime: 0
        ))
        XCTAssertNil(SNTP.parseResponse(
            request: request,
            response: Array(repeating: 0, count: 47),
            sentAt: 0,
            receivedAt: 1,
            monotonicTime: 0
        ))
    }

    func testTimeProviderUsesMonotonicBase() {
        var monotonic = 100.0
        var system = 500.0
        let provider = TimeProvider(
            monotonic: { monotonic },
            systemUnix: { system }
        )
        XCTAssertEqual(provider.now(), 500)
        XCTAssertFalse(provider.isSynced)
        provider.accept(SNTPSample(
            unixTime: 1000,
            offset: 0,
            delay: 0,
            monotonicTime: 100
        ))
        XCTAssertTrue(provider.isSynced)
        monotonic = 110
        system = 999
        XCTAssertEqual(provider.now(), 1010)
        provider.reset()
        XCTAssertEqual(provider.now(), 999)
    }

    func testNTPClientUsesFirstSuccessfulFallback() throws {
        let transport = FakeUDPTransport { request in
            var packet = [UInt8](repeating: 0, count: 48)
            packet[0] = 0x24
            packet[1] = 1
            packet.replaceSubrange(24..<32, with: request[40..<48])
            packet.replaceSubrange(32..<40, with: self.ntpTimestamp(unix: 2000))
            packet.replaceSubrange(40..<48, with: self.ntpTimestamp(unix: 2000))
            return packet
        }
        let client = NTPClient(
            transport: transport,
            systemUnix: { 1000 },
            monotonic: { 0 }
        )
        let sample = try XCTUnwrap(client.sync(timeout: 1))
        XCTAssertEqual(sample.unixTime, 2000, accuracy: 0.001)
        XCTAssertEqual(transport.hosts.first, NTPClient.fallbackIPs.first)
    }

    func testNTPClientReturnsNilWhenAllServersFail() {
        let transport = FakeUDPTransport { _ in throw TransportError.timeout }
        let client = NTPClient(
            transport: transport,
            systemUnix: { 1000 },
            monotonic: { 0 }
        )
        XCTAssertNil(client.sync(timeout: 1))
    }
}

private final class FakeUDPTransport: UDPTransport {
    private let handler: ([UInt8]) throws -> [UInt8]
    private(set) var hosts: [String] = []

    init(handler: @escaping ([UInt8]) throws -> [UInt8]) {
        self.handler = handler
    }

    func query(
        host: String,
        port: UInt16,
        request: [UInt8],
        timeout: TimeInterval
    ) throws -> [UInt8] {
        hosts.append(host)
        return try handler(request)
    }
}
