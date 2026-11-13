import XCTest

@testable import FptnCore

final class IPPacketTests: XCTestCase {
    private func ipv4HeaderChecksumValid(_ packet: [UInt8]) -> Bool {
        let headerLength = Int(packet[0] & 0x0f) * 4
        var sum = UInt32(0)
        var index = 0
        while index + 1 < headerLength {
            sum += UInt32(packet[index]) << 8 | UInt32(packet[index + 1])
            index += 2
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return sum == 0xffff
    }

    private func checksumValid(_ packet: [UInt8], start: Int, length: Int, seed: UInt32) -> Bool {
        var sum = UInt64(seed)
        var index = start
        while index + 1 < start + length {
            sum += UInt64(packet[index]) << 8 | UInt64(packet[index + 1])
            index += 2
        }
        if index < start + length {
            sum += UInt64(packet[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return sum == 0xffff
    }

    private func ipv4UDPPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 28)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 28
        packet[8] = 64
        packet[9] = IPPacket.protocolUDP
        packet[12...15] = [10, 0, 0, 1]
        packet[16...19] = [8, 8, 8, 8]
        packet[20] = 0x04
        packet[21] = 0xd2
        packet[22] = 0
        packet[23] = 53
        packet[24] = 0
        packet[25] = 8
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    private func ipv4TCPPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 40)
        packet[0] = 0x45
        packet[3] = 40
        packet[8] = 64
        packet[9] = IPPacket.protocolTCP
        packet[12...15] = [10, 0, 0, 1]
        packet[16...19] = [93, 184, 216, 34]
        packet[20] = 0x04
        packet[21] = 0xd2
        packet[22] = 0
        packet[23] = 80
        packet[32] = 0x50
        packet[33] = 0x02
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    private func ipv4ICMPPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 28)
        packet[0] = 0x45
        packet[3] = 28
        packet[8] = 64
        packet[9] = IPPacket.protocolICMP
        packet[12...15] = [10, 0, 0, 1]
        packet[16...19] = [1, 1, 1, 1]
        packet[20] = 8
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    private func ipv6UDPPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 48)
        packet[0] = 0x60
        packet[4] = 0
        packet[5] = 8
        packet[6] = IPPacket.protocolUDP
        packet[7] = 64
        packet[8...23] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        packet[24...39] = [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]
        packet[40] = 0x04
        packet[41] = 0xd2
        packet[42] = 0
        packet[43] = 53
        packet[44] = 0
        packet[45] = 8
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    private func ipv6ICMPPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 44)
        packet[0] = 0x60
        packet[4] = 0
        packet[5] = 4
        packet[6] = IPPacket.protocolICMPv6
        packet[7] = 64
        packet[8...23] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        packet[24...39] = [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]
        packet[40] = 128
        IPPacket.recalculateChecksums(&packet)
        return packet
    }

    func testIPv4HeaderAndUDPChecksumsAreValid() {
        let packet = ipv4UDPPacket()
        XCTAssertTrue(ipv4HeaderChecksumValid(packet))
        XCTAssertNotEqual(packet[26], 0)
        XCTAssertNotEqual(packet[27], 0)
        var seed = UInt32(0)
        for offset in [12, 14, 16, 18] {
            seed += UInt32(packet[offset]) << 8 | UInt32(packet[offset + 1])
        }
        seed += UInt32(IPPacket.protocolUDP)
        seed += 8
        XCTAssertTrue(checksumValid(packet, start: 20, length: 8, seed: seed))
    }

    func testIPv4TCPChecksumIsValid() {
        let packet = ipv4TCPPacket()
        XCTAssertTrue(ipv4HeaderChecksumValid(packet))
        var seed = UInt32(0)
        for offset in [12, 14, 16, 18] {
            seed += UInt32(packet[offset]) << 8 | UInt32(packet[offset + 1])
        }
        seed += UInt32(IPPacket.protocolTCP)
        seed += 20
        XCTAssertTrue(checksumValid(packet, start: 20, length: 20, seed: seed))
    }

    func testIPv4ICMPChecksumIsValid() {
        let packet = ipv4ICMPPacket()
        XCTAssertTrue(ipv4HeaderChecksumValid(packet))
        XCTAssertTrue(checksumValid(packet, start: 20, length: 8, seed: 0))
    }

    func testIPv4SourceRewriteUpdatesChecksums() {
        var packet = ipv4UDPPacket()
        IPPacket.setSourceIPv4(&packet, address: 0xac140007)
        XCTAssertEqual(Array(packet[12...15]), [172, 20, 0, 7])
        XCTAssertTrue(ipv4HeaderChecksumValid(packet))
    }

    func testIPv4DestinationRewriteUpdatesChecksums() {
        var packet = ipv4UDPPacket()
        IPPacket.setDestinationIPv4(&packet, address: 0x0a000001)
        XCTAssertEqual(Array(packet[16...19]), [10, 0, 0, 1])
        XCTAssertTrue(ipv4HeaderChecksumValid(packet))
    }

    func testIPv4ZeroTTLIsIgnored() {
        var packet = ipv4UDPPacket()
        packet[8] = 0
        let original = packet
        IPPacket.setSourceIPv4(&packet, address: 0x01020304)
        XCTAssertEqual(packet, original)
    }

    func testIPv6UDPChecksumIsValidAfterRewrite() {
        var packet = ipv6UDPPacket()
        IPPacket.setSourceIPv6(&packet, address: IPAddress("fd00::9")!.bytes)
        XCTAssertEqual(Array(packet[8...23]), IPAddress("fd00::9")!.bytes)
        XCTAssertTrue(checksumValid(packet, start: 40, length: 8, seed: pseudoV6(packet, 17, 8)))
    }

    func testIPv6ICMPChecksumIsValid() {
        let packet = ipv6ICMPPacket()
        XCTAssertTrue(checksumValid(packet, start: 40, length: 4, seed: pseudoV6(packet, 58, 4)))
    }

    func testOutgoingAndIncomingRewrite() {
        var packet = ipv4UDPPacket()
        IPPacket.rewriteOutgoing(
            &packet,
            assignedIPv4: IPAddress("172.20.0.7"),
            assignedIPv6: nil
        )
        XCTAssertEqual(Array(packet[12...15]), [172, 20, 0, 7])

        IPPacket.rewriteIncoming(
            &packet,
            tunIPv4: IPAddress("10.0.0.2"),
            tunIPv6: nil
        )
        XCTAssertEqual(Array(packet[16...19]), [10, 0, 0, 2])
    }

    func testNonIPPacketsAreLeftAlone() {
        var packet = [UInt8](repeating: 0xff, count: 24)
        let original = packet
        IPPacket.setSourceIPv4(&packet, address: 1)
        IPPacket.setSourceIPv6(&packet, address: [UInt8](repeating: 1, count: 16))
        XCTAssertEqual(packet, original)
    }

    func testSourcePortExtraction() {
        XCTAssertEqual(IPPacket.sourcePort(of: ipv4UDPPacket()), 1234)
        XCTAssertEqual(IPPacket.sourcePort(of: ipv4TCPPacket()), 1234)
        XCTAssertEqual(IPPacket.sourcePort(of: ipv6UDPPacket()), 1234)
        XCTAssertNil(IPPacket.sourcePort(of: []))
        XCTAssertNil(IPPacket.sourcePort(of: [0x45]))
        XCTAssertNil(IPPacket.sourcePort(of: ipv4ICMPPacket()))
    }

    private func pseudoV6(_ packet: [UInt8], _ next: UInt8, _ length: Int) -> UInt32 {
        var sum = UInt32(0)
        for range in [8..<24, 24..<40] {
            var index = range.lowerBound
            while index + 1 < range.upperBound {
                sum += UInt32(packet[index]) << 8 | UInt32(packet[index + 1])
                index += 2
            }
        }
        sum += UInt32(length)
        sum += UInt32(next)
        return sum
    }
}
