import XCTest

@testable import FptnCore

final class SplitTunnelTests: XCTestCase {
    private func sniExtension(_ sni: String) -> [UInt8] {
        let host = Array(sni.utf8)
        let listLength = host.count + 3
        var extensionBytes: [UInt8] = []
        extensionBytes += [0x00, 0x00]
        extensionBytes += be16(listLength + 2)
        extensionBytes += be16(listLength)
        extensionBytes.append(0)
        extensionBytes += be16(host.count)
        extensionBytes += host
        return extensionBytes
    }

    private func clientHello(sessionID: [UInt8] = [], extensions: [UInt8]? = nil) -> [UInt8] {
        var body: [UInt8] = [0x03, 0x03]
        body += [UInt8](repeating: 0, count: 32)
        body.append(UInt8(sessionID.count))
        body += sessionID
        body += be16(2)
        body += [0x13, 0x01]
        body += [1, 0]
        let ext = extensions ?? sniExtension("example.com")
        body += be16(ext.count)
        body += ext

        var record: [UInt8] = [0x16, 0x03, 0x01]
        let handshakeLength = body.count + 4
        record += be16(handshakeLength)
        record.append(0x01)
        record += [UInt8((body.count >> 16) & 0xff), UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)]
        record += body
        return record
    }

    private func tcpPacket(
        destination: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        let total = 20 + 20 + payload.count
        var packet = [UInt8](repeating: 0, count: total)
        packet[0] = 0x45
        packet[2] = UInt8((total >> 8) & 0xff)
        packet[3] = UInt8(total & 0xff)
        packet[8] = 64
        packet[9] = IPPacket.protocolTCP
        packet.replaceSubrange(12..<16, with: [10, 0, 0, 2])
        packet.replaceSubrange(16..<20, with: destination)
        packet[20] = UInt8((sourcePort >> 8) & 0xff)
        packet[21] = UInt8(sourcePort & 0xff)
        packet[22] = UInt8((destinationPort >> 8) & 0xff)
        packet[23] = UInt8(destinationPort & 0xff)
        packet[24...27] = [0, 0, 0x03, 0xe8]
        packet[28...31] = [0, 0, 0x07, 0xd0]
        packet[32] = 0x50
        packet[33] = 0x18
        packet.replaceSubrange(40..<total, with: payload)
        return packet
    }

    private func udpPacket(sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
        let total = 20 + 8 + payload.count
        var packet = [UInt8](repeating: 0, count: total)
        packet[0] = 0x45
        packet[2] = UInt8((total >> 8) & 0xff)
        packet[3] = UInt8(total & 0xff)
        packet[8] = 64
        packet[9] = IPPacket.protocolUDP
        packet.replaceSubrange(12..<16, with: [172, 20, 0, 1])
        packet.replaceSubrange(16..<20, with: [10, 0, 0, 2])
        packet[20] = UInt8((sourcePort >> 8) & 0xff)
        packet[21] = UInt8(sourcePort & 0xff)
        packet[22] = UInt8((destinationPort >> 8) & 0xff)
        packet[23] = UInt8(destinationPort & 0xff)
        packet[24] = UInt8(((8 + payload.count) >> 8) & 0xff)
        packet[25] = UInt8((8 + payload.count) & 0xff)
        packet.replaceSubrange(28..<total, with: payload)
        return packet
    }

    private func dnsResponse(domain: String, answers: [[UInt8]]) -> [UInt8] {
        var dns: [UInt8] = [0x12, 0x34, 0x81, 0x80]
        dns += be16(1)
        dns += be16(answers.count)
        dns += be16(0) + be16(0)
        for label in domain.split(separator: ".") {
            dns.append(UInt8(label.utf8.count))
            dns += Array(label.utf8)
        }
        dns.append(0)
        dns += be16(1) + be16(1)
        for answer in answers {
            dns += [0xc0, 0x0c]
            dns += be16(1) + be16(1)
            dns += [0, 0, 0, 60]
            dns += be16(answer.count)
            dns += answer
        }
        return udpPacket(sourcePort: 53, destinationPort: 40000, payload: dns)
    }

    private func be16(_ value: Int) -> [UInt8] {
        [UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
    }

    func testDomainRulesMatchAtLabelBoundaries() throws {
        let split = try SplitTunnel(rules: ["example.com", "domain: vk.com."])
        XCTAssertTrue(split.matches(domain: "example.com"))
        XCTAssertTrue(split.matches(domain: "m.example.com"))
        XCTAssertFalse(split.matches(domain: "notexample.com"))
        XCTAssertTrue(split.matches(domain: "VK.COM"))
        XCTAssertFalse(split.matches(domain: "notvk.com"))
        XCTAssertEqual(split.ruleCount, 2)
    }

    func testCIDRBypass() throws {
        let split = try SplitTunnel(cidrs: ["10.0.0.0/8", "fd00::/8"])
        XCTAssertTrue(split.shouldBypass(address: IPAddress("10.1.2.3")!))
        XCTAssertTrue(split.shouldBypass(address: IPAddress("fd12::1")!))
        XCTAssertFalse(split.shouldBypass(address: IPAddress("8.8.8.8")!))
        let packet = tcpPacket(
            destination: [10, 1, 2, 3],
            sourcePort: 1,
            destinationPort: 443,
            payload: []
        )
        XCTAssertEqual(split.outgoingExclusion(packet: packet)?.reset, nil)
    }

    func testLocalAndSystemCIDRsAreBypassed() throws {
        let split = try SplitTunnel(
            cidrs: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "224.0.0.0/4",
                "255.255.255.255/32",
                "::1/128",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8"
            ]
        )
        let bypassed = [
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1"
        ]
        for value in bypassed {
            let address = try XCTUnwrap(IPAddress(value))
            XCTAssertTrue(split.shouldBypass(address: address), value)
        }
        XCTAssertFalse(split.shouldBypass(address: IPAddress("8.8.8.8")!))
        XCTAssertFalse(split.shouldBypass(address: IPAddress("2001:4860:4860::8888")!))
    }

    func testPrivateNetworkTCPPacketIsDroppedWithoutReset() throws {
        let split = try SplitTunnel(cidrs: ["192.168.0.0/16"])
        let packet = tcpPacket(
            destination: [192, 168, 1, 10],
            sourcePort: 40000,
            destinationPort: 443,
            payload: []
        )
        let exclusion = try XCTUnwrap(split.outgoingExclusion(packet: packet))
        XCTAssertNil(exclusion.reset)
        XCTAssertEqual(exclusion.destination, IPAddress("192.168.1.10"))
    }

    func testInvalidCIDRIsRejected() {
        XCTAssertThrowsError(try SplitTunnel(cidrs: ["not-a-cidr"])) { error in
            XCTAssertEqual(error as? SplitTunnelError, .invalidCIDR("not-a-cidr"))
        }
    }

    func testExcludedSNIProducesTCPReset() throws {
        let split = try SplitTunnel(rules: ["example.com"])
        let packet = tcpPacket(
            destination: [1, 2, 3, 4],
            sourcePort: 40000,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("www.example.com"))
        )
        let exclusion = try XCTUnwrap(split.outgoingExclusion(packet: packet))
        XCTAssertEqual(exclusion.destination, IPAddress("1.2.3.4"))
        let reset = try XCTUnwrap(exclusion.reset)
        XCTAssertEqual(Array(reset[12..<16]), [1, 2, 3, 4])
        XCTAssertEqual(Array(reset[16..<20]), [10, 0, 0, 2])
        XCTAssertEqual(Array(reset[20..<22]), [0x01, 0xbb])
        XCTAssertEqual(Array(reset[22..<24]), [0x9c, 0x40])
        XCTAssertEqual(reset[33], 0x14)
    }

    func testNonMatchingSNIIsIgnored() throws {
        let split = try SplitTunnel(rules: ["example.com"])
        let packet = tcpPacket(
            destination: [1, 2, 3, 4],
            sourcePort: 1,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("other.net"))
        )
        XCTAssertNil(split.outgoingExclusion(packet: packet))
    }

    func testIncludePolicyExcludesEverythingElse() throws {
        let split = try SplitTunnel(rules: ["example.com"], policy: .include)
        let other = tcpPacket(
            destination: [9, 9, 9, 9],
            sourcePort: 1,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("other.net"))
        )
        XCTAssertNotNil(split.outgoingExclusion(packet: other))
        let matching = tcpPacket(
            destination: [8, 8, 8, 8],
            sourcePort: 1,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("www.example.com"))
        )
        XCTAssertNil(split.outgoingExclusion(packet: matching))
    }

    func testSNIIsFoundAfterSessionIDAndAnotherExtension() throws {
        let dummy: [UInt8] = [0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d]
        let packet = tcpPacket(
            destination: [1, 2, 3, 4],
            sourcePort: 1,
            destinationPort: 443,
            payload: clientHello(sessionID: [0xaa], extensions: dummy + sniExtension("api.example.com"))
        )
        let split = try SplitTunnel(rules: ["example.com"])
        XCTAssertNotNil(split.outgoingExclusion(packet: packet))
    }

    func testDNSResponseYieldsExcludedAddresses() throws {
        let split = try SplitTunnel(rules: ["example.com"])
        let packet = dnsResponse(
            domain: "www.example.com",
            answers: [[1, 2, 3, 4], [5, 6, 7, 8]]
        )
        XCTAssertEqual(
            split.incomingDNSExclusion(packet: packet),
            [IPAddress("1.2.3.4")!, IPAddress("5.6.7.8")!]
        )
    }

    func testDNSResponseForOtherDomainIsIgnored() throws {
        let split = try SplitTunnel(rules: ["example.com"])
        let packet = dnsResponse(domain: "other.net", answers: [[1, 2, 3, 4]])
        XCTAssertEqual(split.incomingDNSExclusion(packet: packet), [])
    }

    func testDisabledSplitTunnelNeverTriggers() throws {
        let split = try SplitTunnel(rules: ["example.com"], cidrs: ["10.0.0.0/8"], enabled: false)
        let hello = tcpPacket(
            destination: [10, 0, 0, 1],
            sourcePort: 1,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("www.example.com"))
        )
        XCTAssertNil(split.outgoingExclusion(packet: hello))
        let dns = dnsResponse(domain: "www.example.com", answers: [[1, 2, 3, 4]])
        XCTAssertEqual(split.incomingDNSExclusion(packet: dns), [])
    }

    func testMalformedPacketsAreIgnored() throws {
        let split = try SplitTunnel(rules: ["example.com"])
        XCTAssertNil(split.outgoingExclusion(packet: []))
        XCTAssertNil(split.outgoingExclusion(packet: [0x45, 0x00]))
        XCTAssertNil(SplitTunnel.makeTCPReset([]))
        XCTAssertEqual(split.incomingDNSExclusion(packet: [0x60]), [])
    }

    func testResetChecksumsAreValid() throws {
        let packet = tcpPacket(
            destination: [1, 2, 3, 4],
            sourcePort: 40000,
            destinationPort: 443,
            payload: clientHello(extensions: sniExtension("x.example.com"))
        )
        let reset = try XCTUnwrap(SplitTunnel.makeTCPReset(packet))
        let ihl = Int(reset[0] & 0x0f) * 4
        var sum = 0
        var index = 0
        while index + 1 < ihl {
            sum += Int(reset[index]) << 8 | Int(reset[index + 1])
            index += 2
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        XCTAssertEqual(sum, 0xffff)
    }
}
