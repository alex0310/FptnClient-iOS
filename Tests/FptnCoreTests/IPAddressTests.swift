import XCTest

@testable import FptnCore

final class IPAddressTests: XCTestCase {
    func testParsesAndFormatsIPv4() {
        let address = IPAddress("192.168.1.10")
        XCTAssertEqual(address, .ipv4(0xc0a8010a))
        XCTAssertEqual(address?.text, "192.168.1.10")
        XCTAssertEqual(address?.bytes, [192, 168, 1, 10])
    }

    func testRejectsMalformedIPv4() {
        XCTAssertNil(IPAddress("256.1.1.1"))
        XCTAssertNil(IPAddress("1.2.3"))
        XCTAssertNil(IPAddress("1.2.3.4.5"))
        XCTAssertNil(IPAddress("1.2.3."))
    }

    func testParsesFullAndCompressedIPv6() {
        XCTAssertEqual(
            IPAddress("2001:0db8:0000:0000:0000:0000:0000:0001")?.text,
            "2001:db8::1"
        )
        XCTAssertEqual(IPAddress("::1")?.text, "::1")
        XCTAssertEqual(IPAddress("::")?.text, "::")
        XCTAssertEqual(IPAddress("fd00::2")?.text, "fd00::2")
        XCTAssertEqual(IPAddress("2001:db8::")?.text, "2001:db8::")
    }

    func testParsesIPv4MappedIPv6() {
        XCTAssertEqual(
            IPAddress("::ffff:192.168.0.1")?.bytes,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0, 1]
        )
    }

    func testRejectsMalformedIPv6() {
        XCTAssertNil(IPAddress("1::2::3"))
        XCTAssertNil(IPAddress("gggg::1"))
        XCTAssertNil(IPAddress("1:2:3:4:5:6:7"))
        XCTAssertNil(IPAddress("1:2:3:4:5:6:7:8:9"))
    }

    func testIPv4PrefixMatching() {
        let prefix = IPPrefix("10.0.0.0/8")
        XCTAssertTrue(prefix!.contains(IPAddress("10.255.1.2")!))
        XCTAssertFalse(prefix!.contains(IPAddress("11.0.0.1")!))
        XCTAssertTrue(IPPrefix("0.0.0.0/0")!.contains(IPAddress("8.8.8.8")!))
    }

    func testIPv6PrefixMatching() {
        let prefix = IPPrefix("fd00::/8")
        XCTAssertTrue(prefix!.contains(IPAddress("fd12:3456::1")!))
        XCTAssertFalse(prefix!.contains(IPAddress("fe80::1")!))
        XCTAssertTrue(IPPrefix("::/0")!.contains(IPAddress("2001:db8::1")!))
    }

    func testPrefixRejectsMismatchedFamiliesAndBadLengths() {
        XCTAssertFalse(IPPrefix("10.0.0.0/8")!.contains(IPAddress("fd00::1")!))
        XCTAssertNil(IPPrefix("10.0.0.0/33"))
        XCTAssertNil(IPPrefix("::/129"))
        XCTAssertNil(IPPrefix("not-an-address/8"))
    }

    func testBareAddressBecomesHostPrefix() {
        XCTAssertEqual(IPPrefix("10.0.0.1")?.prefixLength, 32)
        XCTAssertEqual(IPPrefix("fd00::1")?.prefixLength, 128)
    }
}
