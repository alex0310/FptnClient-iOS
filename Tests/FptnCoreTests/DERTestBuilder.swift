import Foundation

@testable import FptnCore

/// Minimal DER encoder used only to build deterministic revocation/SCT
/// fixtures for tests. It produces canonical definite-length TLVs.
enum DERTestBuilder {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    static func sequence(_ parts: [[UInt8]]) -> [UInt8] {
        tlv(0x30, parts.flatMap { $0 })
    }

    static func set(_ parts: [[UInt8]]) -> [UInt8] {
        tlv(0x31, parts.flatMap { $0 })
    }

    static func integer(_ bytes: [UInt8]) -> [UInt8] { tlv(0x02, bytes) }
    static func enumerated(_ value: UInt8) -> [UInt8] { tlv(0x0a, [value]) }
    static func boolean(_ value: Bool) -> [UInt8] { tlv(0x01, [value ? 0xff : 0x00]) }
    static func null() -> [UInt8] { [0x05, 0x00] }
    static func octetString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x04, bytes) }
    static func bitString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + bytes) }
    static func oid(_ content: [UInt8]) -> [UInt8] { tlv(0x06, content) }
    static func context(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(tag, content) }
    static func contextElements(_ tag: UInt8, _ parts: [[UInt8]]) -> [UInt8] {
        tlv(tag, parts.flatMap { $0 })
    }

    static func utc(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tlv(0x17, Array(formatter.string(from: date).utf8))
    }

    static func generalized(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return tlv(0x18, Array(formatter.string(from: date).utf8))
    }

    // Common OID contents.
    static let sha256WithRSAOID: [UInt8] = [
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
    ]
    static let sha256OID: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    static let basicOCSPResponseOID: [UInt8] = [
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
    ]

    static func algorithmIdentifier(_ oid: [UInt8]) -> [UInt8] {
        sequence([DERTestBuilder.oid(oid), null()])
    }

    private static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
