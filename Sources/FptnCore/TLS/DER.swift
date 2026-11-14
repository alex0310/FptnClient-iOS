import Foundation

/// Errors raised while decoding strict DER (definite length only, minimal
/// length encoding, no trailing bytes).
public enum DERError: Error, Equatable, LocalizedError {
    case truncated
    case invalidLength
    case indefiniteLength
    case nonMinimalLength
    case unexpectedTag(expected: UInt8, actual: UInt8)
    case trailingData
    case invalidOID
    case invalidTime(String)
    case invalidBitString
    case invalidBoolean
    case unsupportedString(UInt8)

    public var errorDescription: String? {
        switch self {
        case .truncated: return "DER element is truncated."
        case .invalidLength: return "DER element has an invalid length."
        case .indefiniteLength: return "Indefinite DER lengths are not supported."
        case .nonMinimalLength: return "DER length is not minimally encoded."
        case let .unexpectedTag(expected, actual):
            return String(format: "DER tag mismatch: expected 0x%02x, got 0x%02x.", expected, actual)
        case .trailingData: return "Unexpected trailing DER data."
        case .invalidOID: return "DER object identifier is malformed."
        case let .invalidTime(value): return "DER time value is invalid: \(value)."
        case .invalidBitString: return "DER BIT STRING is malformed."
        case .invalidBoolean: return "DER BOOLEAN is malformed."
        case let .unsupportedString(tag):
            return String(format: "DER string tag 0x%02x is unsupported.", tag)
        }
    }
}

/// One decoded TLV. `encoded` is the complete element (used as the raw issuer/
/// subject name and as the `tbsCertificate` bytes that a signature covers).
public struct DERElement: Equatable, Sendable {
    public let tag: UInt8
    public let content: [UInt8]
    public let encoded: [UInt8]

    public init(tag: UInt8, content: [UInt8], encoded: [UInt8]) {
        self.tag = tag
        self.content = content
        self.encoded = encoded
    }

    public func requireTag(_ expected: UInt8) throws -> DERElement {
        guard tag == expected else {
            throw DERError.unexpectedTag(expected: expected, actual: tag)
        }
        return self
    }

    public var children: [DERElement] {
        get throws { try DER.parseAll(content) }
    }

    public var objectIdentifier: String {
        get throws {
            _ = try requireTag(0x06)
            guard let firstByte = content.first else { throw DERError.invalidOID }
            let raw = UInt64(firstByte)
            let firstArc = min(raw / 40, 2)
            var components: [UInt64] = [firstArc, raw - firstArc * 40]
            var value: UInt64 = 0
            var pending = false
            for byte in content.dropFirst() {
                guard value < (1 << 56) else { throw DERError.invalidOID }
                value = (value << 7) | UInt64(byte & 0x7f)
                if byte & 0x80 == 0 {
                    components.append(value)
                    value = 0
                    pending = false
                } else {
                    pending = true
                }
            }
            guard !pending else { throw DERError.invalidOID }
            return components.map(String.init).joined(separator: ".")
        }
    }

    /// ASCII-compatible string tags used by X.509 names and times.
    public var text: String {
        get throws {
            switch tag {
            // 0x82 is the context-specific IA5String used by X.509 dNSName.
            case 0x0c, 0x13, 0x16, 0x17, 0x18, 0x14, 0x82:
                guard let value = String(bytes: content, encoding: .utf8) else {
                    throw DERError.unsupportedString(tag)
                }
                return value
            default:
                throw DERError.unsupportedString(tag)
            }
        }
    }

    public var bitStringBytes: [UInt8] {
        get throws {
            _ = try requireTag(0x03)
            // DER allows 0...7 unused trailing bits. KeyUsage often uses 5.
            guard let unusedBits = content.first, unusedBits <= 7 else {
                throw DERError.invalidBitString
            }
            return Array(content.dropFirst())
        }
    }

    public var booleanValue: Bool {
        get throws {
            _ = try requireTag(0x01)
            guard content.count == 1 else { throw DERError.invalidBoolean }
            switch content[0] {
            case 0x00: return false
            case 0xff: return true
            default: throw DERError.invalidBoolean
            }
        }
    }

    /// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ), UTC only.
    public var dateValue: Date {
        get throws {
            let raw = try text
            guard raw.hasSuffix("Z") else { throw DERError.invalidTime(raw) }
            let digits = String(raw.dropLast())
            guard digits.allSatisfy(\.isNumber) else { throw DERError.invalidTime(raw) }
            let year: Int
            let remainder: String
            switch tag {
            case 0x17:
                guard digits.count == 12 else { throw DERError.invalidTime(raw) }
                let shortYear = Int(digits.prefix(2)) ?? -1
                year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear
                remainder = String(digits.dropFirst(2))
            case 0x18:
                guard digits.count == 14 else { throw DERError.invalidTime(raw) }
                year = Int(digits.prefix(4)) ?? -1
                remainder = String(digits.dropFirst(4))
            default:
                throw DERError.invalidTime(raw)
            }
            guard remainder.count == 10, year > 0 else { throw DERError.invalidTime(raw) }
            let month = Int(remainder.prefix(2)) ?? 0
            let day = Int(remainder.dropFirst(2).prefix(2)) ?? 0
            let hour = Int(remainder.dropFirst(4).prefix(2)) ?? 0
            let minute = Int(remainder.dropFirst(6).prefix(2)) ?? 0
            let second = Int(remainder.dropFirst(8).prefix(2)) ?? 0
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = TimeZone(secondsFromGMT: 0)!
            let components = DateComponents(
                calendar: calendar,
                year: year, month: month, day: day,
                hour: hour, minute: minute, second: second
            )
            guard let date = components.date,
                  calendar.component(.month, from: date) == month,
                  calendar.component(.day, from: date) == day else {
                throw DERError.invalidTime(raw)
            }
            return date
        }
    }
}

public enum DER {
    /// Decodes exactly one element and rejects trailing data.
    public static func parse(_ bytes: [UInt8]) throws -> DERElement {
        var offset = 0
        let element = try parseOne(bytes, &offset)
        guard offset == bytes.count else { throw DERError.trailingData }
        return element
    }

    public static func parseAll(_ bytes: [UInt8]) throws -> [DERElement] {
        var offset = 0
        var elements: [DERElement] = []
        while offset < bytes.count {
            elements.append(try parseOne(bytes, &offset))
        }
        return elements
    }

    private static func parseOne(_ bytes: [UInt8], _ offset: inout Int) throws -> DERElement {
        let start = offset
        guard offset < bytes.count else { throw DERError.truncated }
        let tag = bytes[offset]
        offset += 1
        guard offset < bytes.count else { throw DERError.truncated }
        let first = bytes[offset]
        offset += 1

        var length = 0
        if first & 0x80 == 0 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7f)
            guard count > 0 else { throw DERError.indefiniteLength }
            guard count <= 4, offset + count <= bytes.count else {
                throw DERError.invalidLength
            }
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[offset])
                offset += 1
            }
            guard length >= 0x80 else { throw DERError.nonMinimalLength }
        }
        guard offset + length <= bytes.count else { throw DERError.truncated }
        let content = Array(bytes[offset..<(offset + length)])
        let encoded = Array(bytes[start..<(offset + length)])
        offset += length
        return DERElement(tag: tag, content: content, encoded: encoded)
    }
}
