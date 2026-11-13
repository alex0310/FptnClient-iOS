import Foundation

public enum Hex {
    public static func decode(_ string: String) -> [UInt8]? {
        let cleaned = string.filter { !$0.isWhitespace }
        guard cleaned.count.isMultiple(of: 2) else { return nil }
        var output = [UInt8]()
        output.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else { return nil }
            output.append(byte)
            index = next
        }
        return output
    }

    public static func encode(_ bytes: [UInt8], uppercase: Bool = false) -> String {
        let digits = Array(uppercase ? "0123456789ABCDEF" : "0123456789abcdef")
        var output = ""
        output.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            output.append(digits[Int(byte >> 4)])
            output.append(digits[Int(byte & 0x0f)])
        }
        return output
    }
}

extension Array where Element == UInt8 {
    public var hexString: String { Hex.encode(self) }

    public init?(hexString: String) {
        guard let bytes = Hex.decode(hexString) else { return nil }
        self = bytes
    }
}
