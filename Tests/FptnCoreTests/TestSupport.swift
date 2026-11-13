import XCTest
@testable import FptnCore

/// Decodes a whitespace-tolerant hex fixture, failing the test on bad input.
func hex(_ string: String, file: StaticString = #filePath, line: UInt = #line) -> [UInt8] {
    guard let value = Hex.decode(string) else {
        XCTFail("Invalid hex fixture", file: file, line: line)
        return []
    }
    return value
}

func ascii(_ bytes: [UInt8]) -> String {
    String(decoding: bytes, as: UTF8.self)
}
