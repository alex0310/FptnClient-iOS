import Foundation
import XCTest

/// `NetworkExtension` pulls in system modules that also expose `IPAddress`.
/// The iOS targets cannot be type-checked on Linux, so this test guards the
/// module qualification that keeps `Tunnel/` unambiguous on macOS/Xcode.
final class TunnelSourceQualificationTests: XCTestCase {
    func testIPAddressIsAlwaysQualifiedWithFptnCore() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/FptnSharedTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root

        let directories = ["App", "Tunnel"]
        let pattern = #"(?<!FptnCore\.)\bIPAddress\b"#
        let regex = try NSRegularExpression(pattern: pattern)
        var scannedFiles = 0

        for directory in directories {
            let enumerator = FileManager.default.enumerator(
                at: root.appendingPathComponent(directory),
                includingPropertiesForKeys: nil
            )
            let files = try XCTUnwrap(enumerator, "Missing directory: \(directory)")
            while let url = files.nextObject() as? URL {
                guard url.pathExtension == "swift" else { continue }
                scannedFiles += 1
                let source = try String(contentsOf: url, encoding: .utf8)
                let range = NSRange(source.startIndex..., in: source)
                let matches = regex.matches(in: source, range: range)
                XCTAssertTrue(
                    matches.isEmpty,
                    "\(url.lastPathComponent) contains an unqualified IPAddress; use FptnCore.IPAddress"
                )
            }
        }

        XCTAssertGreaterThan(scannedFiles, 10, "Expected the iOS sources to be present")
    }
}
