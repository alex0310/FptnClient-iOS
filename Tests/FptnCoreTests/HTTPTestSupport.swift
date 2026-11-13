import Foundation

@testable import FptnCore

final class MockHTTPConnection: HTTPConnection {
    private var chunks: [[UInt8]]
    private(set) var written: [UInt8] = []
    private(set) var closed = false

    init(response: [UInt8], chunkSize: Int = 4096) {
        if chunkSize <= 0 {
            chunks = [response]
        } else {
            var chunks: [[UInt8]] = []
            var offset = 0
            while offset < response.count {
                let end = min(offset + chunkSize, response.count)
                chunks.append(Array(response[offset..<end]))
                offset = end
            }
            self.chunks = chunks
        }
    }

    func write(_ bytes: [UInt8]) throws {
        written.append(contentsOf: bytes)
    }

    func read(maxBytes: Int) throws -> [UInt8] {
        guard !chunks.isEmpty else { throw TransportError.closed }
        var chunk = chunks.removeFirst()
        if chunk.count > maxBytes {
            let rest = Array(chunk.dropFirst(maxBytes))
            chunk = Array(chunk.prefix(maxBytes))
            chunks.insert(rest, at: 0)
        }
        return chunk
    }

    func close() {
        closed = true
    }
}

final class FailingHTTPConnection: HTTPConnection {
    let error: Error

    init(error: Error) {
        self.error = error
    }

    func write(_ bytes: [UInt8]) throws {}
    func read(maxBytes: Int) throws -> [UInt8] { throw error }
    func close() {}
}
