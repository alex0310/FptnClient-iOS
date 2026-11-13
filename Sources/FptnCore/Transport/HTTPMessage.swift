import Foundation

public struct HTTPHeader: Equatable, Sendable {
    public let name: String
    public let value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

public struct HTTPRequest: Equatable, Sendable {
    public var method: String
    public var target: String
    public var headers: [HTTPHeader]
    public var body: [UInt8]

    public init(
        method: String,
        target: String,
        headers: [HTTPHeader],
        body: [UInt8] = []
    ) {
        self.method = method
        self.target = target
        self.headers = headers
        self.body = body
    }

    public func encoded() -> [UInt8] {
        var head = "\(method) \(target) HTTP/1.1\r\n"
        var hasContentLength = false
        for header in headers {
            if header.name.caseInsensitiveCompare("Content-Length") == .orderedSame {
                hasContentLength = true
            }
            head += "\(header.name): \(header.value)\r\n"
        }
        if !body.isEmpty && !hasContentLength {
            head += "Content-Length: \(body.count)\r\n"
        }
        head += "\r\n"
        return Array(head.utf8) + body
    }

    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

public struct HTTPResponse: Equatable, Sendable {
    public let statusCode: Int
    public let reason: String
    public let headers: [HTTPHeader]
    public let body: [UInt8]

    public init(
        statusCode: Int,
        reason: String,
        headers: [HTTPHeader],
        body: [UInt8]
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.headers = headers
        self.body = body
    }

    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    public var text: String? {
        String(bytes: body, encoding: .utf8)
    }
}

public enum HTTPError: Error, Equatable, LocalizedError {
    case malformedStatusLine
    case malformedHeader
    case headersTooLarge(Int)
    case malformedChunk
    case unexpectedEndOfStream
    case responseTooLarge(Int)

    public var errorDescription: String? {
        switch self {
        case .malformedStatusLine: return "Malformed HTTP status line."
        case .malformedHeader: return "Malformed HTTP header."
        case let .headersTooLarge(size): return "HTTP headers exceed \(size) bytes."
        case .malformedChunk: return "Malformed HTTP chunked body."
        case .unexpectedEndOfStream: return "Unexpected end of HTTP stream."
        case let .responseTooLarge(size): return "HTTP response exceeds \(size) bytes."
        }
    }
}

/// Incremental HTTP/1.1 response parser. Supports `Content-Length`, chunked
/// transfer encoding, bodyless statuses, and connection-close delimited bodies.
public final class HTTPResponseParser {
    public let maxHeaderSize: Int
    private var buffer: [UInt8] = []
    private var cursor = 0
    private var endOfStream = false

    public init(maxHeaderSize: Int = 64 * 1024) {
        self.maxHeaderSize = maxHeaderSize
    }

    public func append(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    public func markEndOfStream() {
        endOfStream = true
    }

    public var isEndOfStream: Bool { endOfStream }

    public var bufferedByteCount: Int { buffer.count - cursor }

    /// Removes and returns bytes that follow the last parsed response. Used by
    /// the WebSocket upgrade path, where the server may send frames in the same
    /// TCP segment as the `101` response.
    public func takeBufferedBytes() -> [UInt8] {
        let bytes = Array(buffer[cursor...])
        buffer.removeAll(keepingCapacity: true)
        cursor = 0
        return bytes
    }

    public func nextResponse() throws -> HTTPResponse? {
        guard let headEnd = findHeaderEnd() else {
            if bufferedByteCount > maxHeaderSize {
                throw HTTPError.headersTooLarge(bufferedByteCount)
            }
            return nil
        }
        if headEnd - cursor > maxHeaderSize {
            throw HTTPError.headersTooLarge(headEnd - cursor)
        }
        let head = Array(buffer[cursor..<headEnd])
        guard let parsed = try parseHead(head) else { return nil }

        let bodyStart = headEnd + 4
        let available = buffer.count - bodyStart
        let body: [UInt8]
        let consumed: Int

        if parsed.statusCode == 101
            || (100...199).contains(parsed.statusCode)
            || parsed.statusCode == 204
            || parsed.statusCode == 304 {
            body = []
            consumed = 0
        } else if parsed.isChunked {
            guard let result = try decodeChunked(from: bodyStart) else { return nil }
            body = result.body
            consumed = result.consumed
        } else if let length = parsed.contentLength {
            guard available >= length else {
                if endOfStream { throw HTTPError.unexpectedEndOfStream }
                return nil
            }
            body = Array(buffer[bodyStart..<(bodyStart + length)])
            consumed = length
        } else {
            guard endOfStream else { return nil }
            body = Array(buffer[bodyStart...])
            consumed = available
        }

        cursor = bodyStart + consumed
        compactIfNeeded()
        return HTTPResponse(
            statusCode: parsed.statusCode,
            reason: parsed.reason,
            headers: parsed.headers,
            body: body
        )
    }

    // MARK: - Head parsing

    private struct ParsedHead {
        let statusCode: Int
        let reason: String
        let headers: [HTTPHeader]
        let contentLength: Int?
        let isChunked: Bool
    }

    private func parseHead(_ head: [UInt8]) throws -> ParsedHead? {
        guard let text = String(bytes: head, encoding: .utf8) else {
            throw HTTPError.malformedStatusLine
        }
        let lines = text.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { throw HTTPError.malformedStatusLine }
        let parts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2,
              parts[0].hasPrefix("HTTP/"),
              let status = Int(parts[1]) else {
            throw HTTPError.malformedStatusLine
        }
        let reason = parts.count == 3 ? String(parts[2]) : ""

        var headers: [HTTPHeader] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else {
                throw HTTPError.malformedHeader
            }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { throw HTTPError.malformedHeader }
            headers.append(HTTPHeader(name: name, value: value))
        }

        let contentLength = headers.first {
            $0.name.caseInsensitiveCompare("Content-Length") == .orderedSame
        }.flatMap { Int($0.value.trimmingCharacters(in: .whitespaces)) }
        let isChunked = headers.first {
            $0.name.caseInsensitiveCompare("Transfer-Encoding") == .orderedSame
        }.map { $0.value.lowercased().contains("chunked") } ?? false
        return ParsedHead(
            statusCode: status,
            reason: reason,
            headers: headers,
            contentLength: contentLength,
            isChunked: isChunked
        )
    }

    private func findHeaderEnd() -> Int? {
        guard bufferedByteCount >= 4 else { return nil }
        var index = cursor
        while index + 4 <= buffer.count {
            if buffer[index] == 0x0d, buffer[index + 1] == 0x0a,
               buffer[index + 2] == 0x0d, buffer[index + 3] == 0x0a {
                return index
            }
            index += 1
        }
        return nil
    }

    // MARK: - Chunked bodies

    private func decodeChunked(from start: Int) throws -> (body: [UInt8], consumed: Int)? {
        var position = start
        var body: [UInt8] = []
        while true {
            guard let lineEnd = findCRLF(from: position) else { return nil }
            let sizeLine = String(
                bytes: buffer[position..<lineEnd],
                encoding: .utf8
            ) ?? ""
            let sizeText = sizeLine.split(separator: ";", maxSplits: 1).first?
                .trimmingCharacters(in: .whitespaces) ?? ""
            guard let size = Int(sizeText, radix: 16), size >= 0 else {
                throw HTTPError.malformedChunk
            }
            position = lineEnd + 2
            if size == 0 {
                // Skip optional trailers until the terminating blank line.
                while true {
                    guard let trailerEnd = findCRLF(from: position) else { return nil }
                    if trailerEnd == position {
                        return (body, trailerEnd + 2 - start)
                    }
                    position = trailerEnd + 2
                }
            }
            guard buffer.count >= position + size + 2 else { return nil }
            body.append(contentsOf: buffer[position..<(position + size)])
            position += size
            guard buffer[position] == 0x0d, buffer[position + 1] == 0x0a else {
                throw HTTPError.malformedChunk
            }
            position += 2
        }
    }

    private func findCRLF(from start: Int) -> Int? {
        var index = start
        while index + 2 <= buffer.count {
            if buffer[index] == 0x0d, buffer[index + 1] == 0x0a {
                return index
            }
            index += 1
        }
        return nil
    }

    private func compactIfNeeded() {
        guard cursor > 0 else { return }
        if cursor == buffer.count {
            buffer.removeAll(keepingCapacity: true)
            cursor = 0
        } else if cursor >= 4096 {
            buffer.removeFirst(cursor)
            cursor = 0
        }
    }
}

public enum BrowserHeaders {
    /// Browser-like headers used for API and WebSocket upgrade requests.
    /// `Accept-Encoding` is intentionally absent: FPTN responses are not
    /// compressed and advertising gzip would make the server compress them.
    public static func make(
        userAgent: String = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 "
            + "Mobile/15E148 Safari/604.1",
        platform: String = "\"iOS\""
    ) -> [HTTPHeader] {
        [
            HTTPHeader(name: "User-Agent", value: userAgent),
            HTTPHeader(name: "Accept-Language", value: "en-US,en;q=0.9"),
            HTTPHeader(
                name: "Accept",
                value: "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    + "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            HTTPHeader(name: "Referer", value: "https://www.google.com/"),
            HTTPHeader(name: "Sec-Ch-Ua", value: "\"Not:A-Brand\";v=\"24\", \"Chromium\";v=\"134\""),
            HTTPHeader(name: "Sec-Ch-Ua-Mobile", value: "?1"),
            HTTPHeader(name: "Sec-Ch-Ua-Platform", value: platform),
            HTTPHeader(name: "Upgrade-Insecure-Requests", value: "1"),
            HTTPHeader(name: "Sec-Fetch-Site", value: "cross-site"),
            HTTPHeader(name: "Sec-Fetch-Mode", value: "navigate"),
            HTTPHeader(name: "Sec-Fetch-User", value: "?1"),
            HTTPHeader(name: "Sec-Fetch-Dest", value: "document"),
            HTTPHeader(name: "Priority", value: "u=0, i")
        ]
    }
}
