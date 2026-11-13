import Foundation

public enum TransportError: Error, Equatable, LocalizedError {
    case resolveFailed(String)
    case connectFailed(String)
    case timeout
    case closed
    case ioError(Int32)
    case invalidArgument(String)
    case notConnected

    public var errorDescription: String? {
        switch self {
        case let .resolveFailed(host): return "Could not resolve host \(host)."
        case let .connectFailed(reason): return "Could not connect: \(reason)."
        case .timeout: return "Network operation timed out."
        case .closed: return "The connection was closed by the peer."
        case let .ioError(code): return "Socket I/O failed with errno \(code)."
        case let .invalidArgument(reason): return "Invalid network argument: \(reason)."
        case .notConnected: return "The transport is not connected."
        }
    }
}

/// A blocking, byte-oriented transport. Implementations are intentionally
/// small so the TLS and protocol layers stay independent from the OS network
/// stack and can be exercised with in-memory fakes.
public protocol ByteTransport: AnyObject {
    func read(maxBytes: Int) throws -> [UInt8]
    func write(_ bytes: [UInt8]) throws
    func close()
    func setReadTimeout(_ seconds: TimeInterval) throws
    func setWriteTimeout(_ seconds: TimeInterval) throws
}

public extension ByteTransport {
    func readAll() throws -> [UInt8] {
        var output: [UInt8] = []
        while true {
            do {
                let chunk = try read(maxBytes: 16_384)
                if chunk.isEmpty { return output }
                output.append(contentsOf: chunk)
            } catch TransportError.closed {
                return output
            }
        }
    }
}

/// Minimal connection surface used by HTTP and WebSocket code. `TLSConnection`
/// and test doubles both conform to it.
public protocol HTTPConnection: AnyObject {
    func write(_ bytes: [UInt8]) throws
    func read(maxBytes: Int) throws -> [UInt8]
    func close()
    func setReadTimeout(_ seconds: TimeInterval) throws
    func setWriteTimeout(_ seconds: TimeInterval) throws
}

public extension HTTPConnection {
    /// In-memory test connections do not have a socket timeout; production
    /// connections override this.
    func setReadTimeout(_ seconds: TimeInterval) throws {}
    func setWriteTimeout(_ seconds: TimeInterval) throws {}
}
