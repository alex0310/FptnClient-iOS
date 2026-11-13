import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Blocking POSIX TCP transport with connect/read/write timeouts. This is used
/// on both iOS and Linux so the same TLS and protocol code runs everywhere.
public final class POSIXSocket: ByteTransport {
    private var descriptor: Int32
    private let lock = NSLock()

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        close()
    }

    public static func connect(
        host: String,
        port: UInt16,
        timeout: TimeInterval = 10
    ) throws -> POSIXSocket {
        guard !host.isEmpty, port > 0 else {
            throw TransportError.invalidArgument("empty host or zero port")
        }
        #if os(Linux)
        let streamType = Int32(SOCK_STREAM.rawValue)
        #else
        let streamType = SOCK_STREAM
        #endif
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = streamType
        hints.ai_protocol = Int32(IPPROTO_TCP)
        hints.ai_flags = AI_ADDRCONFIG

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let first = result else {
            throw TransportError.resolveFailed(host)
        }
        defer { freeaddrinfo(result) }

        var lastError: Int32 = 0
        var pointer: UnsafeMutablePointer<addrinfo>? = first
        while let info = pointer {
            let fd = socket(
                info.pointee.ai_family,
                info.pointee.ai_socktype,
                info.pointee.ai_protocol
            )
            if fd < 0 {
                lastError = errno
                pointer = info.pointee.ai_next
                continue
            }
            do {
                try configure(fd)
                try connectWithTimeout(
                    descriptor: fd,
                    address: info.pointee.ai_addr,
                    length: info.pointee.ai_addrlen,
                    timeout: timeout
                )
                let socket = POSIXSocket(descriptor: fd)
                try socket.setReadTimeout(timeout)
                try socket.setWriteTimeout(timeout)
                return socket
            } catch {
                lastError = errno
                _ = systemClose(fd)
            }
            pointer = info.pointee.ai_next
        }
        if lastError != 0 {
            throw TransportError.ioError(lastError)
        }
        throw TransportError.connectFailed("no usable address for \(host)")
    }

    // MARK: - ByteTransport

    public func read(maxBytes: Int) throws -> [UInt8] {
        guard maxBytes > 0 else { return [] }
        lock.lock()
        let fd = descriptor
        lock.unlock()
        guard fd >= 0 else { throw TransportError.closed }

        var buffer = [UInt8](repeating: 0, count: maxBytes)
        while true {
            let count = buffer.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress, maxBytes, 0)
            }
            if count > 0 {
                return Array(buffer.prefix(count))
            }
            if count == 0 {
                throw TransportError.closed
            }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                throw TransportError.timeout
            }
            if errno == ECONNRESET || errno == ENOTCONN {
                throw TransportError.closed
            }
            throw TransportError.ioError(errno)
        }
    }

    public func write(_ bytes: [UInt8]) throws {
        guard !bytes.isEmpty else { return }
        lock.lock()
        let fd = descriptor
        lock.unlock()
        guard fd >= 0 else { throw TransportError.closed }

        #if os(Linux)
        let flags = Int32(MSG_NOSIGNAL)
        #else
        let flags: Int32 = 0
        #endif
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { raw -> Int in
                let base = raw.baseAddress!.advanced(by: offset)
                return send(fd, base, bytes.count - offset, flags)
            }
            if count > 0 {
                offset += count
                continue
            }
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw TransportError.timeout
                }
                if errno == EPIPE || errno == ECONNRESET {
                    throw TransportError.closed
                }
                throw TransportError.ioError(errno)
            }
            throw TransportError.ioError(EIO)
        }
    }

    public func close() {
        lock.lock()
        let fd = descriptor
        descriptor = -1
        lock.unlock()
        if fd >= 0 {
            _ = systemClose(fd)
        }
    }

    public func setReadTimeout(_ seconds: TimeInterval) throws {
        try setSocketTimeout(option: SO_RCVTIMEO, seconds: seconds)
    }

    public func setWriteTimeout(_ seconds: TimeInterval) throws {
        try setSocketTimeout(option: SO_SNDTIMEO, seconds: seconds)
    }

    // MARK: - Configuration

    private static func configure(_ fd: Int32) throws {
        var enabled: Int32 = 1
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &enabled,
            socklen_t(MemoryLayout<Int32>.size)
        )
        _ = setsockopt(
            fd,
            Int32(IPPROTO_TCP),
            TCP_NODELAY,
            &enabled,
            socklen_t(MemoryLayout<Int32>.size)
        )
        #if canImport(Darwin)
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &enabled,
            socklen_t(MemoryLayout<Int32>.size)
        )
        #endif
    }

    private static func connectWithTimeout(
        descriptor: Int32,
        address: UnsafeMutablePointer<sockaddr>?,
        length: socklen_t,
        timeout: TimeInterval
    ) throws {
        guard let address else {
            throw TransportError.invalidArgument("missing socket address")
        }
        let originalFlags = fcntl(descriptor, F_GETFL, 0)
        guard originalFlags >= 0 else { throw TransportError.ioError(errno) }
        guard fcntl(descriptor, F_SETFL, originalFlags | O_NONBLOCK) == 0 else {
            throw TransportError.ioError(errno)
        }
        defer { _ = fcntl(descriptor, F_SETFL, originalFlags) }

        #if canImport(Darwin)
        let result = Darwin.connect(descriptor, address, length)
        #else
        let result = Glibc.connect(descriptor, address, length)
        #endif
        if result == 0 { return }
        if errno != EINPROGRESS {
            throw TransportError.ioError(errno)
        }

        var pollDescriptor = pollfd(
            fd: descriptor,
            events: Int16(POLLOUT),
            revents: 0
        )
        let milliseconds = Int32(max(1, min(timeout, 3_600) * 1_000))
        let pollResult = poll(&pollDescriptor, 1, milliseconds)
        if pollResult == 0 { throw TransportError.timeout }
        if pollResult < 0 {
            if errno == EINTR { return try connectWithTimeout(
                descriptor: descriptor,
                address: address,
                length: length,
                timeout: timeout
            ) }
            throw TransportError.ioError(errno)
        }

        var socketError: Int32 = 0
        var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_ERROR,
            &socketError,
            &socketErrorLength
        ) == 0 else {
            throw TransportError.ioError(errno)
        }
        if socketError != 0 {
            throw TransportError.connectFailed(
                String(cString: strerror(socketError))
            )
        }
    }

    private func setSocketTimeout(option: Int32, seconds: TimeInterval) throws {
        lock.lock()
        let fd = descriptor
        lock.unlock()
        guard fd >= 0 else { throw TransportError.notConnected }
        let clamped = max(0, min(seconds, 86_400))
        var timeout = timeval()
        timeout.tv_sec = Int(clamped)
        #if canImport(Darwin)
        timeout.tv_usec = Int32((clamped - floor(clamped)) * 1_000_000)
        #else
        timeout.tv_usec = Int((clamped - floor(clamped)) * 1_000_000)
        #endif
        guard setsockopt(
            fd,
            SOL_SOCKET,
            option,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        ) == 0 else {
            throw TransportError.ioError(errno)
        }
    }
}

#if canImport(Darwin)
private func systemClose(_ fd: Int32) -> Int32 {
    Darwin.close(fd)
}
#else
private func systemClose(_ fd: Int32) -> Int32 {
    Glibc.close(fd)
}
#endif
