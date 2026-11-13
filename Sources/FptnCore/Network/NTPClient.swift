import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public protocol UDPTransport: AnyObject {
    func query(host: String, port: UInt16, request: [UInt8], timeout: TimeInterval) throws -> [UInt8]
}

/// Tries direct anycast addresses first (DNS may point at the VPN resolver
/// before the tunnel exists), then the public NTP pool names.
public final class NTPClient {
    public static let fallbackIPs = [
        "194.190.168.1",
        "162.159.200.1",
        "162.159.200.123",
        "216.239.35.0"
    ]
    public static let servers = ["pool.ntp.org", "ru.pool.ntp.org", "ntp.ix.ru"]

    private let transport: UDPTransport
    private let systemUnix: () -> Double
    private let monotonic: () -> TimeInterval

    public init(
        transport: UDPTransport = POSIXUDPTransport(),
        systemUnix: @escaping () -> Double = { Date().timeIntervalSince1970 },
        monotonic: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.transport = transport
        self.systemUnix = systemUnix
        self.monotonic = monotonic
    }

    public func query(host: String, timeout: TimeInterval = 2) -> SNTPSample? {
        let request = SNTP.makeRequest()
        let t1 = systemUnix()
        do {
            let response = try transport.query(
                host: host,
                port: SNTP.port,
                request: request,
                timeout: timeout
            )
            let t4 = systemUnix()
            return SNTP.parseResponse(
                request: request,
                response: response,
                sentAt: t1,
                receivedAt: t4,
                monotonicTime: monotonic()
            )
        } catch {
            return nil
        }
    }

    public func sync(timeout: TimeInterval = 3) -> SNTPSample? {
        let deadline = monotonic() + timeout
        for host in Self.fallbackIPs + Self.servers {
            let remaining = deadline - monotonic()
            guard remaining > 0 else { break }
            if let sample = query(host: host, timeout: min(remaining, 2)) {
                return sample
            }
        }
        return nil
    }
}

/// Blocking UDP transport used by the NTP client. It works on both iOS and
/// Linux without Network.framework.
public final class POSIXUDPTransport: UDPTransport {
    public init() {}

    public func query(
        host: String,
        port: UInt16,
        request: [UInt8],
        timeout: TimeInterval
    ) throws -> [UInt8] {
        #if os(Linux)
        let datagramType = Int32(SOCK_DGRAM.rawValue)
        #else
        let datagramType = SOCK_DGRAM
        #endif
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = datagramType
        hints.ai_protocol = Int32(IPPROTO_UDP)
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
            if fd >= 0 {
                defer { _ = udpClose(fd) }
                do {
                    try setSocketTimeout(fd: fd, option: SO_RCVTIMEO, seconds: timeout)
                    try setSocketTimeout(fd: fd, option: SO_SNDTIMEO, seconds: timeout)
                    let connectResult = udpConnect(
                        fd,
                        UnsafePointer(info.pointee.ai_addr),
                        info.pointee.ai_addrlen
                    )
                    guard connectResult == 0 else {
                        lastError = errno
                        pointer = info.pointee.ai_next
                        continue
                    }
                    let sent = request.withUnsafeBytes { raw in
                        send(fd, raw.baseAddress, request.count, 0)
                    }
                    guard sent == request.count else {
                        lastError = errno
                        pointer = info.pointee.ai_next
                        continue
                    }
                    var buffer = [UInt8](repeating: 0, count: 512)
                    let bufferSize = buffer.count
                    let received = buffer.withUnsafeMutableBytes { raw in
                        recv(fd, raw.baseAddress, bufferSize, 0)
                    }
                    if received > 0 {
                        return Array(buffer.prefix(received))
                    }
                    lastError = errno
                } catch {
                    lastError = errno
                }
            } else {
                lastError = errno
            }
            pointer = info.pointee.ai_next
        }
        if lastError == EAGAIN || lastError == EWOULDBLOCK {
            throw TransportError.timeout
        }
        throw TransportError.ioError(lastError)
    }

    private func setSocketTimeout(fd: Int32, option: Int32, seconds: TimeInterval) throws {
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
private func udpClose(_ fd: Int32) -> Int32 {
    Darwin.close(fd)
}

private func udpConnect(
    _ fd: Int32,
    _ address: UnsafePointer<sockaddr>,
    _ length: socklen_t
) -> Int32 {
    Darwin.connect(fd, address, length)
}
#else
private func udpClose(_ fd: Int32) -> Int32 {
    Glibc.close(fd)
}

private func udpConnect(
    _ fd: Int32,
    _ address: UnsafePointer<sockaddr>,
    _ length: socklen_t
) -> Int32 {
    Glibc.connect(fd, address, length)
}
#endif
