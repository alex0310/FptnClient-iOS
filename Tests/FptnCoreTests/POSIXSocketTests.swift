import Foundation
import XCTest

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@testable import FptnCore

final class POSIXSocketTests: XCTestCase {
    private final class EchoServer {
        private(set) var descriptor: Int32 = -1
        private(set) var port: UInt16 = 0
        private var thread: Thread?

        init(echo: Bool) throws {
            #if os(Linux)
            let streamType = Int32(SOCK_STREAM.rawValue)
            #else
            let streamType = SOCK_STREAM
            #endif
            descriptor = socket(AF_INET, streamType, 0)
            guard descriptor >= 0 else { throw TransportError.ioError(errno) }

            var reuse: Int32 = 1
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuse,
                socklen_t(MemoryLayout<Int32>.size)
            )
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = 0
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let bindResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bindResult == 0 else {
                _ = testClose(descriptor)
                throw TransportError.ioError(errno)
            }
            guard listen(descriptor, 1) == 0 else {
                _ = testClose(descriptor)
                throw TransportError.ioError(errno)
            }
            var bound = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let nameResult = withUnsafeMutablePointer(to: &bound) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(descriptor, $0, &length)
                }
            }
            guard nameResult == 0 else {
                _ = testClose(descriptor)
                throw TransportError.ioError(errno)
            }
            port = UInt16(bigEndian: bound.sin_port)
            let thread = Thread { [weak self] in
                self?.run(echo: echo)
            }
            self.thread = thread
            thread.start()
        }

        deinit {
            _ = testClose(descriptor)
        }

        func stopListening() {
            _ = testClose(descriptor)
        }

        private func run(echo: Bool) {
            let client = accept(descriptor, nil, nil)
            guard client >= 0 else { return }
            defer { _ = testClose(client) }
            var buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = recv(client, &buffer, buffer.count, 0)
                if count <= 0 { return }
                if echo {
                    var offset = 0
                    while offset < count {
                        let sent = buffer.withUnsafeBytes { raw -> Int in
                            send(
                                client,
                                raw.baseAddress!.advanced(by: offset),
                                count - offset,
                                0
                            )
                        }
                        if sent <= 0 { return }
                        offset += sent
                    }
                }
            }
        }
    }

    func testConnectWriteReadAndClose() throws {
        let server = try EchoServer(echo: true)
        let socket = try POSIXSocket.connect(
            host: "127.0.0.1",
            port: server.port,
            timeout: 2
        )
        defer { socket.close() }
        try socket.write(Array("hello".utf8))
        XCTAssertEqual(try socket.read(maxBytes: 16), Array("hello".utf8))
        socket.close()
        XCTAssertThrowsError(try socket.read(maxBytes: 16))
    }

    func testReadTimeout() throws {
        let server = try EchoServer(echo: false)
        let socket = try POSIXSocket.connect(
            host: "127.0.0.1",
            port: server.port,
            timeout: 2
        )
        defer { socket.close() }
        try socket.setReadTimeout(0.05)
        XCTAssertThrowsError(try socket.read(maxBytes: 16)) { error in
            XCTAssertEqual(error as? TransportError, .timeout)
        }
    }

    func testConnectionRefused() throws {
        let server = try EchoServer(echo: true)
        let port = server.port
        server.stopListening()
        XCTAssertThrowsError(try POSIXSocket.connect(
            host: "127.0.0.1",
            port: port,
            timeout: 0.2
        ))
    }

    func testResolveFailure() {
        XCTAssertThrowsError(try POSIXSocket.connect(
            host: "this-host-does-not-exist.invalid",
            port: 443,
            timeout: 0.2
        )) { error in
            XCTAssertEqual(error as? TransportError, .resolveFailed(
                "this-host-does-not-exist.invalid"
            ))
        }
    }
}

private func testClose(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
    Darwin.close(fd)
    #else
    Glibc.close(fd)
    #endif
}
