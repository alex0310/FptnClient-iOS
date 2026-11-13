import XCTest

@testable import FptnCore

final class LoginRacePreferenceTests: XCTestCase {
    private func server(_ index: Int) -> FPTNServer {
        FPTNServer(
            name: "s\(index)",
            host: "10.0.0.\(index)",
            port: UInt16(8000 + index),
            md5Fingerprint: nil,
            countryCode: nil,
            isCensoredZone: false
        )
    }

    func testPreferredServerWinsBeforeRace() {
        let servers = (1...4).map(server)
        let preferred = server(2)
        let lock = NSLock()
        var called: [String] = []

        let result = LoginRace.find(
            servers: servers,
            preferredServerID: preferred.id,
            timeout: 1,
            maxAttempts: 1,
            retryDelay: 0,
            extraWait: 0
        ) { server in
            lock.lock()
            called.append(server.id)
            lock.unlock()
            return "token-\(server.name)"
        }

        XCTAssertEqual(result?.server, preferred)
        XCTAssertEqual(called, [preferred.id])
    }

    func testPreferredFailureFallsBackToOtherServers() {
        let preferred = server(2)
        let others = [server(1), server(3)]
        let lock = NSLock()
        var called: Set<String> = []

        let result = LoginRace.find(
            servers: [server(1), preferred, server(3)],
            preferredServerID: preferred.id,
            timeout: 1,
            maxAttempts: 1,
            retryDelay: 0,
            extraWait: 0
        ) { server in
            lock.lock()
            called.insert(server.id)
            lock.unlock()
            if server == preferred {
                throw TransportError.timeout
            }
            return "token-\(server.name)"
        }

        XCTAssertNotNil(result)
        XCTAssertTrue(result.map { others.contains($0.server) } ?? false)
        XCTAssertTrue(called.contains(preferred.id))
    }

    func testSingleServerPreferredKeepsRetryBudget() {
        let only = server(1)
        let lock = NSLock()
        var calls = 0

        let result = LoginRace.find(
            servers: [only],
            preferredServerID: only.id,
            timeout: 1,
            maxAttempts: 2,
            retryDelay: 0,
            extraWait: 0,
            preferredAttempts: 1
        ) { _ in
            lock.lock()
            calls += 1
            let current = calls
            lock.unlock()
            if current == 1 {
                throw TransportError.timeout
            }
            return "ok"
        }

        XCTAssertEqual(result?.token, "ok")
        XCTAssertEqual(calls, 2)
    }

    func testUnknownPreferredServerFallsBackToNormalRace() {
        let servers = (1...4).map(server)

        let result = LoginRace.find(
            servers: servers,
            preferredServerID: "missing:1",
            timeout: 1,
            maxAttempts: 1,
            retryDelay: 0,
            extraWait: 0
        ) { server in
            "token-\(server.name)"
        }

        XCTAssertNotNil(result)
        XCTAssertTrue(result.map { servers.contains($0.server) } ?? false)
    }
}
