import XCTest

@testable import FptnCore

final class ReconnectTests: XCTestCase {
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

    func testCandidatesUseHalfButAtLeastOne() {
        var generator = SeededGenerator(seed: 7)
        XCTAssertEqual(LoginRace.candidates(from: [], using: &generator), [])
        XCTAssertEqual(LoginRace.candidates(from: [server(1)], using: &generator).count, 1)
        let five = (1...5).map(server)
        let picked = LoginRace.candidates(from: five, using: &generator)
        XCTAssertEqual(picked.count, 2)
        XCTAssertTrue(picked.allSatisfy { five.contains($0) })
        XCTAssertEqual(Set(picked).count, picked.count)
    }

    func testFindReturnsFirstSuccessfulLogin() {
        let servers = (1...4).map(server)
        let result = LoginRace.find(
            servers: servers,
            timeout: 1,
            maxAttempts: 1,
            retryDelay: 0,
            extraWait: 0
        ) { server in
            "token-\(server.name)"
        }
        XCTAssertNotNil(result)
        XCTAssertTrue(result.map { servers.contains($0.server) } ?? false)
        XCTAssertTrue(result?.token.hasPrefix("token-") ?? false)
    }

    func testFindRetriesTransientFailure() {
        let servers = [server(1)]
        let lock = NSLock()
        var calls = 0
        let result = LoginRace.find(
            servers: servers,
            timeout: 1,
            maxAttempts: 2,
            retryDelay: 0,
            extraWait: 0
        ) { _ in
            lock.lock()
            calls += 1
            let current = calls
            lock.unlock()
            if current == 1 { throw TransportError.timeout }
            return "ok"
        }
        XCTAssertEqual(result?.token, "ok")
        XCTAssertEqual(calls, 2)
    }

    func testFindReturnsNilWhenEveryLoginFails() {
        let result = LoginRace.find(
            servers: (1...4).map(server),
            timeout: 0.1,
            maxAttempts: 1,
            retryDelay: 0,
            extraWait: 0
        ) { _ in
            throw TransportError.closed
        }
        XCTAssertNil(result)
    }

    func testReconnectPolicyBudgetAndSlidingWindow() {
        var policy = ReconnectPolicy(maxAttempts: 5, window: 120)
        for index in 0..<5 {
            XCTAssertTrue(policy.canAttempt(at: TimeInterval(index)))
            policy.recordAttempt(at: TimeInterval(index))
        }
        XCTAssertFalse(policy.canAttempt(at: 10))
        XCTAssertEqual(policy.usedAttempts, 5)
        XCTAssertTrue(policy.canAttempt(at: 130))
        XCTAssertEqual(policy.usedAttempts, 0)
    }

    func testReconnectPolicyBackoffIsExponentialAndCapped() {
        let policy = ReconnectPolicy(baseDelay: 1, maximumDelay: 30)
        XCTAssertEqual(policy.delay(forAttempt: 0), 1)
        XCTAssertEqual(policy.delay(forAttempt: 1), 2)
        XCTAssertEqual(policy.delay(forAttempt: 2), 4)
        XCTAssertEqual(policy.delay(forAttempt: 4), 16)
        XCTAssertEqual(policy.delay(forAttempt: 10), 30)
    }

    func testReconnectPolicyReset() {
        var policy = ReconnectPolicy(maxAttempts: 1)
        policy.recordAttempt(at: 0)
        XCTAssertFalse(policy.canAttempt(at: 1))
        policy.reset()
        XCTAssertTrue(policy.canAttempt(at: 1))
    }
}

private struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) {
        state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
}
