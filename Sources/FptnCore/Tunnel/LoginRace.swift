import Foundation
import Dispatch

public struct LoginRaceResult: Equatable, Sendable {
    public let server: FPTNServer
    public let token: String

    public init(server: FPTNServer, token: String) {
        self.server = server
        self.token = token
    }
}

/// Upstream `FindServerByLogin`: pick a random half of the token's servers,
/// race a login against each, and keep the first token that comes back.
public enum LoginRace {
    public static let attempts = 3
    public static let retryDelay: TimeInterval = 0.5
    public static let extraWait: TimeInterval = 2

    /// At least one server, at most half of the list (rounded down), shuffled.
    public static func candidates(
        from servers: [FPTNServer],
        using generator: inout some RandomNumberGenerator
    ) -> [FPTNServer] {
        guard !servers.isEmpty else { return [] }
        let count = max(1, servers.count / 2)
        return Array(servers.shuffled(using: &generator).prefix(count))
    }

    /// Tries the pinned server first, then falls back to the normal random
    /// race over the remaining servers. A token with one server keeps the
    /// regular retry budget even when that server is pinned.
    public static func find(
        servers: [FPTNServer],
        preferredServerID: String? = nil,
        timeout: TimeInterval = 10,
        queue: DispatchQueue = .global(),
        maxAttempts: Int = LoginRace.attempts,
        retryDelay: TimeInterval = LoginRace.retryDelay,
        extraWait: TimeInterval = LoginRace.extraWait,
        preferredAttempts: Int = 1,
        login: @escaping (FPTNServer) throws -> String
    ) -> LoginRaceResult? {
        guard !servers.isEmpty else { return nil }
        var remaining = servers

        if let preferredServerID,
           let index = remaining.firstIndex(where: { $0.id == preferredServerID }) {
            let preferred = remaining.remove(at: index)
            if let result = race(
                servers: [preferred],
                timeout: timeout,
                queue: queue,
                maxAttempts: max(1, preferredAttempts),
                retryDelay: retryDelay,
                extraWait: extraWait,
                login: login
            ) {
                return result
            }
            if remaining.isEmpty {
                return race(
                    servers: [preferred],
                    timeout: timeout,
                    queue: queue,
                    maxAttempts: max(1, maxAttempts),
                    retryDelay: retryDelay,
                    extraWait: extraWait,
                    login: login
                )
            }
        }

        guard !remaining.isEmpty else { return nil }
        return race(
            servers: remaining,
            timeout: timeout,
            queue: queue,
            maxAttempts: max(1, maxAttempts),
            retryDelay: retryDelay,
            extraWait: extraWait,
            login: login
        )
    }

    private static func race(
        servers: [FPTNServer],
        timeout: TimeInterval,
        queue: DispatchQueue,
        maxAttempts: Int,
        retryDelay: TimeInterval,
        extraWait: TimeInterval,
        login: @escaping (FPTNServer) throws -> String
    ) -> LoginRaceResult? {
        guard !servers.isEmpty else { return nil }
        var generator = SystemRandomNumberGenerator()
        let picked = candidates(from: servers, using: &generator)
        let state = RaceState()
        let done = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        // `DispatchQueue.async` requires a @Sendable closure. The login
        // operation is deliberately invoked concurrently: each call opens its
        // own HTTP/TLS connection and owns all captured state, so it is safe
        // to share while keeping the public API free of a @Sendable requirement.
        let operation = LoginOperation(run: login)

        for server in picked {
            group.enter()
            queue.async {
                defer { group.leave() }
                for attempt in 0..<maxAttempts {
                    state.lock.lock()
                    let stop = state.cancelled
                    state.lock.unlock()
                    if stop { return }
                    do {
                        let token = try operation.run(server)
                        state.lock.lock()
                        if state.result == nil {
                            state.result = LoginRaceResult(server: server, token: token)
                            state.cancelled = true
                            state.lock.unlock()
                            done.signal()
                        } else {
                            state.lock.unlock()
                        }
                        return
                    } catch {
                        if attempt + 1 < maxAttempts {
                            Thread.sleep(forTimeInterval: retryDelay)
                        }
                    }
                }
            }
        }

        group.notify(queue: queue) {
            done.signal()
        }
        let total = timeout * Double(maxAttempts) + retryDelay * Double(maxAttempts) + extraWait
        _ = done.wait(timeout: .now() + total)
        state.lock.lock()
        let final = state.result
        state.lock.unlock()
        return final
    }
}

private final class RaceState: @unchecked Sendable {
    let lock = NSLock()
    var result: LoginRaceResult?
    var cancelled = false
}

/// See the concurrency note in `race`: the login closure is shared across
/// the racing tasks on purpose, without forcing callers to mark it @Sendable.
private struct LoginOperation: @unchecked Sendable {
    let run: (FPTNServer) throws -> String
}
