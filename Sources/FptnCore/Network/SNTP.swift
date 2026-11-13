import Foundation

public struct SNTPSample: Equatable, Sendable {
    /// Corrected Unix time at the moment the response was received.
    public let unixTime: Double
    /// `server - local` clock offset in seconds.
    public let offset: Double
    /// Round-trip delay in seconds.
    public let delay: Double
    /// Local monotonic time when the response was received.
    public let monotonicTime: TimeInterval

    public init(unixTime: Double, offset: Double, delay: Double, monotonicTime: TimeInterval) {
        self.unixTime = unixTime
        self.offset = offset
        self.delay = delay
        self.monotonicTime = monotonicTime
    }
}

/// Minimal SNTPv4 client-side packet handling. Kept pure so the timestamp math
/// can be tested without a network.
public enum SNTP {
    public static let packetLength = 48
    public static let port: UInt16 = 123
    public static let unixEpochDelta: UInt64 = 2_208_988_800

    public static func makeRequest(transmitTimestamp: [UInt8]? = nil) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: packetLength)
        // LI = 0, version = 4, mode = 3 (client).
        packet[0] = 0x23
        let transmit = transmitTimestamp ?? SecureRandom.bytes(8)
        precondition(transmit.count == 8)
        packet.replaceSubrange(40..<48, with: transmit)
        return packet
    }

    public static func parseResponse(
        request: [UInt8],
        response: [UInt8],
        sentAt t1: Double,
        receivedAt t4: Double,
        monotonicTime: TimeInterval
    ) -> SNTPSample? {
        guard request.count >= packetLength, response.count >= packetLength else { return nil }
        let mode = response[0] & 0x07
        guard mode == 4 || mode == 5 else { return nil }
        let version = (response[0] >> 3) & 0x07
        guard version == 3 || version == 4 else { return nil }
        let stratum = response[1]
        guard stratum >= 1, stratum <= 15 else { return nil }
        guard Array(response[24..<32]) == Array(request[40..<48]) else { return nil }
        guard let t2 = timestamp(response, offset: 32),
              let t3 = timestamp(response, offset: 40) else {
            return nil
        }

        let offset = ((t2 - t1) + (t3 - t4)) / 2
        let delay = (t4 - t1) - (t3 - t2)
        guard delay.isFinite, offset.isFinite else { return nil }
        return SNTPSample(
            unixTime: t4 + offset,
            offset: offset,
            delay: delay,
            monotonicTime: monotonicTime
        )
    }

    public static func timestamp(_ packet: [UInt8], offset: Int) -> Double? {
        guard offset >= 0, offset + 8 <= packet.count else { return nil }
        let seconds = UInt32(packet[offset]) << 24
            | UInt32(packet[offset + 1]) << 16
            | UInt32(packet[offset + 2]) << 8
            | UInt32(packet[offset + 3])
        let fraction = UInt32(packet[offset + 4]) << 24
            | UInt32(packet[offset + 5]) << 16
            | UInt32(packet[offset + 6]) << 8
            | UInt32(packet[offset + 7])
        guard seconds != 0 || fraction != 0 else { return nil }
        guard seconds >= UInt32(unixEpochDelta) else { return nil }
        let unix = Double(seconds - UInt32(unixEpochDelta))
        return unix + Double(fraction) / 4_294_967_296.0
    }
}

/// Wall-clock source for the obfuscation layer. Once an NTP sample is
/// accepted, time is advanced monotonically so a later system clock step does
/// not corrupt the ±120 s timestamp window.
public final class TimeProvider {
    private var base: (unix: Double, monotonic: TimeInterval)?
    private let monotonic: () -> TimeInterval
    private let systemUnix: () -> Double

    public init(
        monotonic: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        systemUnix: @escaping () -> Double = { Date().timeIntervalSince1970 }
    ) {
        self.monotonic = monotonic
        self.systemUnix = systemUnix
    }

    public var isSynced: Bool { base != nil }

    public func now() -> UInt32 {
        let seconds: Double
        if let base {
            seconds = base.unix + max(0, monotonic() - base.monotonic)
        } else {
            seconds = systemUnix()
        }
        return UInt32(max(0, min(seconds, Double(UInt32.max))))
    }

    public func accept(_ sample: SNTPSample) {
        base = (sample.unixTime, sample.monotonicTime)
    }

    public func reset() {
        base = nil
    }
}
