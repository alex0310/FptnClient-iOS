import Foundation

/// FPTN stamps a time-based key into the TLS legacy session identifier so the
/// server can tell a real client from a probe.
public enum FPTNSessionKey {
    public static let keyLength = 4
    public static let sessionIDLength = 32
    /// Reality-mode decoy handshake stamp offset (upstream shift 2).
    public static let decoyOffset = 14

    /// First four bytes of SHA-1 over the big-endian timestamp.
    public static func generate(timestamp: UInt32) -> [UInt8] {
        let input: [UInt8] = [
            UInt8((timestamp >> 24) & 0xff),
            UInt8((timestamp >> 16) & 0xff),
            UInt8((timestamp >> 8) & 0xff),
            UInt8(timestamp & 0xff)
        ]
        return Array(Digests.sha1(input).prefix(keyLength))
    }

    public static func stampedSessionID(
        random: [UInt8],
        timestamp: UInt32,
        offset: Int
    ) throws -> [UInt8] {
        guard random.count == sessionIDLength else {
            throw TLSError.invalidConfiguration("session id must be 32 bytes")
        }
        guard offset >= 0, offset + keyLength <= random.count else {
            throw TLSError.invalidConfiguration("session id stamp offset is out of range")
        }
        var sessionID = random
        let key = generate(timestamp: timestamp)
        for index in 0..<keyLength {
            sessionID[offset + index] = key[index]
        }
        return sessionID
    }

    public static func realSessionID(random: [UInt8], timestamp: UInt32) throws -> [UInt8] {
        try stampedSessionID(
            random: random,
            timestamp: timestamp,
            offset: sessionIDLength - keyLength
        )
    }

    public static func decoySessionID(random: [UInt8], timestamp: UInt32) throws -> [UInt8] {
        try stampedSessionID(random: random, timestamp: timestamp, offset: decoyOffset)
    }

    /// Checks a received session id the same way the server does: any key in a
    /// +/-120 second window is accepted.
    public static func matches(sessionID: [UInt8], offset: Int, timestamp: UInt32) -> Bool {
        guard sessionID.count >= offset + keyLength else { return false }
        let received = Array(sessionID[offset..<(offset + keyLength)])
        for shift in 0...240 {
            guard let candidate = UInt32(exactly: Int64(timestamp) - 120 + Int64(shift)) else {
                continue
            }
            if generate(timestamp: candidate) == received { return true }
        }
        return false
    }
}
