import Foundation

public enum SecureRandom {
    /// Cryptographically secure random bytes. `SystemRandomNumberGenerator`
    /// uses `getrandom(2)` on Linux and the platform CSPRNG on Apple systems.
    public static func bytes(_ count: Int) -> [UInt8] {
        precondition(count >= 0)
        var generator = SystemRandomNumberGenerator()
        var output = [UInt8]()
        output.reserveCapacity(count)
        for _ in 0..<count {
            output.append(UInt8.random(in: .min ... .max, using: &generator))
        }
        return output
    }
}
