import Foundation

public struct TLSClientConfiguration: Sendable {
    public let serverName: String
    public let cipherSuites: [TLSCipherSuite]
    public let expectedCertificateMD5: String?
    public let maxHandshakeSize: Int
    public let certificatePolicy: CertificateValidationPolicy

    public init(
        serverName: String,
        cipherSuites: [TLSCipherSuite] = TLSCipherSuite.allCases,
        expectedCertificateMD5: String? = nil,
        maxHandshakeSize: Int = 1 << 20,
        certificatePolicy: CertificateValidationPolicy? = nil
    ) {
        self.serverName = serverName
        self.cipherSuites = cipherSuites
        self.expectedCertificateMD5 = expectedCertificateMD5
        self.maxHandshakeSize = maxHandshakeSize
        // Backwards compatible default: an MD5 pin when the token supplies
        // one, otherwise no silent trust (the pinner fails closed).
        self.certificatePolicy = certificatePolicy ?? .pinnedMD5(expectedCertificateMD5)
    }
}

public enum TLSClientState: String, Sendable {
    case idle
    case waitServerHello
    case handshaking
    case connected
    case closed
    case failed
}

public enum TLSClientEvent: Equatable, Sendable {
    case handshakeCompleted
    case applicationData([UInt8])
    case closed
}

public struct TLSClientStep: Equatable, Sendable {
    public let output: [UInt8]
    public let events: [TLSClientEvent]

    public init(output: [UInt8], events: [TLSClientEvent]) {
        self.output = output
        self.events = events
    }
}
