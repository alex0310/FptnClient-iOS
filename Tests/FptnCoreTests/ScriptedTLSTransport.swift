import Foundation

@testable import FptnCore

/// In-memory TLS 1.3 server endpoint used by `TLSConnection` tests. It
/// deobfuscates client handshake writes, drives `SimulatedTLSServer`, and
/// queues obfuscated server responses.
final class ScriptedTLSTransport: ByteTransport {
    enum Phase {
        case decoy
        case changeCipherSpec
        case handshake
        case application
    }

    let mode: FPTNSecurityMode
    let server: SimulatedTLSServer
    var timestamp: UInt32
    var readChunkSize = Int.max
    private(set) var clientWrites: [UInt8] = []
    private(set) var receivedApplicationData: [UInt8] = []
    private(set) var receivedAlert: [UInt8]?
    private(set) var isClosed = false

    private var readQueue: [UInt8] = []
    private var deobfuscator = TlsObfuscator2()
    private var obfuscator = TlsObfuscator2()
    private var phase: Phase
    private var sentServerFlight = false
    private var receivedClientFinished = false

    init(
        mode: FPTNSecurityMode,
        suite: TLSCipherSuite = .aes128GcmSha256,
        timestamp: UInt32 = 1_700_000_000
    ) {
        self.mode = mode
        self.server = SimulatedTLSServer(suite: suite)
        self.timestamp = timestamp
        self.phase = mode == .reality ? .decoy : .handshake
    }

    func read(maxBytes: Int) throws -> [UInt8] {
        guard !readQueue.isEmpty else {
            if isClosed { throw TransportError.closed }
            throw TransportError.timeout
        }
        let count = min(min(maxBytes, readChunkSize), readQueue.count)
        let result = Array(readQueue.prefix(count))
        readQueue.removeFirst(count)
        return result
    }

    func write(_ bytes: [UInt8]) throws {
        clientWrites.append(contentsOf: bytes)
        switch phase {
        case .decoy:
            // Pretend the decoy domain answered with a ServerHello-shaped
            // record. The client only drains it.
            readQueue.append(contentsOf: [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00])
            phase = .changeCipherSpec
        case .changeCipherSpec:
            if bytes == [0x14, 0x03, 0x03, 0x00, 0x01, 0x01] {
                phase = .handshake
            }
        case .handshake:
            if mode == .plain {
                try handleHandshakePayload(bytes)
            } else {
                deobfuscator.push(bytes)
                while let payload = deobfuscator.nextPayload(now: timestamp) {
                    try handleHandshakePayload(payload)
                }
            }
        case .application:
            for record in try server.openClientRecords(bytes) {
                switch record.contentType {
                case .applicationData:
                    receivedApplicationData.append(contentsOf: record.plaintext)
                case .alert:
                    receivedAlert = record.plaintext
                case .handshake, .changeCipherSpec:
                    break
                }
            }
        }
    }

    func close() {
        isClosed = true
    }

    func setReadTimeout(_ seconds: TimeInterval) throws {}
    func setWriteTimeout(_ seconds: TimeInterval) throws {}

    func queueServerApplicationData(_ data: [UInt8]) throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + TLSRecordProtector.maximumPlaintextLength, data.count)
            readQueue.append(contentsOf: try server.sealApplicationData(
                Array(data[offset..<end])
            ))
            offset = end
        }
    }

    func queueServerKeyUpdate(requestUpdate: Bool) throws {
        readQueue.append(contentsOf: try server.sendKeyUpdate(requestUpdate: requestUpdate))
    }

    func receiveClientKeyUpdate(_ bytes: [UInt8]) throws {
        try server.receiveClientKeyUpdate(bytes)
    }

    // MARK: - Internals

    private func handleHandshakePayload(_ payload: [UInt8]) throws {
        if !sentServerFlight {
            let flight = try server.accept(clientOutput: payload)
            sentServerFlight = true
            if mode == .plain {
                readQueue.append(contentsOf: flight)
            } else {
                readQueue.append(contentsOf: try obfuscator.encode(
                    payload: flight,
                    timestamp: timestamp
                ))
            }
            return
        }
        if !receivedClientFinished {
            try server.receiveClientFinished(payload)
            receivedClientFinished = true
            phase = .application
            return
        }
        receivedApplicationData.append(
            contentsOf: try server.openApplicationData(payload)
        )
    }
}
