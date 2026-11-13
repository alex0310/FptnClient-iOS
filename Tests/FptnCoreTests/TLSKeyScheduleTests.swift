import XCTest
@testable import FptnCore

/// Validates the TLS 1.3 key schedule against the RFC 8448 section 5 trace.
final class TLSKeyScheduleTests: XCTestCase {
    private let sharedSecret = hex(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    )
    private let handshakeTranscriptHash = hex(
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    )
    private let fullTranscriptHash = hex(
        "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    )

    /// Transcript state at the point handshake traffic secrets are derived.
    private func scheduleAfterServerHello() -> TLSKeySchedule {
        var schedule = TLSKeySchedule(hash: .sha256)
        schedule.appendTranscript(RFC8448.clientHello)
        schedule.appendTranscript(RFC8448.serverHello)
        return schedule
    }

    /// Transcript state after the server Finished message.
    private func scheduleAfterServerFinished() -> TLSKeySchedule {
        var schedule = scheduleAfterServerHello()
        schedule.appendTranscript(RFC8448.encryptedExtensions)
        schedule.appendTranscript(RFC8448.certificate)
        schedule.appendTranscript(RFC8448.certificateVerify)
        schedule.appendTranscript(RFC8448.serverFinished)
        return schedule
    }

    func testTranscriptHashAfterServerHello() {
        var schedule = TLSKeySchedule(hash: .sha256)
        schedule.appendTranscript(RFC8448.clientHello)
        schedule.appendTranscript(RFC8448.serverHello)
        XCTAssertEqual(schedule.transcriptHash(), handshakeTranscriptHash)
    }

    func testTranscriptHashAfterServerFinished() {
        XCTAssertEqual(scheduleAfterServerFinished().transcriptHash(), fullTranscriptHash)
    }

    func testEmptyTranscriptHash() {
        let schedule = TLSKeySchedule(hash: .sha256)
        XCTAssertEqual(
            schedule.transcriptHash(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        )
    }

    func testEarlySecret() {
        XCTAssertEqual(
            TLSKeySchedule(hash: .sha256).earlySecret(),
            hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        )
    }

    func testDerivedSecret() {
        let schedule = TLSKeySchedule(hash: .sha256)
        let derived = HKDF.expandLabel(
            hash: .sha256,
            secret: schedule.earlySecret(),
            label: "derived",
            context: schedule.transcriptHash(),
            length: 32
        )
        XCTAssertEqual(
            derived,
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        )
    }

    func testHandshakeSecretsAndMasterSecret() {
        let secrets = scheduleAfterServerHello().handshakeSecrets(sharedSecret: sharedSecret)
        XCTAssertEqual(
            secrets.handshakeSecret,
            hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        )
        XCTAssertEqual(
            secrets.clientHandshakeTrafficSecret,
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        )
        XCTAssertEqual(
            secrets.serverHandshakeTrafficSecret,
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        )
        XCTAssertEqual(
            secrets.masterSecret,
            hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        )
    }

    func testServerHandshakeTrafficKeys() {
        let handle = scheduleAfterServerHello()
        let secrets = handle.handshakeSecrets(sharedSecret: sharedSecret)
        let keys = handle.trafficKeys(
            trafficSecret: secrets.serverHandshakeTrafficSecret,
            keyLength: 16
        )
        XCTAssertEqual(keys.key, hex("3fce516009c21727d0f2e4e86ee403bc"))
        XCTAssertEqual(keys.iv, hex("5d313eb2671276ee13000b30"))
    }

    func testClientHandshakeTrafficKeys() {
        let handle = scheduleAfterServerHello()
        let secrets = handle.handshakeSecrets(sharedSecret: sharedSecret)
        let keys = handle.trafficKeys(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            keyLength: 16
        )
        XCTAssertEqual(keys.key, hex("dbfaa693d1762c5b666af5d950258d01"))
        XCTAssertEqual(keys.iv, hex("5bd3c71b836e0b76bb73265f"))
    }

    func testApplicationSecrets() {
        let handle = scheduleAfterServerFinished()
        let handshake = scheduleAfterServerHello().handshakeSecrets(sharedSecret: sharedSecret)
        XCTAssertEqual(handle.transcriptHash(), fullTranscriptHash)
        let application = handle.applicationSecrets(masterSecret: handshake.masterSecret)
        XCTAssertEqual(
            application.clientApplicationTrafficSecret,
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        )
        XCTAssertEqual(
            application.serverApplicationTrafficSecret,
            hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        )
    }

    func testServerApplicationTrafficKeys() {
        let handle = scheduleAfterServerFinished()
        let handshake = scheduleAfterServerHello().handshakeSecrets(sharedSecret: sharedSecret)
        let application = handle.applicationSecrets(masterSecret: handshake.masterSecret)
        let keys = handle.trafficKeys(
            trafficSecret: application.serverApplicationTrafficSecret,
            keyLength: 16
        )
        XCTAssertEqual(keys.key, hex("9f02283b6c9c07efc26bb9f2ac92e356"))
        XCTAssertEqual(keys.iv, hex("cf782b88dd83549aadf1e984"))
    }

    func testClientFinishedVerifyData() {
        let transcript = scheduleAfterServerFinished()
        let secrets = scheduleAfterServerHello().handshakeSecrets(sharedSecret: sharedSecret)
        let verifyData = transcript.finishedVerifyData(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            transcriptHash: transcript.transcriptHash()
        )
        XCTAssertEqual(
            verifyData,
            hex("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
        )
    }

    func testFinishedKeyMatchesRFC8448ExpandInfo() {
        let handle = TLSKeySchedule(hash: .sha256)
        XCTAssertEqual(
            handle.finishedKey(
                trafficSecret: hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
            ),
            hex("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
        )
    }

    func testNextTrafficSecretIsDeterministicAndUnique() {
        let handle = TLSKeySchedule(hash: .sha256)
        let secret = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        let first = handle.nextTrafficSecret(secret)
        let second = handle.nextTrafficSecret(secret)
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 32)
        XCTAssertNotEqual(first, secret)
    }

    func testSHA384KeyLengthsAndDeterminism() {
        let handle = TLSKeySchedule(hash: .sha384)
        XCTAssertEqual(handle.earlySecret().count, 48)
        let secrets = handle.handshakeSecrets(sharedSecret: [UInt8](repeating: 0x01, count: 48))
        XCTAssertEqual(secrets.handshakeSecret.count, 48)
        XCTAssertEqual(secrets.masterSecret.count, 48)
        XCTAssertEqual(secrets.clientHandshakeTrafficSecret.count, 48)
        let keys = handle.trafficKeys(trafficSecret: secrets.clientHandshakeTrafficSecret, keyLength: 32)
        XCTAssertEqual(keys.key.count, 32)
        XCTAssertEqual(keys.iv.count, 12)
    }

    func testTranscriptAccumulatesIncrementally() {
        var incremental = TLSKeySchedule(hash: .sha256)
        incremental.appendTranscript(RFC8448.clientHello)
        incremental.appendTranscript(RFC8448.serverHello)
        var combined = TLSKeySchedule(hash: .sha256)
        combined.appendTranscript(RFC8448.clientHello + RFC8448.serverHello)
        XCTAssertEqual(incremental.transcriptHash(), combined.transcriptHash())
    }
}
