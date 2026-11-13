import XCTest

@testable import FptnCore

final class FPTNClientTests: XCTestCase {
    private func server() -> FPTNServer {
        FPTNServer(
            name: "test",
            host: "127.0.0.1",
            port: 8443,
            md5Fingerprint: nil,
            countryCode: nil,
            isCensoredZone: false
        )
    }

    private func token() -> FPTNAccessToken {
        FPTNAccessToken(
            version: 1,
            serviceName: "test",
            username: "user",
            password: "pass",
            servers: [server()]
        )
    }

    private func response(_ json: String) -> HTTPResponse {
        HTTPResponse(
            statusCode: 200,
            reason: "OK",
            headers: [HTTPHeader(name: "Content-Type", value: "application/json")],
            body: Array(json.utf8)
        )
    }

    private func successfulAPI() -> FPTNAPIClient.Transport {
        { request, _ in
            if request.target == "/api/v1/login" {
                return self.response("{\"access_token\":\"jwt-token\"}")
            }
            return self.response("{\"dns\":\"10.0.0.53\",\"dns_ipv6\":\"fd00::53\"}")
        }
    }

    private func makeClient(
        clock: @escaping () -> TimeInterval = { 0 },
        api: FPTNAPIClient.Transport? = nil,
        connector: FPTNClient.TunnelConnector? = nil
    ) -> FPTNClient {
        FPTNClient(
            accessToken: token(),
            configuration: FPTNClientConfiguration(
                pool: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
                securityMode: .plain
            ),
            clock: clock,
            apiTransport: api ?? successfulAPI(),
            tunnelConnector: connector ?? { _, _, _, _ in ClientFakeTunnel() }
        )
    }

    func testStartLogsInFetchesDNSAndOpensPool() throws {
        let client = makeClient()
        let dns = try client.start()
        XCTAssertEqual(client.state, .connected)
        XCTAssertEqual(client.jwt, "jwt-token")
        XCTAssertEqual(client.selectedServer, server())
        XCTAssertEqual(dns?.dns, "10.0.0.53")
        XCTAssertEqual(client.pool?.activeSlots.count, 1)
    }

    func testStartUsesPreferredServerBeforeRace() throws {
        let first = server()
        let preferred = FPTNServer(
            name: "preferred",
            host: "127.0.0.2",
            port: 8443,
            md5Fingerprint: nil,
            countryCode: nil,
            isCensoredZone: false
        )
        let token = FPTNAccessToken(
            version: 1,
            serviceName: "test",
            username: "user",
            password: "pass",
            servers: [first, preferred]
        )
        let lock = NSLock()
        var loginServers: [String] = []
        let api: FPTNAPIClient.Transport = { request, server in
            if request.target == "/api/v1/login" {
                lock.lock()
                loginServers.append(server.id)
                lock.unlock()
                return self.response("{\"access_token\":\"jwt-token\"}")
            }
            return self.response("{\"dns\":\"10.0.0.53\"}")
        }
        let client = FPTNClient(
            accessToken: token,
            configuration: FPTNClientConfiguration(
                pool: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
                securityMode: .plain,
                preferredServerID: preferred.id
            ),
            clock: { 0 },
            apiTransport: api,
            tunnelConnector: { _, _, _, _ in ClientFakeTunnel() }
        )

        try client.start()

        XCTAssertEqual(client.selectedServer, preferred)
        XCTAssertEqual(loginServers, [preferred.id])
    }

    func testStartReportsLoginFailure() {
        let client = makeClient(api: { _, _ in
            throw TransportError.closed
        })
        XCTAssertThrowsError(try client.start()) { error in
            XCTAssertEqual(error as? FPTNClientError, .loginFailed)
        }
        XCTAssertEqual(client.state, .failed(FPTNClientError.loginFailed.localizedDescription))
    }

    func testDNSFailureDoesNotAbortTheTunnel() throws {
        let client = makeClient(api: { request, _ in
            if request.target == "/api/v1/login" {
                return self.response("{\"access_token\":\"jwt\"}")
            }
            throw TransportError.timeout
        })
        XCTAssertNil(try client.start())
        XCTAssertEqual(client.state, .connected)
    }

    func testConnectorFailureFailsStart() {
        let client = makeClient(connector: { _, _, _, _ in
            throw TransportError.connectFailed("no")
        })
        XCTAssertThrowsError(try client.start()) { error in
            XCTAssertEqual(error as? FPTNClientError, .noTunnel)
        }
        XCTAssertEqual(client.state, .failed(FPTNClientError.noTunnel.localizedDescription))
    }

    func testSendDispatchesPacketsAndStopClosesPool() throws {
        let fake = ClientFakeTunnel()
        let client = makeClient(connector: { _, _, _, _ in fake })
        try client.start()
        var packet = [UInt8](repeating: 0, count: 24)
        packet[0] = 0x45
        packet[9] = IPPacket.protocolICMP
        XCTAssertEqual(try client.send(packets: [packet]), 1)
        XCTAssertEqual(fake.sent.count, 1)
        client.stop()
        XCTAssertEqual(client.state, .stopped)
        XCTAssertTrue(fake.isClosed)
    }

    func testSendBeforeStartThrows() {
        let client = makeClient()
        XCTAssertThrowsError(try client.send(packets: [[0x45]])) { error in
            XCTAssertEqual(error as? FPTNClientError, .notStarted)
        }
    }

    func testMaintainFillsSecondConnection() throws {
        var now: TimeInterval = 0
        var created: [ClientFakeTunnel] = []
        let client = makeClient(clock: { now }, connector: { _, _, _, _ in
            let fake = ClientFakeTunnel()
            created.append(fake)
            return fake
        })
        try client.start()
        now = 15
        XCTAssertEqual(client.maintain(), .connected)
        XCTAssertEqual(client.pool?.activeSlots.count, 2)
        XCTAssertEqual(created.count, 2)
    }

    func testMaintainWithoutPoolFails() {
        let client = makeClient()
        XCTAssertEqual(
            client.maintain(),
            .failed(FPTNClientError.notStarted.localizedDescription)
        )
    }

    func testNoServersIsRejectedBeforeLogin() {
        let client = FPTNClient(
            accessToken: FPTNAccessToken(
                version: 1,
                serviceName: nil,
                username: "u",
                password: "p",
                servers: []
            ),
            apiTransport: successfulAPI(),
            tunnelConnector: { _, _, _, _ in ClientFakeTunnel() }
        )
        XCTAssertThrowsError(try client.start()) { error in
            XCTAssertEqual(error as? FPTNClientError, .noServers)
        }
    }
}

private final class ClientFakeTunnel: PoolTunnel {
    var assignedIPv4: IPAddress? = IPAddress("10.0.0.2")
    var assignedIPv6: IPAddress? = IPAddress("fd00::2")
    var isClosed = false
    private(set) var sent: [[UInt8]] = []

    func send(packets: [[UInt8]]) throws -> Int {
        sent.append(contentsOf: packets)
        return packets.count
    }

    func receivePackets() throws -> [[UInt8]] {
        []
    }

    func tick() throws -> FPTNTunnelStatus {
        .active
    }

    func close() {
        isClosed = true
    }
}
