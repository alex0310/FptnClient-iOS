import XCTest

@testable import FptnCore

final class TunnelPoolTests: XCTestCase {
    private func tcpPacket(sourcePort: UInt16) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 24)
        packet[0] = 0x45
        packet[9] = IPPacket.protocolTCP
        packet[20] = UInt8((sourcePort >> 8) & 0xff)
        packet[21] = UInt8(sourcePort & 0xff)
        return packet
    }

    private func icmpPacket() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 24)
        packet[0] = 0x45
        packet[9] = IPPacket.protocolICMP
        return packet
    }

    private func makePool(
        configuration: TunnelPoolConfiguration,
        clock: @escaping () -> TimeInterval,
        connector: @escaping () throws -> any PoolTunnel
    ) -> TunnelPool {
        TunnelPool(
            configuration: configuration,
            sessionID: "session",
            connector: connector,
            clock: clock
        )
    }

    func testDualPoolFillsWithStaggeredLifetimes() {
        var now: TimeInterval = 0
        var created: [FakePoolTunnel] = []
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
            clock: { now }
        ) {
            let tunnel = FakePoolTunnel()
            created.append(tunnel)
            return tunnel
        }

        XCTAssertTrue(pool.maintain(now: 0))
        XCTAssertEqual(pool.activeSlots.count, 1)
        XCTAssertEqual(pool.activeSlots[0].closeAt, 300)

        XCTAssertFalse(pool.maintain(now: 0))
        now = 15
        XCTAssertTrue(pool.maintain(now: 15))
        XCTAssertEqual(pool.activeSlots.count, 2)
        XCTAssertEqual(pool.activeSlots[1].closeAt, 600)
        XCTAssertEqual(created.count, 2)

        now = 30
        XCTAssertFalse(pool.maintain(now: 30))
        XCTAssertEqual(pool.activeSlots.count, 2)
    }

    func testTriplePoolFillsThreeConnections() {
        var now: TimeInterval = 0
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .triple, lifetime: 600),
            clock: { now }
        ) { FakePoolTunnel() }

        XCTAssertTrue(pool.maintain(now: 0))
        XCTAssertEqual(pool.activeSlots[0].closeAt, 200)
        now = 15
        XCTAssertTrue(pool.maintain(now: 15))
        XCTAssertEqual(pool.activeSlots[1].closeAt, 400)
        now = 30
        XCTAssertTrue(pool.maintain(now: 30))
        XCTAssertEqual(pool.activeSlots.count, 3)
        XCTAssertEqual(pool.activeSlots[2].closeAt, 600)
    }

    func testPoolReplacesConnectionBeforeItsCloseTime() {
        var now: TimeInterval = 0
        var created: [FakePoolTunnel] = []
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
            clock: { now }
        ) {
            let tunnel = FakePoolTunnel()
            created.append(tunnel)
            return tunnel
        }
        _ = pool.maintain(now: 0)
        now = 15
        _ = pool.maintain(now: 15)
        let firstID = pool.activeSlots[0].id

        now = 250
        XCTAssertTrue(pool.maintain(now: 250))
        XCTAssertEqual(pool.activeSlots.count, 2)
        XCTAssertFalse(pool.activeSlots.contains { $0.id == firstID })
        XCTAssertEqual(created.count, 3)
        XCTAssertEqual(pool.activeSlots.map(\.closeAt).sorted(), [450, 600])
    }

    func testSourcePortPinsFlowToSameSlot() throws {
        var now: TimeInterval = 0
        var created: [FakePoolTunnel] = []
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
            clock: { now }
        ) {
            let tunnel = FakePoolTunnel()
            created.append(tunnel)
            return tunnel
        }
        _ = pool.maintain(now: 0)
        now = 15
        _ = pool.maintain(now: 15)

        XCTAssertEqual(try pool.send(packets: [tcpPacket(sourcePort: 443)]), 1)
        XCTAssertEqual(try pool.send(packets: [tcpPacket(sourcePort: 443)]), 1)
        let slot = pool.activeSlots[1].tunnel as? FakePoolTunnel
        XCTAssertEqual(slot?.sentPackets.count, 2)
        XCTAssertEqual((pool.activeSlots[0].tunnel as? FakePoolTunnel)?.sentPackets.count, 0)
    }

    func testPacketsWithoutSourcePortRoundRobin() throws {
        var now: TimeInterval = 0
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
            clock: { now }
        ) { FakePoolTunnel() }
        _ = pool.maintain(now: 0)
        now = 15
        _ = pool.maintain(now: 15)

        XCTAssertEqual(try pool.send(packets: [icmpPacket(), icmpPacket()]), 2)
        XCTAssertEqual((pool.activeSlots[0].tunnel as? FakePoolTunnel)?.sentPackets.count, 1)
        XCTAssertEqual((pool.activeSlots[1].tunnel as? FakePoolTunnel)?.sentPackets.count, 1)
    }

    func testTickRemovesDeadTunnelAndReplacesAfterStagger() {
        var now: TimeInterval = 0
        var created: [FakePoolTunnel] = []
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual, lifetime: 600),
            clock: { now }
        ) {
            let tunnel = FakePoolTunnel()
            created.append(tunnel)
            return tunnel
        }
        _ = pool.maintain(now: 0)
        now = 15
        _ = pool.maintain(now: 15)
        let dead = pool.activeSlots[0].tunnel as! FakePoolTunnel
        dead.tickStatus = .dead

        now = 20
        XCTAssertFalse(pool.tick(now: 20))
        XCTAssertEqual(pool.activeSlots.count, 1)
        XCTAssertTrue(dead.isClosed)

        now = 30
        XCTAssertTrue(pool.tick(now: 30))
        XCTAssertEqual(pool.activeSlots.count, 2)
        XCTAssertEqual(created.count, 3)
    }

    func testConnectorFailureIsRetriedAfterStagger() {
        var now: TimeInterval = 0
        var attempts = 0
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual),
            clock: { now }
        ) {
            attempts += 1
            if attempts == 1 { throw TunnelPoolError.connectorFailed }
            return FakePoolTunnel()
        }
        XCTAssertFalse(pool.maintain(now: 0))
        now = 14
        XCTAssertFalse(pool.maintain(now: 14))
        XCTAssertEqual(attempts, 1)
        now = 15
        XCTAssertTrue(pool.maintain(now: 15))
        XCTAssertEqual(attempts, 2)
    }

    func testSendWithoutTunnelThrows() {
        let pool = makePool(
            configuration: TunnelPoolConfiguration(),
            clock: { 0 }
        ) { throw TunnelPoolError.connectorFailed }
        XCTAssertThrowsError(try pool.send(packets: [icmpPacket()])) { error in
            XCTAssertEqual(error as? TunnelPoolError, .noTunnel)
        }
    }

    func testCloseClosesEveryTunnel() {
        var now: TimeInterval = 0
        var created: [FakePoolTunnel] = []
        let pool = makePool(
            configuration: TunnelPoolConfiguration(strategy: .dual),
            clock: { now }
        ) {
            let tunnel = FakePoolTunnel()
            created.append(tunnel)
            return tunnel
        }
        _ = pool.maintain(now: 0)
        now = 15
        _ = pool.maintain(now: 15)
        pool.close()
        XCTAssertTrue(pool.isEmpty)
        XCTAssertTrue(created.allSatisfy { $0.isClosed })
    }

    func testNextLifetimeMatchesUpstream() {
        XCTAssertEqual(TunnelPool.nextLifetimeSeconds(remaining: [], lifetime: 600, count: 2), 300)
        XCTAssertEqual(TunnelPool.nextLifetimeSeconds(remaining: [300], lifetime: 600, count: 2), 600)
        XCTAssertEqual(TunnelPool.nextLifetimeSeconds(remaining: [500, 590], lifetime: 600, count: 2), 250)
        XCTAssertEqual(TunnelPool.nextLifetimeSeconds(remaining: [120], lifetime: 600, count: 1), 600)
    }

    func testSessionIDIsSixtyFourAlphanumerics() {
        let id = TunnelPool.randomSessionID()
        XCTAssertEqual(id.count, 64)
        XCTAssertTrue(id.allSatisfy { $0.isLetter || $0.isNumber })
        XCTAssertNotEqual(id, TunnelPool.randomSessionID())
    }
}

private final class FakePoolTunnel: PoolTunnel {
    var assignedIPv4: IPAddress? = IPAddress("10.0.0.2")
    var assignedIPv6: IPAddress? = IPAddress("fd00::2")
    var isClosed = false
    var tickStatus: FPTNTunnelStatus = .active
    private(set) var sentPackets: [[UInt8]] = []

    func send(packets: [[UInt8]]) throws -> Int {
        sentPackets.append(contentsOf: packets)
        return packets.count
    }

    func receivePackets() throws -> [[UInt8]] {
        []
    }

    func tick() throws -> FPTNTunnelStatus {
        tickStatus
    }

    func close() {
        isClosed = true
    }
}
