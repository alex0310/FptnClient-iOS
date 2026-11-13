import XCTest

@testable import FptnCore

final class SplitTunnelRouteStoreTests: XCTestCase {
    private func address(_ value: String) -> IPAddress {
        IPAddress(value)!
    }

    func testInsertDeduplicatesAndPreservesDiscoveryOrder() {
        let store = SplitTunnelRouteStore()
        XCTAssertTrue(
            store.insert([
                address("1.2.3.4"),
                address("5.6.7.8"),
                address("1.2.3.4")
            ])
        )
        XCTAssertEqual(
            store.snapshot(),
            [address("1.2.3.4"), address("5.6.7.8")]
        )
        XCTAssertEqual(store.count, 2)
        XCTAssertFalse(store.insert([address("5.6.7.8")]))
        XCTAssertEqual(store.count, 2)
    }

    func testCapacityEvictsOldestAddresses() {
        let store = SplitTunnelRouteStore(capacity: 2)
        XCTAssertTrue(
            store.insert([
                address("1.1.1.1"),
                address("2.2.2.2"),
                address("3.3.3.3")
            ])
        )
        XCTAssertEqual(store.snapshot(), [address("2.2.2.2"), address("3.3.3.3")])
        XCTAssertTrue(store.insert([address("4.4.4.4")]))
        XCTAssertEqual(store.snapshot(), [address("3.3.3.3"), address("4.4.4.4")])
    }

    func testEmptyInsertDoesNothing() {
        let store = SplitTunnelRouteStore()
        XCTAssertFalse(store.insert([]))
        XCTAssertEqual(store.snapshot(), [])
    }

    func testSnapshotIsIndependentCopy() {
        let store = SplitTunnelRouteStore()
        _ = store.insert([address("9.9.9.9")])
        var snapshot = store.snapshot()
        snapshot.append(address("8.8.8.8"))
        XCTAssertEqual(store.snapshot(), [address("9.9.9.9")])
    }
}
