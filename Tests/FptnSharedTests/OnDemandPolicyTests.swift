import XCTest

@testable import FptnShared

final class OnDemandPolicyTests: XCTestCase {
    func testAutomaticModeInstallsAlwaysConnectRule() {
        XCTAssertEqual(
            OnDemandPolicy.rules(enabled: true),
            [OnDemandRuleDescriptor(interfaceType: .any)]
        )
    }

    func testManualModeInstallsNoRules() {
        XCTAssertEqual(OnDemandPolicy.rules(enabled: false), [])
    }
}
