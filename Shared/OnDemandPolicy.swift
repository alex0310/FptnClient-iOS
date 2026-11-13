import Foundation

/// Platform-independent description of the NetworkExtension on-demand policy.
/// Keeping the decision here makes the app/extension boundary testable without
/// importing NetworkExtension on Linux.
public struct OnDemandRuleDescriptor: Equatable, Sendable {
    public enum InterfaceType: String, Sendable {
        case any
    }

    public let interfaceType: InterfaceType

    public init(interfaceType: InterfaceType = .any) {
        self.interfaceType = interfaceType
    }
}

public enum OnDemandPolicy {
    /// Automatic mode installs one always-connect rule; manual mode installs
    /// none, so the tunnel only starts from the app's connect action.
    public static func rules(enabled: Bool) -> [OnDemandRuleDescriptor] {
        enabled ? [OnDemandRuleDescriptor(interfaceType: .any)] : []
    }
}
