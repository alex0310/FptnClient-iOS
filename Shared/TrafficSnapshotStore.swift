import Foundation

/// The extension publishes counters into the shared App Group container; the
/// app only reads them. Writing a single encoded blob keeps the exchange
/// atomic and avoids a suite of per-counter keys drifting out of sync.
public enum TrafficSnapshotStore {
    public static let key = "fptn.traffic.v1"

    public static func write(
        _ snapshot: TrafficSnapshot,
        defaults: UserDefaults? = UserDefaults(suiteName: SharedStore.suiteName)
    ) {
        guard let defaults,
              let data = try? JSONEncoder().encode(snapshot) else { return }
        defaults.set(data, forKey: key)
    }

    public static func read(
        defaults: UserDefaults? = UserDefaults(suiteName: SharedStore.suiteName)
    ) -> TrafficSnapshot? {
        guard let defaults,
              let data = defaults.data(forKey: key),
              let snapshot = try? JSONDecoder().decode(TrafficSnapshot.self, from: data) else {
            return nil
        }
        return snapshot
    }

    public static func clear(
        defaults: UserDefaults? = UserDefaults(suiteName: SharedStore.suiteName)
    ) {
        defaults?.removeObject(forKey: key)
    }
}
