import Foundation

/// Persists the FPTN bearer token outside the shared settings blob. The app
/// uses Keychain on Apple platforms; Linux builds and tests use a UserDefaults
/// implementation with the same semantics.
public protocol TokenStore {
    func load() throws -> String?
    func save(_ token: String) throws
    func delete() throws
}

public enum TokenStoreError: Error, Equatable, LocalizedError {
    case emptyToken
    case malformedData
    case keychain(Int32)

    public var errorDescription: String? {
        switch self {
        case .emptyToken:
            return "The access token is empty."
        case .malformedData:
            return "The stored access token is not valid UTF-8."
        case let .keychain(status):
            return "Keychain operation failed with status \(status)."
        }
    }
}

/// Linux/test fallback with the same observable behavior as the Keychain
/// store: values are trimmed, empty values are rejected, and a missing value
/// loads as `nil`.
public struct UserDefaultsTokenStore: TokenStore {
    public static let defaultKey = "fptn.accessToken.v1"

    private let defaults: UserDefaults
    private let key: String

    public init(defaults: UserDefaults, key: String = UserDefaultsTokenStore.defaultKey) {
        self.defaults = defaults
        self.key = key
    }

    public init?(suiteName: String, key: String = UserDefaultsTokenStore.defaultKey) {
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            return nil
        }
        self.init(defaults: defaults, key: key)
    }

    public func load() throws -> String? {
        guard let raw = defaults.string(forKey: key) else {
            return nil
        }
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return token.isEmpty ? nil : token
    }

    public func save(_ token: String) throws {
        let value = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw TokenStoreError.emptyToken
        }
        defaults.set(value, forKey: key)
    }

    public func delete() throws {
        defaults.removeObject(forKey: key)
    }
}

/// Resolves the first usable token when an older build stored it in the
/// App Group settings blob. The validator lets the caller reject malformed
/// tokens without making `FptnShared` depend on `FptnCore`.
public enum TokenMigration {
    public static func preferredToken(
        stored: String?,
        legacy: String?,
        isValid: (String) -> Bool
    ) -> String? {
        for candidate in [stored, legacy] {
            guard let candidate else { continue }
            let token = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty, isValid(token) else { continue }
            return token
        }
        return nil
    }
}

public enum TokenStorage {
    public static let service = "com.example.fptnclient"
    public static let account = "fptn-access-token"
    public static let accessGroupInfoKey = "FPTNKeychainAccessGroup"

    /// Optional shared Keychain access group from Info.plist. The app works
    /// without it; a shared group is only needed if an extension reads
    /// Keychain directly instead of receiving the token in its VPN profile.
    public static func configuredAccessGroup(bundle: Bundle = .main) -> String? {
        guard let raw = bundle.object(forInfoDictionaryKey: accessGroupInfoKey) as? String else {
            return nil
        }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains("$(") else {
            return nil
        }
        return value
    }

    public static func make(
        accessGroup: String? = nil,
        bundle: Bundle = .main
    ) -> any TokenStore {
        #if canImport(Security)
        return KeychainTokenStore(
            service: service,
            account: account,
            accessGroup: accessGroup ?? configuredAccessGroup(bundle: bundle)
        )
        #else
        let defaults = UserDefaults(suiteName: SharedStore.suiteName) ?? .standard
        return UserDefaultsTokenStore(defaults: defaults)
        #endif
    }
}
