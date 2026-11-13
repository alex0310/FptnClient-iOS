import Foundation

#if canImport(Security)
import Security
#endif

enum KeychainAccessError: Error, Equatable {
    case itemNotFound
    case duplicateItem
    case status(Int32)
}

protocol KeychainAccess {
    func copyData(service: String, account: String, accessGroup: String?) throws -> Data?
    func add(service: String, account: String, accessGroup: String?, data: Data) throws
    func update(service: String, account: String, accessGroup: String?, data: Data) throws
    func delete(service: String, account: String, accessGroup: String?) throws
}

/// Token store with an injectable Keychain client so update/add/delete
/// fallbacks can be unit-tested without touching the real Keychain.
final class KeychainTokenStore: TokenStore {
    private let access: any KeychainAccess
    private let service: String
    private let account: String
    private let accessGroup: String?

    init(
        access: any KeychainAccess,
        service: String,
        account: String,
        accessGroup: String? = nil
    ) {
        self.access = access
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }

    func load() throws -> String? {
        do {
            guard let data = try access.copyData(
                service: service,
                account: account,
                accessGroup: accessGroup
            ) else {
                return nil
            }
            guard let raw = String(data: data, encoding: .utf8) else {
                throw TokenStoreError.malformedData
            }
            let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            return token.isEmpty ? nil : token
        } catch let error as TokenStoreError {
            throw error
        } catch {
            throw map(error)
        }
    }

    func save(_ token: String) throws {
        let value = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw TokenStoreError.emptyToken
        }
        let data = Data(value.utf8)
        do {
            try access.update(
                service: service,
                account: account,
                accessGroup: accessGroup,
                data: data
            )
        } catch KeychainAccessError.itemNotFound {
            do {
                try access.add(
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    data: data
                )
            } catch KeychainAccessError.duplicateItem {
                do {
                    try access.update(
                        service: service,
                        account: account,
                        accessGroup: accessGroup,
                        data: data
                    )
                } catch {
                    throw map(error)
                }
            } catch {
                throw map(error)
            }
        } catch {
            throw map(error)
        }
    }

    func delete() throws {
        do {
            try access.delete(
                service: service,
                account: account,
                accessGroup: accessGroup
            )
        } catch KeychainAccessError.itemNotFound {
            return
        } catch {
            throw map(error)
        }
    }

    private func map(_ error: Error) -> TokenStoreError {
        guard let keychainError = error as? KeychainAccessError else {
            return .keychain(-1)
        }
        switch keychainError {
        case .itemNotFound:
            return .keychain(-25300)
        case .duplicateItem:
            return .keychain(-25299)
        case let .status(status):
            return .keychain(status)
        }
    }
}

#if canImport(Security)
extension KeychainTokenStore {
    convenience init(
        service: String,
        account: String,
        accessGroup: String? = nil
    ) {
        self.init(
            access: SystemKeychainAccess(),
            service: service,
            account: account,
            accessGroup: accessGroup
        )
    }
}

private final class SystemKeychainAccess: KeychainAccess {
    func copyData(
        service: String,
        account: String,
        accessGroup: String?
    ) throws -> Data? {
        var query = baseQuery(
            service: service,
            account: account,
            accessGroup: accessGroup
        )
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainAccessError.status(Int32(status))
        }
        guard let data = result as? Data else {
            throw KeychainAccessError.status(Int32(errSecDecode))
        }
        return data
    }

    func add(
        service: String,
        account: String,
        accessGroup: String?,
        data: Data
    ) throws {
        var attributes = baseQuery(
            service: service,
            account: account,
            accessGroup: accessGroup
        )
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            throw KeychainAccessError.duplicateItem
        }
        guard status == errSecSuccess else {
            throw KeychainAccessError.status(Int32(status))
        }
    }

    func update(
        service: String,
        account: String,
        accessGroup: String?,
        data: Data
    ) throws {
        let query = baseQuery(
            service: service,
            account: account,
            accessGroup: accessGroup
        )
        let attributes = [kSecValueData as String: data]
        let status = SecItemUpdate(
            query as CFDictionary,
            attributes as CFDictionary
        )
        if status == errSecItemNotFound {
            throw KeychainAccessError.itemNotFound
        }
        guard status == errSecSuccess else {
            throw KeychainAccessError.status(Int32(status))
        }
    }

    func delete(
        service: String,
        account: String,
        accessGroup: String?
    ) throws {
        let query = baseQuery(
            service: service,
            account: account,
            accessGroup: accessGroup
        )
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw KeychainAccessError.itemNotFound
        }
        guard status == errSecSuccess else {
            throw KeychainAccessError.status(Int32(status))
        }
    }

    private func baseQuery(
        service: String,
        account: String,
        accessGroup: String?
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
#endif
