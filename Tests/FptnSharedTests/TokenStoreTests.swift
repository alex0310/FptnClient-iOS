import XCTest

@testable import FptnShared

final class TokenStoreTests: XCTestCase {
    func testUserDefaultsTokenStoreRoundTrip() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = UserDefaultsTokenStore(defaults: defaults)

        XCTAssertNil(try store.load())
        try store.save("fptn:first")
        XCTAssertEqual(try store.load(), "fptn:first")
        try store.save("fptn:second")
        XCTAssertEqual(try store.load(), "fptn:second")
        try store.delete()
        XCTAssertNil(try store.load())
    }

    func testUserDefaultsTokenStoreTrimsAndRejectsEmpty() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = UserDefaultsTokenStore(defaults: defaults)

        try store.save("  fptn:trimmed \n")
        XCTAssertEqual(try store.load(), "fptn:trimmed")

        XCTAssertThrowsError(try store.save("   \n")) { error in
            XCTAssertEqual(error as? TokenStoreError, .emptyToken)
        }
        XCTAssertEqual(try store.load(), "fptn:trimmed")
    }

    func testUserDefaultsTokenStoreBlankValueLoadsAsNil() throws {
        let suite = "FptnSharedTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(" \n ", forKey: UserDefaultsTokenStore.defaultKey)

        let store = UserDefaultsTokenStore(defaults: defaults)
        XCTAssertNil(try store.load())
    }

    func testKeychainStoreLoadsNilWhenItemIsMissing() throws {
        let keychain = FakeKeychain()
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertNil(try store.load())
        XCTAssertEqual(keychain.lastService, "service")
        XCTAssertEqual(keychain.lastAccount, "account")
    }

    func testKeychainStoreLoadsStoredValueAndAccessGroup() throws {
        let keychain = FakeKeychain()
        keychain.data = Data("  fptn:stored  ".utf8)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account",
            accessGroup: "group.example"
        )

        XCTAssertEqual(try store.load(), "fptn:stored")
        XCTAssertEqual(keychain.lastAccessGroup, "group.example")
    }

    func testKeychainStoreRejectsMalformedUTF8() {
        let keychain = FakeKeychain()
        keychain.data = Data([0xff, 0xfe])
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? TokenStoreError, .malformedData)
        }
    }

    func testKeychainStoreBlankValueLoadsAsNil() throws {
        let keychain = FakeKeychain()
        keychain.data = Data(" \n ".utf8)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertNil(try store.load())
    }

    func testKeychainStoreSavesNewItemWhenUpdateIsNotFound() throws {
        let keychain = FakeKeychain()
        keychain.updateError = .itemNotFound
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        try store.save("  fptn:new  ")
        XCTAssertEqual(keychain.updateCalls, 1)
        XCTAssertEqual(keychain.addCalls, 1)
        XCTAssertEqual(keychain.data, Data("fptn:new".utf8))
    }

    func testKeychainStoreUpdatesExistingItem() throws {
        let keychain = FakeKeychain()
        keychain.data = Data("old".utf8)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        try store.save("new")
        XCTAssertEqual(keychain.updateCalls, 1)
        XCTAssertEqual(keychain.addCalls, 0)
        XCTAssertEqual(keychain.data, Data("new".utf8))
    }

    func testKeychainStoreRetriesUpdateWhenAddFindsDuplicate() throws {
        let keychain = FakeKeychain()
        keychain.updateError = .itemNotFound
        keychain.addError = .duplicateItem
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        try store.save("new")
        XCTAssertEqual(keychain.updateCalls, 2)
        XCTAssertEqual(keychain.addCalls, 1)
        XCTAssertEqual(keychain.data, Data("new".utf8))
    }

    func testKeychainStoreRejectsEmptyToken() {
        let keychain = FakeKeychain()
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.save(" \n ")) { error in
            XCTAssertEqual(error as? TokenStoreError, .emptyToken)
        }
        XCTAssertEqual(keychain.updateCalls, 0)
        XCTAssertEqual(keychain.addCalls, 0)
    }

    func testKeychainStoreIgnoresDeleteNotFound() throws {
        let keychain = FakeKeychain()
        keychain.deleteError = .itemNotFound
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertNoThrow(try store.delete())
        XCTAssertEqual(keychain.deleteCalls, 1)
    }

    func testKeychainStoreDeletesExistingItem() throws {
        let keychain = FakeKeychain()
        keychain.data = Data("token".utf8)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        try store.delete()
        XCTAssertEqual(keychain.deleteCalls, 1)
        XCTAssertNil(keychain.data)
    }

    func testKeychainStoreMapsUpdateStatus() {
        let keychain = FakeKeychain()
        keychain.updateError = .status(-4)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.save("token")) { error in
            XCTAssertEqual(error as? TokenStoreError, .keychain(-4))
        }
    }

    func testKeychainStoreMapsAddStatus() {
        let keychain = FakeKeychain()
        keychain.updateError = .itemNotFound
        keychain.addError = .status(-3)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.save("token")) { error in
            XCTAssertEqual(error as? TokenStoreError, .keychain(-3))
        }
    }

    func testKeychainStoreMapsUnexpectedStatus() {
        let keychain = FakeKeychain()
        keychain.loadError = .status(-1)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? TokenStoreError, .keychain(-1))
        }
    }

    func testKeychainStoreMapsDeleteStatus() {
        let keychain = FakeKeychain()
        keychain.deleteError = .status(-2)
        let store = KeychainTokenStore(
            access: keychain,
            service: "service",
            account: "account"
        )

        XCTAssertThrowsError(try store.delete()) { error in
            XCTAssertEqual(error as? TokenStoreError, .keychain(-2))
        }
    }

    func testTokenMigrationPrefersStoredToken() {
        let token = TokenMigration.preferredToken(
            stored: "  stored  ",
            legacy: "legacy"
        ) { $0 == "stored" || $0 == "legacy" }
        XCTAssertEqual(token, "stored")
    }

    func testTokenMigrationFallsBackToLegacyWhenStoredIsInvalid() {
        let token = TokenMigration.preferredToken(
            stored: "broken",
            legacy: "  legacy  "
        ) { $0 == "legacy" }
        XCTAssertEqual(token, "legacy")
    }

    func testTokenMigrationReturnsNilWhenBothCandidatesAreInvalid() {
        XCTAssertNil(
            TokenMigration.preferredToken(
                stored: "broken",
                legacy: "also-broken"
            ) { _ in false }
        )
        XCTAssertNil(
            TokenMigration.preferredToken(
                stored: "   ",
                legacy: nil
            ) { _ in true }
        )
    }

    func testTokenStoreErrorDescriptions() {
        XCTAssertEqual(
            TokenStoreError.emptyToken.errorDescription,
            "The access token is empty."
        )
        XCTAssertEqual(
            TokenStoreError.malformedData.errorDescription,
            "The stored access token is not valid UTF-8."
        )
        XCTAssertEqual(
            TokenStoreError.keychain(-25300).errorDescription,
            "Keychain operation failed with status -25300."
        )
    }

    #if canImport(Security)
    func testSystemKeychainRoundTrip() throws {
        let service = "FptnSharedTests.\(UUID().uuidString)"
        let store = KeychainTokenStore(service: service, account: "token")
        defer { try? store.delete() }

        XCTAssertNil(try store.load())
        try store.save("fptn:keychain")
        XCTAssertEqual(try store.load(), "fptn:keychain")
        try store.delete()
        XCTAssertNil(try store.load())
    }
    #endif
}

private final class FakeKeychain: KeychainAccess {
    var data: Data?
    var loadError: KeychainAccessError?
    var updateError: KeychainAccessError?
    var addError: KeychainAccessError?
    var deleteError: KeychainAccessError?
    var lastService: String?
    var lastAccount: String?
    var lastAccessGroup: String?
    var updateCalls = 0
    var addCalls = 0
    var deleteCalls = 0

    func copyData(
        service: String,
        account: String,
        accessGroup: String?
    ) throws -> Data? {
        record(service: service, account: account, accessGroup: accessGroup)
        if let loadError {
            self.loadError = nil
            throw loadError
        }
        return data
    }

    func add(
        service: String,
        account: String,
        accessGroup: String?,
        data: Data
    ) throws {
        record(service: service, account: account, accessGroup: accessGroup)
        addCalls += 1
        if let addError {
            self.addError = nil
            throw addError
        }
        self.data = data
    }

    func update(
        service: String,
        account: String,
        accessGroup: String?,
        data: Data
    ) throws {
        record(service: service, account: account, accessGroup: accessGroup)
        updateCalls += 1
        if let updateError {
            self.updateError = nil
            throw updateError
        }
        self.data = data
    }

    func delete(
        service: String,
        account: String,
        accessGroup: String?
    ) throws {
        record(service: service, account: account, accessGroup: accessGroup)
        deleteCalls += 1
        if let deleteError {
            self.deleteError = nil
            throw deleteError
        }
        data = nil
    }

    private func record(service: String, account: String, accessGroup: String?) {
        lastService = service
        lastAccount = account
        lastAccessGroup = accessGroup
    }
}
