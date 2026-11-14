import Foundation
import SwiftBrotli

/// A server entry decoded from an FPTN access token.
public struct FPTNServer: Equatable, Hashable, Sendable {
    public let name: String
    public let host: String
    public let port: UInt16
    public let md5Fingerprint: String?
    /// SHA-256 of the leaf `SubjectPublicKeyInfo` (hex or base64).
    public let spkiSHA256: String?
    public let countryCode: String?
    public let isCensoredZone: Bool

    public init(
        name: String,
        host: String,
        port: UInt16,
        md5Fingerprint: String?,
        countryCode: String?,
        isCensoredZone: Bool,
        spkiSHA256: String? = nil
    ) {
        self.name = name
        self.host = host
        self.port = port
        self.md5Fingerprint = md5Fingerprint
        self.countryCode = countryCode
        self.isCensoredZone = isCensoredZone
        self.spkiSHA256 = spkiSHA256
    }

    public var id: String { "\(host):\(port)" }

    public var displayCountryCode: String? {
        guard let countryCode, countryCode.count == 2 else { return nil }
        return countryCode.uppercased()
    }
}

public struct FPTNAccessToken: Equatable, Sendable {
    public let version: Int?
    public let serviceName: String?
    public let username: String
    public let password: String
    public let servers: [FPTNServer]

    public init(
        version: Int?,
        serviceName: String?,
        username: String,
        password: String,
        servers: [FPTNServer]
    ) {
        self.version = version
        self.serviceName = serviceName
        self.username = username
        self.password = password
        self.servers = servers
    }
}

public enum TokenError: Error, Equatable, LocalizedError {
    case emptyToken
    case invalidBase64
    case brotliDecompressionFailed
    case invalidJSON
    case missingUsername
    case missingPassword
    case noServers
    case invalidServerName(index: Int)
    case invalidServerHost(index: Int)
    case invalidServerPort(index: Int)

    public var errorDescription: String? {
        switch self {
        case .emptyToken: return "The access token is empty."
        case .invalidBase64: return "The access token is not valid Base64."
        case .brotliDecompressionFailed: return "The compressed access token could not be decompressed."
        case .invalidJSON: return "The access token does not contain valid JSON."
        case .missingUsername: return "The access token has no username."
        case .missingPassword: return "The access token has no password."
        case .noServers: return "The access token contains no servers."
        case let .invalidServerName(index): return "Server #\(index + 1) has an invalid name."
        case let .invalidServerHost(index): return "Server #\(index + 1) has an invalid host."
        case let .invalidServerPort(index): return "Server #\(index + 1) has an invalid port."
        }
    }
}

public enum TokenParser {
    /// Decodes `fptn:`, `fptn://` and `fptnb:` tokens. Tokens may be split
    /// across lines by chat applications, so all whitespace is removed first.
    public static func parse(_ raw: String) throws -> FPTNAccessToken {
        let compact = raw.filter { !$0.isWhitespace }
        guard !compact.isEmpty else { throw TokenError.emptyToken }

        let isBrotli = compact.hasPrefix("fptnb:")
        let payload: String
        if isBrotli {
            payload = String(compact.dropFirst("fptnb:".count))
        } else if compact.hasPrefix("fptn://") {
            payload = String(compact.dropFirst("fptn://".count))
        } else if compact.hasPrefix("fptn:") {
            payload = String(compact.dropFirst("fptn:".count))
        } else {
            payload = compact
        }

        let jsonData: Data
        if isBrotli {
            jsonData = try decodeBrotli(payload)
        } else {
            guard let bytes = Base64Codec.decode(payload) else { throw TokenError.invalidBase64 }
            jsonData = Data(bytes)
        }

        let wire: WireToken
        do {
            wire = try JSONDecoder().decode(WireToken.self, from: jsonData)
        } catch {
            throw TokenError.invalidJSON
        }

        let username = wire.username?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !username.isEmpty else { throw TokenError.missingUsername }
        let password = wire.password ?? ""
        guard !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw TokenError.missingPassword
        }

        var servers: [FPTNServer] = []
        servers.reserveCapacity((wire.servers?.count ?? 0) + (wire.censoredZoneServers?.count ?? 0))
        for (index, server) in (wire.servers ?? []).enumerated() {
            servers.append(try domainServer(server, index: index, censored: false))
        }
        for (index, server) in (wire.censoredZoneServers ?? []).enumerated() {
            servers.append(try domainServer(server, index: index, censored: true))
        }
        guard !servers.isEmpty else { throw TokenError.noServers }

        return FPTNAccessToken(
            version: wire.version,
            serviceName: wire.serviceName,
            username: username,
            password: password,
            servers: servers
        )
    }

    private static func decodeBrotli(_ payload: String) throws -> Data {
        guard let compressed = Base64Codec.decode(payload) else { throw TokenError.invalidBase64 }
        switch Brotli().decompress(Data(compressed), maximumDecompressedSize: 1 << 20) {
        case let .success(data):
            return data
        case .failure:
            throw TokenError.brotliDecompressionFailed
        }
    }

    private static func domainServer(
        _ server: WireServer,
        index: Int,
        censored: Bool
    ) throws -> FPTNServer {
        let name = server.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !name.isEmpty, name.count <= 100 else { throw TokenError.invalidServerName(index: index) }
        let host = server.host?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !host.isEmpty else { throw TokenError.invalidServerHost(index: index) }
        guard let port = server.port, (1...65535).contains(port) else {
            throw TokenError.invalidServerPort(index: index)
        }
        return FPTNServer(
            name: name,
            host: host,
            port: UInt16(port),
            md5Fingerprint: server.md5Fingerprint?.lowercased(),
            countryCode: server.countryCode,
            isCensoredZone: censored,
            spkiSHA256: server.spkiSHA256?.lowercased()
        )
    }
}

// MARK: - Wire model

private struct WireToken: Decodable {
    let version: Int?
    let serviceName: String?
    let username: String?
    let password: String?
    let servers: [WireServer]?
    let censoredZoneServers: [WireServer]?

    enum CodingKeys: String, CodingKey {
        case version
        case serviceName = "service_name"
        case username
        case password
        case servers
        case censoredZoneServers = "censored_zone_servers"
    }
}

private struct WireServer: Decodable {
    let name: String?
    let host: String?
    let port: Int?
    let md5Fingerprint: String?
    let spkiSHA256: String?
    let countryCode: String?

    enum CodingKeys: String, CodingKey {
        case name
        case host
        case port
        case md5Fingerprint = "md5_fingerprint"
        case spkiSHA256 = "spki_sha256"
        case countryCode = "country_code"
    }
}

// MARK: - Base64

public enum Base64Codec {
    public static func decode(_ value: String) -> [UInt8]? {
        guard !value.isEmpty else { return nil }
        var normalized = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: normalized) else { return nil }
        return [UInt8](data)
    }

    public static func encode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
    }
}
