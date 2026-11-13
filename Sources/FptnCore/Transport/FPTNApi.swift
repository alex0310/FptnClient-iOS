import Foundation

public struct FPTNDNSSettings: Equatable, Sendable {
    public let dns: String
    public let dnsIPv6: String?

    public init(dns: String, dnsIPv6: String? = nil) {
        self.dns = dns
        self.dnsIPv6 = dnsIPv6
    }
}

public struct FPTNAPIConfiguration: Equatable, Sendable {
    public let clientAgent: String

    public init(clientAgent: String = "FptnClient(iOS/1.0.0)") {
        self.clientAgent = clientAgent
    }
}

public enum FPTNAPIError: Error, Equatable, LocalizedError {
    case httpStatus(Int, String)
    case invalidJSON
    case missingAccessToken
    case missingDNS
    case emptyUsername
    case emptyPassword

    public var errorDescription: String? {
        switch self {
        case let .httpStatus(status, body): return "FPTN API returned HTTP \(status): \(body)"
        case .invalidJSON: return "FPTN API returned invalid JSON."
        case .missingAccessToken: return "The login response has no access_token."
        case .missingDNS: return "The DNS response has no dns field."
        case .emptyUsername: return "The username is empty."
        case .emptyPassword: return "The password is empty."
        }
    }
}

/// FPTN control-plane API. The transport closure is injected so the API can be
/// tested without a network and so production code can choose plain,
/// obfuscated, or reality TLS per server.
public final class FPTNAPIClient {
    public typealias Transport = (HTTPRequest, FPTNServer) throws -> HTTPResponse

    public let configuration: FPTNAPIConfiguration
    private let transport: Transport

    public init(
        configuration: FPTNAPIConfiguration = FPTNAPIConfiguration(),
        transport: @escaping Transport
    ) {
        self.configuration = configuration
        self.transport = transport
    }

    public func login(
        server: FPTNServer,
        username: String,
        password: String
    ) throws -> String {
        guard !username.isEmpty else { throw FPTNAPIError.emptyUsername }
        guard !password.isEmpty else { throw FPTNAPIError.emptyPassword }
        let payload: [String: String] = ["username": username, "password": password]
        let body = try JSONSerialization.data(withJSONObject: payload, options: [])
        let request = HTTPRequest(
            method: "POST",
            target: "/api/v1/login",
            headers: headers(
                server: server,
                extra: [
                    HTTPHeader(name: "Content-Type", value: "application/json"),
                    HTTPHeader(name: "Connection", value: "close")
                ]
            ),
            body: [UInt8](body)
        )
        let response = try transport(request, server)
        try ensureSuccess(response)
        guard let token = try stringField("access_token", in: response) else {
            throw FPTNAPIError.missingAccessToken
        }
        return token
    }

    public func dns(server: FPTNServer, token: String) throws -> FPTNDNSSettings {
        let request = HTTPRequest(
            method: "GET",
            target: "/api/v1/dns",
            headers: headers(
                server: server,
                extra: [
                    HTTPHeader(name: "Authorization", value: "Bearer \(token)"),
                    HTTPHeader(name: "Connection", value: "close")
                ]
            )
        )
        let response = try transport(request, server)
        try ensureSuccess(response)
        guard let dns = try stringField("dns", in: response), !dns.isEmpty else {
            throw FPTNAPIError.missingDNS
        }
        let dnsIPv6 = try stringField("dns_ipv6", in: response)
        return FPTNDNSSettings(dns: dns, dnsIPv6: dnsIPv6)
    }

    // MARK: - Helpers

    private func headers(server: FPTNServer, extra: [HTTPHeader]) -> [HTTPHeader] {
        [
            HTTPHeader(name: "Host", value: "\(server.host):\(server.port)"),
            HTTPHeader(name: "Client-Agent", value: configuration.clientAgent)
        ] + BrowserHeaders.make() + extra
    }

    private func ensureSuccess(_ response: HTTPResponse) throws {
        guard response.statusCode == 200 else {
            throw FPTNAPIError.httpStatus(
                response.statusCode,
                response.text ?? ""
            )
        }
    }

    private func stringField(_ key: String, in response: HTTPResponse) throws -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(response.body)) else {
            throw FPTNAPIError.invalidJSON
        }
        guard let dictionary = object as? [String: Any] else {
            throw FPTNAPIError.invalidJSON
        }
        return dictionary[key] as? String
    }
}
