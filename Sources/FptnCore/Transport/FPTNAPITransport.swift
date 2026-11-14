import Foundation

/// Production control-plane transport: a fresh TLS connection per API request.
/// The login and DNS endpoints are HTTP/1.1 and are closed after each response,
/// which matches the server's `Connection: close` handling.
public enum FPTNAPITransport {
    public static func transport(
        securityMode: FPTNSecurityMode = .plain,
        connectTimeout: TimeInterval = 10,
        readTimeout: TimeInterval = 10,
        certificatePolicy: CertificateValidationPolicy? = nil
    ) -> FPTNAPIClient.Transport {
        { request, server in
            let socket = try POSIXSocket.connect(
                host: server.host,
                port: server.port,
                timeout: connectTimeout
            )
            let tls = try TLSConnection(
                transport: socket,
                configuration: TLSConnectionConfiguration(
                    serverName: server.host,
                    expectedCertificateMD5: server.md5Fingerprint,
                    certificatePolicy: certificatePolicy,
                    securityMode: securityMode,
                    handshakeTimeout: connectTimeout,
                    readTimeout: readTimeout,
                    writeTimeout: readTimeout
                )
            )
            do {
                try tls.connect()
                let response = try HTTPClient.perform(request, over: tls)
                tls.close()
                return response
            } catch {
                tls.close()
                throw error
            }
        }
    }
}
