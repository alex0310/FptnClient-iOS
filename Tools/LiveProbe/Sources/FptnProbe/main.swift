import Foundation
import FptnCore

private let clientAgent = "FptnProbe/1.0"
private let connectTimeout: TimeInterval = 15
private let readTimeout: TimeInterval = 15

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

private func requestedMode() -> FPTNSecurityMode? {
    guard let raw = ProcessInfo.processInfo.environment["FPTN_LIVE_MODE"] else {
        return nil
    }
    guard let mode = FPTNSecurityMode(rawValue: raw) else {
        fail("FPTN_LIVE_MODE must be plain, obfuscated or reality")
    }
    return mode
}

private func makeAPI(mode: FPTNSecurityMode) -> FPTNAPIClient {
    FPTNAPIClient(
        configuration: FPTNAPIConfiguration(clientAgent: clientAgent),
        transport: FPTNAPITransport.transport(
            securityMode: mode,
            connectTimeout: connectTimeout,
            readTimeout: readTimeout
        )
    )
}

private func makeDNSQuery(id: UInt16, name: String) -> [UInt8] {
    var bytes: [UInt8] = []
    func u16(_ value: UInt16) {
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }
    u16(id)
    u16(0x0100)  // recursion desired
    u16(1)       // QDCOUNT
    u16(0)       // ANCOUNT
    u16(0)       // NSCOUNT
    u16(0)       // ARCOUNT
    for label in name.split(separator: ".") {
        bytes.append(UInt8(label.utf8.count))
        bytes.append(contentsOf: label.utf8)
    }
    bytes.append(0)
    u16(1)  // A
    u16(1)  // IN
    return bytes
}

private func makeDNSPacket(
    destination: IPAddress,
    query: [UInt8],
    sourcePort: UInt16 = 40_000
) -> [UInt8]? {
    guard case let .ipv4(destinationValue) = destination else { return nil }
    let udpLength = 8 + query.count
    let totalLength = 20 + udpLength
    guard totalLength <= Int(UInt16.max) else { return nil }
    var packet = [UInt8](repeating: 0, count: totalLength)
    packet[0] = 0x45
    packet[2] = UInt8((totalLength >> 8) & 0xff)
    packet[3] = UInt8(totalLength & 0xff)
    packet[8] = 64
    packet[9] = IPPacket.protocolUDP
    packet[12] = 0
    packet[13] = 0
    packet[14] = 0
    packet[15] = 0
    packet[16] = UInt8((destinationValue >> 24) & 0xff)
    packet[17] = UInt8((destinationValue >> 16) & 0xff)
    packet[18] = UInt8((destinationValue >> 8) & 0xff)
    packet[19] = UInt8(destinationValue & 0xff)
    packet[20] = UInt8((sourcePort >> 8) & 0xff)
    packet[21] = UInt8(sourcePort & 0xff)
    packet[22] = 0
    packet[23] = 53
    packet[24] = UInt8((udpLength >> 8) & 0xff)
    packet[25] = UInt8(udpLength & 0xff)
    packet.replaceSubrange(28..<packet.count, with: query)
    IPPacket.recalculateChecksums(&packet)
    return packet
}

private func udpPayload(from packet: [UInt8]) -> [UInt8]? {
    guard packet.count >= 28, packet[0] >> 4 == 4, packet[9] == IPPacket.protocolUDP else {
        return nil
    }
    let headerLength = Int(packet[0] & 0x0f) * 4
    guard headerLength >= 20, packet.count >= headerLength + 8 else { return nil }
    let udpLength = (Int(packet[headerLength + 4]) << 8) | Int(packet[headerLength + 5])
    guard udpLength >= 8, packet.count >= headerLength + udpLength else { return nil }
    let sourcePort = (UInt16(packet[headerLength]) << 8) | UInt16(packet[headerLength + 1])
    guard sourcePort == 53 else { return nil }
    return Array(packet[(headerLength + 8)..<(headerLength + udpLength)])
}

private func dnsAnswerCount(_ response: [UInt8]) -> Int? {
    guard response.count >= 12 else { return nil }
    return (Int(response[6]) << 8) | Int(response[7])
}

private func runDNSProbe(tunnel: FPTNTunnel, dns: FPTNDNSSettings) {
    guard let dnsAddress = IPAddress(dns.dns) else {
        print("dns: cannot parse \(dns.dns)")
        return
    }
    let queryID: UInt16 = 0x4a7b
    let query = makeDNSQuery(id: queryID, name: "example.com")
    guard let packet = makeDNSPacket(destination: dnsAddress, query: query) else {
        print("dns: cannot build IPv4 packet for \(dns.dns)")
        return
    }
    do {
        let sent = try tunnel.send(packets: [packet])
        print("dns: sent \(sent) packet(s) to \(dns.dns)")
        try tunnel.webSocket.connection.setReadTimeout(5)
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            do {
                let packets = try tunnel.receivePackets()
                for response in packets {
                    guard let payload = udpPayload(from: response) else { continue }
                    if payload.count >= 2 {
                        let id = (UInt16(payload[0]) << 8) | UInt16(payload[1])
                        if id == queryID {
                            print("dns: got response, answers=\(dnsAnswerCount(payload) ?? -1)")
                            return
                        }
                    }
                }
            } catch {
                print("dns: receive failed: \(error)")
                return
            }
        }
        print("dns: no matching response before deadline")
    } catch {
        print("dns: send failed: \(error)")
    }
}

private func runClientProbe(
    token: FPTNAccessToken,
    requestedMode: FPTNSecurityMode?
) {
    let mode = requestedMode ?? .obfuscated
    var now = ProcessInfo.processInfo.systemUptime
    let client = FPTNClient(
        accessToken: token,
        configuration: FPTNClientConfiguration(
            pool: TunnelPoolConfiguration(
                strategy: .dual,
                lifetime: 600,
                replacementLead: 60
            ),
            securityMode: mode,
            clientAgent: clientAgent,
            connectTimeout: connectTimeout,
            loginTimeout: connectTimeout,
            handshakeTimeout: connectTimeout
        ),
        clock: { now }
    )
    do {
        let dns = try client.start()
        print(
            "client: state=\(client.state) "
                + "server=\(client.selectedServer?.host ?? "-") "
                + "dns=\(dns?.dns ?? "-") "
                + "slots=\(client.pool?.activeSlots.count ?? -1)"
        )
        now += 16
        _ = client.maintain()
        let slots = client.pool?.activeSlots ?? []
        print("client: after maintain slots=\(slots.count)")
        for slot in slots {
            print(
                "client: slot=\(slot.id) ipv4=\(slot.assignedIPv4?.text ?? "-") "
                    + "ipv6=\(slot.assignedIPv6?.text ?? "-")"
            )
        }
        if let dns, let tunnel = slots.first?.tunnel as? FPTNTunnel {
            runDNSProbe(tunnel: tunnel, dns: dns)
        }
        client.stop()
        print("client: stopped")
    } catch {
        print("client: failed: \(error)")
        exit(1)
    }
}

private func main() {
    let environment = ProcessInfo.processInfo.environment
    let rawToken: String
    if let path = environment["FPTN_LIVE_TOKEN_FILE"] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            fail("cannot read FPTN_LIVE_TOKEN_FILE")
        }
        rawToken = contents
    } else if let value = environment["FPTN_LIVE_TOKEN"] {
        rawToken = value
    } else {
        fail("set FPTN_LIVE_TOKEN or FPTN_LIVE_TOKEN_FILE")
    }
    guard !rawToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        fail("the live token is empty")
    }

    let token: FPTNAccessToken
    do {
        token = try TokenParser.parse(rawToken)
    } catch {
        fail("token parse failed: \(error)")
    }

    print("token: service=\(token.serviceName ?? "-") servers=\(token.servers.count)")
    for server in token.servers {
        print(
            "server: \(server.name) \(server.host):\(server.port) "
                + "censored=\(server.isCensoredZone) country=\(server.displayCountryCode ?? "-")"
        )
    }

    let requested = requestedMode()
    let serverFilter = ProcessInfo.processInfo.environment["FPTN_LIVE_SERVER"]
    if ProcessInfo.processInfo.environment["FPTN_LIVE_CLIENT"] == "1" {
        var clientToken = token
        if let serverFilter {
            let filtered = token.servers.filter {
                $0.name == serverFilter || $0.host == serverFilter
            }
            guard !filtered.isEmpty else {
                fail("FPTN_LIVE_SERVER did not match a token server")
            }
            clientToken = FPTNAccessToken(
                version: token.version,
                serviceName: token.serviceName,
                username: token.username,
                password: token.password,
                servers: filtered
            )
        }
        runClientProbe(token: clientToken, requestedMode: requested)
        return
    }
    for server in token.servers {
        if let serverFilter,
           server.name != serverFilter,
           server.host != serverFilter {
            continue
        }
        let mode = requested ?? (server.isCensoredZone ? .reality : .obfuscated)
        print("trying \(server.host):\(server.port) mode=\(mode.rawValue)")
        do {
            let api = makeAPI(mode: mode)
            let jwt = try api.login(
                server: server,
                username: token.username,
                password: token.password
            )
            print("login: ok")
            let dns = try api.dns(server: server, token: jwt)
            print("dns: \(dns.dns) ipv6=\(dns.dnsIPv6 ?? "-")")

            let tunnel = try FPTNTunnelFactory.connect(
                server: server,
                token: jwt,
                securityMode: mode,
                configuration: FPTNTunnelConfiguration(
                    clientAgent: clientAgent,
                    handshakeTimeout: connectTimeout,
                    pollTimeout: 1,
                    keepaliveIdle: 60,
                    connectionLifetime: nil
                ),
                connectTimeout: connectTimeout,
                clientAgent: clientAgent,
                sessionID: TunnelPool.randomSessionID()
            )
            print(
                "tunnel: ok ipv4=\(tunnel.assignedIPv4?.text ?? "-") "
                    + "ipv6=\(tunnel.assignedIPv6?.text ?? "-")"
            )
            runDNSProbe(tunnel: tunnel, dns: dns)
            tunnel.close()
            return
        } catch {
            print("failed: \(error)")
        }
    }
    fail("no server completed login and tunnel handshake")
}

main()
