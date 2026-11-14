import Foundation

/// A parsed X.509 certificate. Only the fields needed for TLS server-chain
/// validation are decoded; unknown extensions are ignored unless critical and
/// unrecognised (which fails closed, see `CertificateChainPolicy`).
public struct X509Certificate: Equatable, Sendable {
    public let der: [UInt8]
    /// The exact `tbsCertificate` bytes covered by `signature`.
    public let tbsDER: [UInt8]
    public let signatureAlgorithmOID: String
    public let signature: [UInt8]
    public let issuerDER: [UInt8]
    public let subjectDER: [UInt8]
    public let commonName: String?
    public let notBefore: Date
    public let notAfter: Date
    public let subjectPublicKeyInfoDER: [UInt8]
    public let publicKeyAlgorithmOID: String
    public let publicKeyCurveOID: String?
    public let publicKeyBytes: [UInt8]
    public let dnsNames: [String]
    public let isCA: Bool
    public let keyUsageBits: UInt16
    public let extendedKeyUsages: [String]
    public let extensionOIDs: [String]

    public init(der: [UInt8]) throws {
        self.der = der
        let top = try DER.parse(der).requireTag(0x30)
        let fields = try top.children
        guard fields.count == 3 else { throw DERError.truncated }

        let tbs = try fields[0].requireTag(0x30)
        tbsDER = tbs.encoded
        let algorithm = try fields[1].requireTag(0x30)
        guard let algorithmOID = try algorithm.children.first else {
            throw DERError.truncated
        }
        signatureAlgorithmOID = try algorithmOID.objectIdentifier
        signature = try fields[2].bitStringBytes

        let tbsFields = try tbs.children
        var index = 0
        if tbsFields.first?.tag == 0xa0 { index += 1 }  // [0] EXPLICIT version
        guard tbsFields.count >= index + 6 else { throw DERError.truncated }
        index += 1  // serialNumber
        index += 1  // signature AlgorithmIdentifier (matches outer algorithm)
        issuerDER = tbsFields[index].encoded
        index += 1
        let validity = try tbsFields[index].requireTag(0x30).children
        guard validity.count == 2 else { throw DERError.truncated }
        notBefore = try validity[0].dateValue
        notAfter = try validity[1].dateValue
        index += 1
        subjectDER = tbsFields[index].encoded
        commonName = try Self.findCommonName(in: tbsFields[index])
        index += 1
        let spki = try tbsFields[index].requireTag(0x30)
        subjectPublicKeyInfoDER = spki.encoded
        let spkiFields = try spki.children
        guard spkiFields.count == 2 else { throw DERError.truncated }
        let keyAlgorithm = try spkiFields[0].requireTag(0x30).children
        guard let keyOID = keyAlgorithm.first else { throw DERError.truncated }
        publicKeyAlgorithmOID = try keyOID.objectIdentifier
        publicKeyCurveOID = keyAlgorithm.count > 1
            ? try? keyAlgorithm[1].objectIdentifier
            : nil
        publicKeyBytes = try spkiFields[1].bitStringBytes
        index += 1

        var parsedDNSNames: [String] = []
        var parsedIsCA = false
        var parsedKeyUsage: UInt16 = 0
        var parsedEKUs: [String] = []
        var parsedExtensionOIDs: [String] = []
        if let extensionsField = tbsFields[safe: index], extensionsField.tag == 0xa3 {
            let sequence = try DER.parse(extensionsField.content)
            for extensionElement in try sequence.children {
                let parts = try extensionElement.children
                guard let oidElement = parts.first else { throw DERError.truncated }
                let oid = try oidElement.objectIdentifier
                parsedExtensionOIDs.append(oid)
                guard let valueElement = parts.last, valueElement.tag == 0x04 else {
                    throw DERError.unexpectedTag(expected: 0x04, actual: parts.last?.tag ?? 0)
                }
                switch oid {
                case X509OID.subjectAltName:
                    let names = try DER.parse(valueElement.content).children
                    parsedDNSNames = names
                        .filter { $0.tag == 0x82 }
                        .compactMap { try? $0.text }
                case X509OID.basicConstraints:
                    let body = try DER.parse(valueElement.content).children
                    if let first = body.first, first.tag == 0x01 {
                        parsedIsCA = try first.booleanValue
                    }
                case X509OID.keyUsage:
                    let bytes = try DER.parse(valueElement.content).bitStringBytes
                    if let first = bytes.first {
                        parsedKeyUsage = UInt16(first) << 8
                        if bytes.count > 1 { parsedKeyUsage |= UInt16(bytes[1]) }
                    }
                case X509OID.extKeyUsage:
                    parsedEKUs = try DER.parse(valueElement.content).children
                        .compactMap { try? $0.objectIdentifier }
                default:
                    break
                }
            }
        }
        dnsNames = parsedDNSNames
        isCA = parsedIsCA
        keyUsageBits = parsedKeyUsage
        extendedKeyUsages = parsedEKUs
        extensionOIDs = parsedExtensionOIDs
    }

    public func isValid(at now: Date) -> Bool {
        now >= notBefore && now <= notAfter
    }

    public var canSignCertificates: Bool {
        // bit 5 (keyCertSign) of the BIT STRING, counting from the MSB.
        keyUsageBits == 0 || (keyUsageBits & (1 << 10)) != 0
    }

    public var supportsServerAuthentication: Bool {
        extendedKeyUsages.isEmpty
            || extendedKeyUsages.contains(X509OID.serverAuth)
            || extendedKeyUsages.contains(X509OID.anyExtendedKeyUsage)
    }

    private static func findCommonName(in name: DERElement) throws -> String? {
        guard name.tag == 0x30 else { return nil }
        for rdn in try name.children where rdn.tag == 0x31 {
            for attribute in try rdn.children where attribute.tag == 0x30 {
                let parts = try attribute.children
                guard parts.count >= 2,
                      (try? parts[0].objectIdentifier) == X509OID.commonName else {
                    continue
                }
                return try? parts[1].text
            }
        }
        return nil
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
