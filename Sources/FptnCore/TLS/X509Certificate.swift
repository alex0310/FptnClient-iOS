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
    /// Raw INTEGER content of the serial number (used by CRL/OCSP).
    public let serialNumber: [UInt8]
    /// CRL distribution point URIs (extension 2.5.29.31).
    public let crlDistributionPoints: [String]
    /// OCSP responder URIs (Authority Information Access).
    public let ocspURLs: [String]
    /// TLS-encoded SCT list embedded in the certificate, if present.
    public let embeddedSCTList: [UInt8]?

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
        serialNumber = try tbsFields[index].requireTag(0x02).content
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
        var parsedCRLDPs: [String] = []
        var parsedOCSPURLs: [String] = []
        var parsedSCTList: [UInt8]?
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
                case X509OID.crlDistributionPoints:
                    parsedCRLDPs = try Self.collectURIs(in: DER.parse(valueElement.content))
                case X509OID.authorityInfoAccess:
                    parsedOCSPURLs = try Self.ocspResponderURIs(
                        in: DER.parse(valueElement.content)
                    )
                case X509OID.signedCertificateTimestamp:
                    let inner = try DER.parse(valueElement.content)
                    if inner.tag == 0x04 { parsedSCTList = inner.content }
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
        crlDistributionPoints = parsedCRLDPs
        ocspURLs = parsedOCSPURLs
        embeddedSCTList = parsedSCTList
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

    /// Recursively collects `uniformResourceIdentifier` GeneralNames (0x86).
    private static func collectURIs(in element: DERElement) throws -> [String] {
        var result: [String] = []
        if element.tag == 0x86, let uri = try? element.text {
            result.append(uri)
        }
        if element.tag & 0x20 != 0 || element.tag == 0x30 || element.tag == 0x31 {
            for child in try element.children {
                result.append(contentsOf: try collectURIs(in: child))
            }
        }
        return result
    }

    private static func ocspResponderURIs(in element: DERElement) throws -> [String] {
        var result: [String] = []
        for description in try element.children {
            let parts = try description.children
            guard parts.count >= 2,
                  (try? parts[0].objectIdentifier) == X509OID.ocspAccessMethod else {
                continue
            }
            result.append(contentsOf: try collectURIs(in: parts[1]))
        }
        return result
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
