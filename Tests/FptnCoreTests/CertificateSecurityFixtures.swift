import Foundation
import XCTest
import _CryptoExtras

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@testable import FptnCore

/// Builds signed CRL / OCSP / SCT fixtures with the throwaway test CA key.
enum CertificateSecurityFixtures {
    static func rootPrivateKey() throws -> _RSA.Signing.PrivateKey {
        try _RSA.Signing.PrivateKey(
            pemRepresentation: CertificateFixtures.pem("rsa-root-key")
        )
    }

    static func crl(
        issuer: X509Certificate,
        revokedSerials: [[UInt8]],
        thisUpdate: Date,
        nextUpdate: Date? = nil
    ) throws -> [UInt8] {
        var parts: [[UInt8]] = [
            DERTestBuilder.integer([0x01]),
            DERTestBuilder.algorithmIdentifier(DERTestBuilder.sha256WithRSAOID),
            issuer.subjectDER,
            DERTestBuilder.utc(thisUpdate)
        ]
        if let nextUpdate {
            parts.append(DERTestBuilder.utc(nextUpdate))
        }
        if !revokedSerials.isEmpty {
            let entries = revokedSerials.map { serial in
                DERTestBuilder.sequence([
                    DERTestBuilder.integer(serial),
                    DERTestBuilder.utc(thisUpdate)
                ])
            }
            parts.append(DERTestBuilder.sequence(entries))
        }
        let tbs = DERTestBuilder.sequence(parts)
        let signature = try rootPrivateKey().signature(
            for: SHA256.hash(data: Data(tbs)),
            padding: .insecurePKCS1v1_5
        )
        return DERTestBuilder.sequence([
            tbs,
            DERTestBuilder.algorithmIdentifier(DERTestBuilder.sha256WithRSAOID),
            DERTestBuilder.bitString(Array(signature.rawRepresentation))
        ])
    }

    static func ocsp(
        issuer: X509Certificate,
        serialNumber: [UInt8],
        statusTag: UInt8,
        thisUpdate: Date,
        nextUpdate: Date? = nil,
        producedAt: Date? = nil
    ) throws -> [UInt8] {
        let certID = DERTestBuilder.sequence([
            DERTestBuilder.algorithmIdentifier(DERTestBuilder.sha256OID),
            DERTestBuilder.octetString([UInt8](repeating: 0xaa, count: 32)),
            DERTestBuilder.octetString([UInt8](repeating: 0xbb, count: 32)),
            DERTestBuilder.integer(serialNumber)
        ])
        var singleParts: [[UInt8]] = [
            certID,
            DERTestBuilder.context(statusTag, []),
            DERTestBuilder.generalized(thisUpdate)
        ]
        if let nextUpdate {
            singleParts.append(
                DERTestBuilder.contextElements(0xa0, [DERTestBuilder.generalized(nextUpdate)])
            )
        }
        let responseData = DERTestBuilder.sequence([
            DERTestBuilder.contextElements(0xa1, [issuer.subjectDER]),
            DERTestBuilder.generalized(producedAt ?? thisUpdate),
            DERTestBuilder.sequence([DERTestBuilder.sequence(singleParts)])
        ])
        let signature = try rootPrivateKey().signature(
            for: SHA256.hash(data: Data(responseData)),
            padding: .insecurePKCS1v1_5
        )
        let basic = DERTestBuilder.sequence([
            responseData,
            DERTestBuilder.algorithmIdentifier(DERTestBuilder.sha256WithRSAOID),
            DERTestBuilder.bitString(Array(signature.rawRepresentation))
        ])
        let responseBytes = DERTestBuilder.contextElements(0xa0, [
            DERTestBuilder.oid(DERTestBuilder.basicOCSPResponseOID),
            DERTestBuilder.octetString(basic)
        ])
        return DERTestBuilder.sequence([
            DERTestBuilder.enumerated(0),
            responseBytes
        ])
    }

    static func sctList(
        certificateDER: [UInt8],
        logID: [UInt8],
        timestamp: UInt64,
        key: P256.Signing.PrivateKey,
        signatureAlgorithm: UInt8 = 3
    ) throws -> [UInt8] {
        let hashAlgorithm: UInt8 = 4  // SHA-256
        let extensions: [UInt8] = []
        let unsigned = SignedCertificateTimestamp(
            version: 0,
            logID: logID,
            timestamp: timestamp,
            extensions: extensions,
            hashAlgorithm: hashAlgorithm,
            signatureAlgorithm: signatureAlgorithm,
            signature: []
        )
        let signedData = SCTList.signedData(
            for: unsigned,
            certificateDER: certificateDER
        )
        let signature = try key.signature(for: SHA256.hash(data: Data(signedData)))

        var sct: [UInt8] = [0x00] + logID
        for shift in stride(from: 56, through: 0, by: -8) {
            sct.append(UInt8((timestamp >> UInt64(shift)) & 0xff))
        }
        sct += [UInt8((extensions.count >> 8) & 0xff), UInt8(extensions.count & 0xff)]
        sct += extensions
        sct += [hashAlgorithm, signatureAlgorithm]
        let der = [UInt8](signature.derRepresentation)
        sct += [UInt8((der.count >> 8) & 0xff), UInt8(der.count & 0xff)]
        sct += der

        let serialized: [UInt8] = [
            UInt8((sct.count >> 8) & 0xff),
            UInt8(sct.count & 0xff)
        ] + sct
        return [
            UInt8((serialized.count >> 8) & 0xff),
            UInt8(serialized.count & 0xff)
        ] + serialized
    }
}
