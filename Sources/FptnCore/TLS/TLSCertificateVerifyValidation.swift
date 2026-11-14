import Foundation

/// Validates the TLS 1.3 `CertificateVerify` message. Kept out of
/// `TLSClientSession` so the session file stays focused on state transitions.
public enum TLSCertificateVerifyValidation {
    public static func verify(
        message: TLSHandshakeMessage,
        policy: CertificateValidationPolicy,
        leaf: X509Certificate?,
        transcriptHash: [UInt8]?
    ) throws {
        var reader = ByteReader(message.body)
        let schemeRaw = try reader.readUInt16()
        let signature = try reader.readLengthPrefixed16()
        guard !signature.isEmpty, reader.isAtEnd else {
            throw TLSError.unexpectedMessage("malformed CertificateVerify")
        }
        switch policy {
        case .pinnedMD5:
            // Upstream FPTN behaviour: the MD5 pin plus TLS Finished are the
            // only authentication when strict X.509 validation is disabled.
            return
        case .strictChain, .systemTrust:
            break
        }
        guard let leaf,
              let hash = transcriptHash,
              let scheme = TLSSignatureScheme(rawValue: schemeRaw) else {
            throw TLSError.invalidState("missing data for CertificateVerify")
        }
        let signedContent = CertificateVerifyContext.signedContent(transcriptHash: hash)
        guard try CertificateSignature.verifyCertificateVerify(
            signature: signature,
            scheme: scheme,
            signedContent: signedContent,
            leaf: leaf
        ) else {
            throw TLSError.certificateVerifyMismatch
        }
    }
}
