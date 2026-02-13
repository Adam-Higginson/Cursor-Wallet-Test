// CredentialResponse.swift
// Model for the OID4VCI Credential Endpoint response (§8).
//
// The wallet requests a credential using the access token obtained
// from the token endpoint. The response contains the issued credential.

import Foundation

/// Response from the credential endpoint containing the issued credential.
public struct CredentialResponse: Sendable, Equatable, Decodable {

    /// The issued credential. For mso_mdoc format this is a base64url-encoded
    /// CBOR byte string containing the IssuerSigned structure.
    public let credential: String?

    /// Transaction ID for deferred issuance (not used in immediate flow).
    public let transactionId: String?

    /// A fresh nonce for subsequent requests.
    public let cNonce: String?

    /// Lifetime of the c_nonce in seconds.
    public let cNonceExpiresIn: Int?

    private enum CodingKeys: String, CodingKey {
        case credential
        case transactionId = "transaction_id"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
    }

    public init(
        credential: String? = nil,
        transactionId: String? = nil,
        cNonce: String? = nil,
        cNonceExpiresIn: Int? = nil
    ) {
        self.credential = credential
        self.transactionId = transactionId
        self.cNonce = cNonce
        self.cNonceExpiresIn = cNonceExpiresIn
    }
}
