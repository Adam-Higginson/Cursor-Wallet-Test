// CredentialResponse.swift
// Model for the OID4VCI Credential Endpoint response (§8).
//
// The wallet requests a credential using the access token obtained
// from the token endpoint. The response contains the issued credential.
// Supports both top-level "credential" and "credentials" array (e.g. CRI).

import Foundation

/// One credential in a credentials array (issuer may return multiple).
private struct CredentialItem: Sendable, Equatable, Decodable {
    let credential: String
}

/// Response from the credential endpoint containing the issued credential(s).
public struct CredentialResponse: Sendable, Equatable, Decodable {

    /// Single credential (when issuer uses top-level "credential").
    private let credentialValue: String?

    /// Multiple credentials (when issuer uses "credentials" array, e.g. CRI).
    private let credentialsArray: [CredentialItem]?

    /// Transaction ID for deferred issuance (not used in immediate flow).
    public let transactionId: String?

    /// A fresh nonce for subsequent requests.
    public let cNonce: String?

    /// Lifetime of the c_nonce in seconds.
    public let cNonceExpiresIn: Int?

    /// Notification ID (e.g. CRI).
    public let notificationId: String?

    /// The issued credential to use. For mso_mdoc format this is a base64url-encoded
    /// CBOR byte string. Resolved from top-level "credential" or first item in "credentials".
    public var credential: String? {
        credentialValue ?? credentialsArray?.first?.credential
    }

    private enum CodingKeys: String, CodingKey {
        case credentialValue = "credential"
        case credentialsArray = "credentials"
        case transactionId = "transaction_id"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
        case notificationId = "notification_id"
    }

    public init(
        credential: String? = nil,
        transactionId: String? = nil,
        cNonce: String? = nil,
        cNonceExpiresIn: Int? = nil,
        notificationId: String? = nil
    ) {
        self.credentialValue = credential
        self.credentialsArray = nil
        self.transactionId = transactionId
        self.cNonce = cNonce
        self.cNonceExpiresIn = cNonceExpiresIn
        self.notificationId = notificationId
    }
}
