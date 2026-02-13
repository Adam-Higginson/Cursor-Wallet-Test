// TokenResponse.swift
// Model for the OAuth 2.0 Token Endpoint response (OID4VCI §6).
//
// The wallet exchanges a pre-authorized code for an access token
// at the authorization server's token endpoint.

import Foundation

/// Response from the token endpoint after exchanging a pre-authorized code.
public struct TokenResponse: Sendable, Equatable, Decodable {

    /// The access token to use for the credential request.
    public let accessToken: String

    /// Token type (typically "Bearer").
    public let tokenType: String?

    /// Number of seconds until the token expires.
    public let expiresIn: Int?

    /// A nonce to use in the credential request proof, if required.
    public let cNonce: String?

    /// Lifetime of the c_nonce in seconds.
    public let cNonceExpiresIn: Int?

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
    }

    public init(
        accessToken: String,
        tokenType: String? = nil,
        expiresIn: Int? = nil,
        cNonce: String? = nil,
        cNonceExpiresIn: Int? = nil
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.cNonce = cNonce
        self.cNonceExpiresIn = cNonceExpiresIn
    }
}
