// IssuerMetadata.swift
// Model for OID4VCI Credential Issuer Metadata (§12.2).
//
// Fetched from: {credential_issuer}/.well-known/openid-credential-issuer
//
// We decode only the subset of fields needed for the pre-authorized code flow.

import Foundation

// MARK: - IssuerMetadata

/// Subset of the OID4VCI Credential Issuer Metadata needed for issuance.
public struct IssuerMetadata: Sendable, Equatable, Decodable {

    /// The credential issuer URL (must match the offer's credential_issuer).
    public let credentialIssuer: String

    /// URL of the credential endpoint.
    public let credentialEndpoint: String

    /// Authorization server URLs. If absent, the issuer itself acts as the AS.
    public let authorizationServers: [String]?

    /// Supported credential configurations, keyed by configuration ID.
    public let credentialConfigurationsSupported: [String: CredentialConfiguration]?

    private enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case credentialConfigurationsSupported = "credential_configurations_supported"
    }

    public init(
        credentialIssuer: String,
        credentialEndpoint: String,
        authorizationServers: [String]? = nil,
        credentialConfigurationsSupported: [String: CredentialConfiguration]? = nil
    ) {
        self.credentialIssuer = credentialIssuer
        self.credentialEndpoint = credentialEndpoint
        self.authorizationServers = authorizationServers
        self.credentialConfigurationsSupported = credentialConfigurationsSupported
    }
}

// MARK: - CredentialConfiguration

/// A single credential configuration from the issuer metadata.
public struct CredentialConfiguration: Sendable, Equatable, Decodable {

    /// The credential format (e.g. "mso_mdoc", "vc+sd-jwt").
    public let format: String

    /// The doctype for mdoc format (e.g. "org.iso.18013.5.1.mDL").
    public let doctype: String?

    public init(format: String, doctype: String? = nil) {
        self.format = format
        self.doctype = doctype
    }
}

// MARK: - Authorization Server Metadata

/// Subset of OAuth 2.0 Authorization Server Metadata needed to find the token endpoint.
/// Fetched from: {authorization_server}/.well-known/oauth-authorization-server
/// or {issuer}/.well-known/openid-configuration
public struct AuthorizationServerMetadata: Sendable, Equatable, Decodable {

    /// The token endpoint URL.
    public let tokenEndpoint: String

    private enum CodingKeys: String, CodingKey {
        case tokenEndpoint = "token_endpoint"
    }

    public init(tokenEndpoint: String) {
        self.tokenEndpoint = tokenEndpoint
    }
}
