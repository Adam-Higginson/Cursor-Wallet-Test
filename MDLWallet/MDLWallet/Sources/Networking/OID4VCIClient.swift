// OID4VCIClient.swift
// Orchestrates the OID4VCI pre-authorized code issuance flow.
//
// Flow:
//   1. Fetch issuer metadata from .well-known/openid-credential-issuer
//   2. Discover the token endpoint (from AS metadata or fallback)
//   3. Exchange pre-authorized code for an access token
//   4. Request the credential from the credential endpoint
//
// This client does NOT sign or verify anything — it handles the HTTP
// transport and JSON parsing for the OID4VCI protocol.

import Foundation

// MARK: - Errors

/// Errors during the OID4VCI issuance flow.
public enum OID4VCIError: Error, Sendable {
    /// The issuer metadata URL could not be constructed.
    case invalidIssuerURL(String)
    /// The issuer metadata response could not be decoded.
    case invalidIssuerMetadata(String)
    /// The token endpoint could not be determined from metadata.
    case tokenEndpointNotFound
    /// The token endpoint returned an error.
    case tokenRequestFailed(String)
    /// The credential endpoint returned an error.
    case credentialRequestFailed(String)
    /// The credential response did not contain a credential.
    case noCredentialInResponse
    /// The credential data could not be decoded from base64url.
    case invalidCredentialEncoding
}

// MARK: - OID4VCIClient

/// Client for the OID4VCI pre-authorized code issuance flow.
public struct OID4VCIClient: Sendable {
    private let httpClient: HTTPClient

    public init(httpClient: HTTPClient) {
        self.httpClient = httpClient
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Public — Full issuance flow
    // ═══════════════════════════════════════════════════════════════

    /// Runs the complete pre-authorized code issuance flow.
    ///
    /// - Parameter offer: A parsed credential offer from a QR code.
    /// - Returns: The raw credential bytes from the issuer.
    public func issueCredential(offer: CredentialOffer) async throws -> Data {
        guard let preAuthGrant = offer.grants?.preAuthorizedCode else {
            throw OID4VCIError.tokenRequestFailed("No pre-authorized code in offer")
        }

        // Step 1: Fetch issuer metadata
        let issuerMetadata = try await fetchIssuerMetadata(issuerURL: offer.credentialIssuer)

        // Step 2: Discover token endpoint
        let tokenEndpoint = try await discoverTokenEndpoint(issuerMetadata: issuerMetadata)

        // Step 3: Exchange pre-authorized code for access token
        let tokenResponse = try await exchangePreAuthorizedCode(
            tokenEndpoint: tokenEndpoint,
            preAuthorizedCode: preAuthGrant.preAuthorizedCode
        )

        // Step 4: Request credential
        let credentialData = try await requestCredential(
            credentialEndpoint: issuerMetadata.credentialEndpoint,
            accessToken: tokenResponse.accessToken,
            credentialConfigurationIds: offer.credentialConfigurationIds
        )

        return credentialData
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Step 1 — Fetch Issuer Metadata
    // ═══════════════════════════════════════════════════════════════

    /// Fetches the credential issuer metadata from the well-known endpoint.
    public func fetchIssuerMetadata(issuerURL: String) async throws -> IssuerMetadata {
        guard let baseURL = URL(string: issuerURL),
              let metadataURL = URL(string: "\(baseURL.absoluteString)/.well-known/openid-credential-issuer") else {
            throw OID4VCIError.invalidIssuerURL(issuerURL)
        }

        let (data, _) = try await httpClient.get(url: metadataURL)

        do {
            return try JSONDecoder().decode(IssuerMetadata.self, from: data)
        } catch {
            throw OID4VCIError.invalidIssuerMetadata(error.localizedDescription)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Step 2 — Discover Token Endpoint
    // ═══════════════════════════════════════════════════════════════

    /// Determines the token endpoint URL.
    ///
    /// Strategy:
    /// 1. If the issuer metadata has `authorization_servers`, fetch the first
    ///    server's `.well-known/oauth-authorization-server` metadata.
    /// 2. Otherwise, try `{issuer}/.well-known/openid-configuration`.
    /// 3. Fall back to `{issuer}/token`.
    public func discoverTokenEndpoint(issuerMetadata: IssuerMetadata) async throws -> URL {
        // Try authorization server metadata first
        if let servers = issuerMetadata.authorizationServers, let firstServer = servers.first {
            if let tokenURL = try? await fetchTokenEndpointFromAS(serverURL: firstServer) {
                return tokenURL
            }
        }

        // Try OpenID configuration on the issuer itself
        if let tokenURL = try? await fetchTokenEndpointFromAS(
            serverURL: issuerMetadata.credentialIssuer,
            wellKnownPath: "/.well-known/openid-configuration"
        ) {
            return tokenURL
        }

        // Fallback: {issuer}/token
        guard let fallback = URL(string: "\(issuerMetadata.credentialIssuer)/token") else {
            throw OID4VCIError.tokenEndpointNotFound
        }
        return fallback
    }

    private func fetchTokenEndpointFromAS(
        serverURL: String,
        wellKnownPath: String = "/.well-known/oauth-authorization-server"
    ) async throws -> URL {
        guard let url = URL(string: "\(serverURL)\(wellKnownPath)") else {
            throw OID4VCIError.tokenEndpointNotFound
        }
        let (data, _) = try await httpClient.get(url: url)
        let asMeta = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: data)
        guard let tokenURL = URL(string: asMeta.tokenEndpoint) else {
            throw OID4VCIError.tokenEndpointNotFound
        }
        return tokenURL
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Step 3 — Token Exchange
    // ═══════════════════════════════════════════════════════════════

    /// Exchanges a pre-authorized code for an access token.
    public func exchangePreAuthorizedCode(
        tokenEndpoint: URL,
        preAuthorizedCode: String
    ) async throws -> TokenResponse {
        let bodyString = [
            "grant_type=\(formEncode("urn:ietf:params:oauth:grant-type:pre-authorized_code"))",
            "pre-authorized_code=\(formEncode(preAuthorizedCode))"
        ].joined(separator: "&")

        let headers = ["Content-Type": "application/x-www-form-urlencoded"]
        let bodyData = bodyString.data(using: .utf8)

        let (data, _): (Data, HTTPURLResponse)
        do {
            (data, _) = try await httpClient.post(url: tokenEndpoint, headers: headers, body: bodyData)
        } catch {
            throw OID4VCIError.tokenRequestFailed(error.localizedDescription)
        }

        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OID4VCIError.tokenRequestFailed("Failed to decode token response: \(error.localizedDescription)")
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Step 4 — Credential Request
    // ═══════════════════════════════════════════════════════════════

    /// Requests a credential from the credential endpoint.
    public func requestCredential(
        credentialEndpoint: String,
        accessToken: String,
        credentialConfigurationIds: [String]
    ) async throws -> Data {
        guard let endpointURL = URL(string: credentialEndpoint) else {
            throw OID4VCIError.credentialRequestFailed("Invalid credential endpoint URL")
        }

        // Build the credential request body per OID4VCI §8.
        // Use the first credential_configuration_id from the offer.
        let configId = credentialConfigurationIds.first ?? "org.iso.18013.5.1.mDL"
        let requestBody: [String: Any] = [
            "credential_configuration_id": configId
        ]

        let bodyData = try JSONSerialization.data(withJSONObject: requestBody)
        let headers = [
            "Content-Type": "application/json",
            "Authorization": "Bearer \(accessToken)"
        ]

        let (data, _): (Data, HTTPURLResponse)
        do {
            (data, _) = try await httpClient.post(url: endpointURL, headers: headers, body: bodyData)
        } catch {
            throw OID4VCIError.credentialRequestFailed(error.localizedDescription)
        }

        let response: CredentialResponse
        do {
            response = try JSONDecoder().decode(CredentialResponse.self, from: data)
        } catch {
            throw OID4VCIError.credentialRequestFailed(
                "Failed to decode credential response: \(error.localizedDescription)"
            )
        }

        guard let credentialString = response.credential else {
            throw OID4VCIError.noCredentialInResponse
        }

        // The credential is base64url-encoded. Decode it.
        guard let credentialData = base64urlDecode(credentialString) else {
            throw OID4VCIError.invalidCredentialEncoding
        }

        return credentialData
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Encoding helpers
    // ═══════════════════════════════════════════════════════════════

    /// Percent-encodes a string for use as a `application/x-www-form-urlencoded` value.
    /// Per RFC 3986 / W3C, unreserved characters plus `*`, `-`, `.`, `_` are kept as-is;
    /// spaces become `+` (though we use percent-encoding for simplicity), everything else
    /// is percent-encoded.
    private func formEncode(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    /// Decodes a base64url-encoded string (no padding) to Data.
    private func base64urlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Add padding if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(contentsOf: repeatElement("=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }
}
