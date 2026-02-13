// OID4VCIClientTests.swift
// Tests for the OID4VCI pre-authorized code flow client.

import Testing
import Foundation
@testable import MDLWallet

// MARK: - Mock HTTP Client

/// A recorded POST request for test assertions.
struct RecordedPost: Sendable {
    let url: URL
    let headers: [String: String]
    let body: Data?
}

/// A mock HTTPClient that returns canned responses based on URL patterns.
actor MockHTTPClient: HTTPClient {
    private var getResponses: [String: (Data, HTTPURLResponse)] = [:]
    private var postResponses: [String: (Data, HTTPURLResponse)] = [:]
    private(set) var getRequests: [URL] = []
    private(set) var postRequests: [RecordedPost] = []

    func stubGet(urlContaining substring: String, data: Data, statusCode: Int = 200) {
        let response = HTTPURLResponse(
            url: URL(string: "https://stub")!, statusCode: statusCode, httpVersion: nil, headerFields: nil
        )!
        getResponses[substring] = (data, response)
    }

    func stubPost(urlContaining substring: String, data: Data, statusCode: Int = 200) {
        let response = HTTPURLResponse(
            url: URL(string: "https://stub")!, statusCode: statusCode, httpVersion: nil, headerFields: nil
        )!
        postResponses[substring] = (data, response)
    }

    nonisolated func get(url: URL) async throws -> (Data, HTTPURLResponse) {
        await recordGet(url: url)
        return try await findGetResponse(for: url)
    }

    nonisolated func post(url: URL, headers: [String: String], body: Data?) async throws -> (Data, HTTPURLResponse) {
        await recordPost(url: url, headers: headers, body: body)
        return try await findPostResponse(for: url)
    }

    private func recordGet(url: URL) { getRequests.append(url) }
    private func recordPost(url: URL, headers: [String: String], body: Data?) {
        postRequests.append(RecordedPost(url: url, headers: headers, body: body))
    }

    private func findGetResponse(for url: URL) throws -> (Data, HTTPURLResponse) {
        let urlString = url.absoluteString
        if let match = getResponses.first(where: { urlString.contains($0.key) }) {
            return match.value
        }
        throw HTTPClientError.httpError(statusCode: 404, body: Data())
    }

    private func findPostResponse(for url: URL) throws -> (Data, HTTPURLResponse) {
        let urlString = url.absoluteString
        if let match = postResponses.first(where: { urlString.contains($0.key) }) {
            return match.value
        }
        throw HTTPClientError.httpError(statusCode: 404, body: Data())
    }
}

// MARK: - Test Data

private enum TestData {
    static let issuerURL = "https://issuer.example.com"

    static let issuerMetadataJSON = Data("""
    {
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "authorization_servers": ["https://auth.example.com"],
        "credential_configurations_supported": {
            "org.iso.18013.5.1.mDL": {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL"
            }
        }
    }
    """.utf8)

    static let asMetadataJSON = Data("""
    {"token_endpoint": "https://auth.example.com/token"}
    """.utf8)

    static let tokenResponseJSON = Data("""
    {"access_token": "eyJhbGciOiJSUzI1NiJ9.test_token", "token_type": "Bearer", "expires_in": 3600}
    """.utf8)

    // A fake credential: base64url("hello_credential")
    static let credentialBase64url = "aGVsbG9fY3JlZGVudGlhbA"
    static let credentialResponseJSON = Data("""
    {"credential": "\(credentialBase64url)"}
    """.utf8)

    static func makeOffer() -> CredentialOffer {
        CredentialOffer(
            credentialIssuer: issuerURL,
            credentialConfigurationIds: ["org.iso.18013.5.1.mDL"],
            grants: CredentialOffer.Grants(
                preAuthorizedCode: CredentialOffer.PreAuthorizedCodeGrant(
                    preAuthorizedCode: "test_pre_auth_code"
                )
            )
        )
    }
}

// MARK: - Tests

@Suite("OID4VCIClient")
struct OID4VCIClientTests {

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Issuer Metadata
    // ═══════════════════════════════════════════════════════════════

    @Suite("Issuer metadata")
    struct IssuerMetadataTests {

        @Test("fetches and decodes issuer metadata")
        func fetchMetadata() async throws {
            let mock = MockHTTPClient()
            await mock.stubGet(urlContaining: ".well-known/openid-credential-issuer", data: TestData.issuerMetadataJSON)

            let client = OID4VCIClient(httpClient: mock)
            let metadata = try await client.fetchIssuerMetadata(issuerURL: TestData.issuerURL)

            #expect(metadata.credentialIssuer == "https://issuer.example.com")
            #expect(metadata.credentialEndpoint == "https://issuer.example.com/credential")
            #expect(metadata.authorizationServers == ["https://auth.example.com"])
        }

        @Test("throws invalidIssuerURL for empty URL")
        func invalidURL() async {
            let client = OID4VCIClient(httpClient: MockHTTPClient())
            do {
                _ = try await client.fetchIssuerMetadata(issuerURL: "")
                #expect(Bool(false), "Should have thrown")
            } catch {
                #expect(error is OID4VCIError)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Token Exchange
    // ═══════════════════════════════════════════════════════════════

    @Suite("Token exchange")
    struct TokenExchangeTests {

        @Test("exchanges pre-authorized code for access token")
        func exchangeCode() async throws {
            let mock = MockHTTPClient()
            await mock.stubPost(urlContaining: "/token", data: TestData.tokenResponseJSON)

            let client = OID4VCIClient(httpClient: mock)
            let tokenURL = URL(string: "https://auth.example.com/token")!
            let response = try await client.exchangePreAuthorizedCode(
                tokenEndpoint: tokenURL,
                preAuthorizedCode: "test_code"
            )

            #expect(response.accessToken == "eyJhbGciOiJSUzI1NiJ9.test_token")
            #expect(response.tokenType == "Bearer")
            #expect(response.expiresIn == 3600)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Credential Request
    // ═══════════════════════════════════════════════════════════════

    @Suite("Credential request")
    struct CredentialRequestTests {

        @Test("requests and decodes credential")
        func requestCredential() async throws {
            let mock = MockHTTPClient()
            await mock.stubPost(urlContaining: "/credential", data: TestData.credentialResponseJSON)

            let client = OID4VCIClient(httpClient: mock)
            let data = try await client.requestCredential(
                credentialEndpoint: "https://issuer.example.com/credential",
                accessToken: "test_token",
                credentialConfigurationIds: ["org.iso.18013.5.1.mDL"]
            )

            #expect(data == Data("hello_credential".utf8))
        }

        @Test("throws noCredentialInResponse when credential field is null")
        func noCredential() async {
            let mock = MockHTTPClient()
            await mock.stubPost(urlContaining: "/credential", data: Data("{\"credential\": null}".utf8))

            let client = OID4VCIClient(httpClient: mock)
            do {
                _ = try await client.requestCredential(
                    credentialEndpoint: "https://issuer.example.com/credential",
                    accessToken: "test_token",
                    credentialConfigurationIds: ["mDL"]
                )
                #expect(Bool(false), "Should have thrown")
            } catch {
                #expect(error is OID4VCIError)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Full Flow
    // ═══════════════════════════════════════════════════════════════

    @Suite("Full issuance flow")
    struct FullFlowTests {

        @Test("completes the full pre-authorized code flow")
        func fullFlow() async throws {
            let mock = MockHTTPClient()
            await mock.stubGet(urlContaining: ".well-known/openid-credential-issuer", data: TestData.issuerMetadataJSON)
            await mock.stubGet(urlContaining: ".well-known/oauth-authorization-server", data: TestData.asMetadataJSON)
            await mock.stubPost(urlContaining: "/token", data: TestData.tokenResponseJSON)
            await mock.stubPost(urlContaining: "/credential", data: TestData.credentialResponseJSON)

            let client = OID4VCIClient(httpClient: mock)
            let credentialData = try await client.issueCredential(offer: TestData.makeOffer())

            #expect(credentialData == Data("hello_credential".utf8))
        }

        @Test("falls back to {issuer}/token when AS metadata is not available")
        func tokenEndpointFallback() async throws {
            let mock = MockHTTPClient()
            // Return metadata without authorization_servers
            let metadataNoAS = Data("""
            {"credential_issuer":"https://issuer.example.com","credential_endpoint":"https://issuer.example.com/credential"}
            """.utf8)
            await mock.stubGet(urlContaining: ".well-known/openid-credential-issuer", data: metadataNoAS)
            await mock.stubPost(urlContaining: "/token", data: TestData.tokenResponseJSON)
            await mock.stubPost(urlContaining: "/credential", data: TestData.credentialResponseJSON)

            let client = OID4VCIClient(httpClient: mock)
            let credentialData = try await client.issueCredential(offer: TestData.makeOffer())

            #expect(credentialData == Data("hello_credential".utf8))
        }
    }
}
