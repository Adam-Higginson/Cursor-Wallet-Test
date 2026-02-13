// ModelDecodingTests.swift
// Tests for JSON decoding of OID4VCI response models.

import Testing
import Foundation
@testable import MDLWallet

@Suite("OID4VCI Model Decoding")
struct ModelDecodingTests {

    // ═══════════════════════════════════════════════════════════════
    // MARK: - IssuerMetadata
    // ═══════════════════════════════════════════════════════════════

    @Suite("IssuerMetadata")
    struct IssuerMetadataDecoding {

        @Test("decodes full issuer metadata with all fields")
        func fullMetadata() throws {
            let json = Data("""
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

            let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: json)

            #expect(metadata.credentialIssuer == "https://issuer.example.com")
            #expect(metadata.credentialEndpoint == "https://issuer.example.com/credential")
            #expect(metadata.authorizationServers == ["https://auth.example.com"])
            #expect(metadata.credentialConfigurationsSupported?["org.iso.18013.5.1.mDL"]?.format == "mso_mdoc")
            #expect(metadata.credentialConfigurationsSupported?["org.iso.18013.5.1.mDL"]?.doctype == "org.iso.18013.5.1.mDL")
        }

        @Test("decodes minimal issuer metadata (only required fields)")
        func minimalMetadata() throws {
            let json = Data("""
            {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential"
            }
            """.utf8)

            let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: json)

            #expect(metadata.credentialIssuer == "https://issuer.example.com")
            #expect(metadata.authorizationServers == nil)
            #expect(metadata.credentialConfigurationsSupported == nil)
        }

        @Test("ignores unknown fields in metadata")
        func unknownFields() throws {
            let json = Data("""
            {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "unknown_field": "should be ignored",
                "another_unknown": 42
            }
            """.utf8)

            let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: json)
            #expect(metadata.credentialIssuer == "https://issuer.example.com")
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - TokenResponse
    // ═══════════════════════════════════════════════════════════════

    @Suite("TokenResponse")
    struct TokenResponseDecoding {

        @Test("decodes full token response")
        func fullResponse() throws {
            let json = Data("""
            {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
                "token_type": "Bearer",
                "expires_in": 3600,
                "c_nonce": "tZignsnFbp",
                "c_nonce_expires_in": 86400
            }
            """.utf8)

            let response = try JSONDecoder().decode(TokenResponse.self, from: json)

            #expect(response.accessToken == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9")
            #expect(response.tokenType == "Bearer")
            #expect(response.expiresIn == 3600)
            #expect(response.cNonce == "tZignsnFbp")
            #expect(response.cNonceExpiresIn == 86400)
        }

        @Test("decodes minimal token response (access_token only)")
        func minimalResponse() throws {
            let json = Data("""
            {"access_token": "abc123"}
            """.utf8)

            let response = try JSONDecoder().decode(TokenResponse.self, from: json)

            #expect(response.accessToken == "abc123")
            #expect(response.tokenType == nil)
            #expect(response.expiresIn == nil)
            #expect(response.cNonce == nil)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - CredentialResponse
    // ═══════════════════════════════════════════════════════════════

    @Suite("CredentialResponse")
    struct CredentialResponseDecoding {

        @Test("decodes immediate credential response")
        func immediateResponse() throws {
            let json = Data("""
            {
                "credential": "base64url_encoded_credential_data",
                "c_nonce": "fresh_nonce",
                "c_nonce_expires_in": 86400
            }
            """.utf8)

            let response = try JSONDecoder().decode(CredentialResponse.self, from: json)

            #expect(response.credential == "base64url_encoded_credential_data")
            #expect(response.transactionId == nil)
            #expect(response.cNonce == "fresh_nonce")
        }

        @Test("decodes deferred credential response")
        func deferredResponse() throws {
            let json = Data("""
            {"transaction_id": "txn_abc123"}
            """.utf8)

            let response = try JSONDecoder().decode(CredentialResponse.self, from: json)

            #expect(response.credential == nil)
            #expect(response.transactionId == "txn_abc123")
        }

        @Test("decodes credentials array (CRI shape)")
        func credentialsArrayResponse() throws {
            let json = Data("""
            {
                "credentials": [{"credential": "aGVsbG9fbWRvYw"}],
                "notification_id": "1143910d-b9d0-4cdb-a2d2-046e2bf8f55b"
            }
            """.utf8)

            let response = try JSONDecoder().decode(CredentialResponse.self, from: json)

            #expect(response.credential == "aGVsbG9fbWRvYw")
            #expect(response.notificationId == "1143910d-b9d0-4cdb-a2d2-046e2bf8f55b")
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - AuthorizationServerMetadata
    // ═══════════════════════════════════════════════════════════════

    @Suite("AuthorizationServerMetadata")
    struct ASMetadataDecoding {

        @Test("decodes authorization server metadata")
        func decodeASMetadata() throws {
            let json = Data("""
            {
                "issuer": "https://auth.example.com",
                "token_endpoint": "https://auth.example.com/oauth/token",
                "authorization_endpoint": "https://auth.example.com/authorize"
            }
            """.utf8)

            let metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: json)
            #expect(metadata.tokenEndpoint == "https://auth.example.com/oauth/token")
        }
    }
}
