// CredentialOfferTests.swift
// Tests for parsing OID4VCI credential offer URIs from QR codes.

import Testing
import Foundation
@testable import MDLWallet

@Suite("CredentialOffer Parsing")
struct CredentialOfferTests {

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Helpers
    // ═══════════════════════════════════════════════════════════════

    /// Builds a valid credential offer URI with the given JSON payload.
    private static func makeOfferURI(json: String) -> String {
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? json
        return "openid-credential-offer://?credential_offer=\(encoded)"
    }

    private static let validJSON = """
    {"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["org.iso.18013.5.1.mDL"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"SplxlOBeZQQYbYS6WxSbIA"}}}
    """

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Valid parsing
    // ═══════════════════════════════════════════════════════════════

    @Suite("Valid offers")
    struct ValidOffers {

        @Test("parses a valid credential offer URI")
        func validOffer() throws {
            let uri = CredentialOfferTests.makeOfferURI(json: CredentialOfferTests.validJSON)
            let offer = try CredentialOffer.parse(uri)

            #expect(offer.credentialIssuer == "https://issuer.example.com")
            #expect(offer.credentialConfigurationIds == ["org.iso.18013.5.1.mDL"])
            #expect(offer.grants?.preAuthorizedCode?.preAuthorizedCode == "SplxlOBeZQQYbYS6WxSbIA")
        }

        @Test("parses offer with multiple credential configuration IDs")
        func multipleConfigIds() throws {
            let json = """
            {"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["org.iso.18013.5.1.mDL","eu.europa.ec.eudi.pid.1"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc123"}}}
            """
            let uri = CredentialOfferTests.makeOfferURI(json: json)
            let offer = try CredentialOffer.parse(uri)

            #expect(offer.credentialConfigurationIds.count == 2)
            #expect(offer.credentialConfigurationIds.contains("org.iso.18013.5.1.mDL"))
            #expect(offer.credentialConfigurationIds.contains("eu.europa.ec.eudi.pid.1"))
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Error cases
    // ═══════════════════════════════════════════════════════════════

    @Suite("Error cases")
    struct ErrorCases {

        @Test("throws invalidScheme for http:// URI")
        func wrongScheme() {
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse("https://example.com/offer")
            }
        }

        @Test("throws invalidScheme for empty string")
        func emptyString() {
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse("")
            }
        }

        @Test("throws missingCredentialOfferParameter when query param is absent")
        func missingParam() {
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse("openid-credential-offer://?other_param=foo")
            }
        }

        @Test("throws invalidJSON when JSON is malformed")
        func malformedJSON() {
            let uri = CredentialOfferTests.makeOfferURI(json: "{not valid json")
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse(uri)
            }
        }

        @Test("throws missingPreAuthorizedCode when grants is nil")
        func noGrants() {
            let json = """
            {"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["mDL"]}
            """
            let uri = CredentialOfferTests.makeOfferURI(json: json)
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse(uri)
            }
        }

        @Test("throws missingPreAuthorizedCode when grants has no pre-auth code")
        func grantsWithoutPreAuth() {
            let json = """
            {"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["mDL"],"grants":{}}
            """
            let uri = CredentialOfferTests.makeOfferURI(json: json)
            #expect(throws: CredentialOfferError.self) {
                _ = try CredentialOffer.parse(uri)
            }
        }
    }
}
