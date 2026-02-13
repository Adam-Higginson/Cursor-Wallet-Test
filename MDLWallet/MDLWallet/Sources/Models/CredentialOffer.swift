// CredentialOffer.swift
// Model for the OID4VCI Credential Offer (§4.1.1).
//
// The credential offer is transmitted as inline JSON in a QR code:
//   openid-credential-offer://?credential_offer=URL_ENCODED_JSON
//
// It tells the wallet which issuer to contact, what credentials are
// available, and provides the pre-authorized code for the token exchange.

import Foundation

// MARK: - CredentialOffer

/// OID4VCI Credential Offer received from a QR code.
public struct CredentialOffer: Sendable, Equatable {

    /// URL of the credential issuer (e.g. "https://issuer.example.com").
    public let credentialIssuer: String

    /// Identifiers of the credential configurations being offered.
    public let credentialConfigurationIds: [String]

    /// Grant types available for this offer.
    public let grants: Grants?

    public init(credentialIssuer: String, credentialConfigurationIds: [String], grants: Grants?) {
        self.credentialIssuer = credentialIssuer
        self.credentialConfigurationIds = credentialConfigurationIds
        self.grants = grants
    }
}

// MARK: - Grants

extension CredentialOffer {

    /// Available grant types in the credential offer.
    public struct Grants: Sendable, Equatable {

        /// Pre-authorized code grant (if present, the pre-auth flow is available).
        public let preAuthorizedCode: PreAuthorizedCodeGrant?

        public init(preAuthorizedCode: PreAuthorizedCodeGrant?) {
            self.preAuthorizedCode = preAuthorizedCode
        }
    }

    /// Parameters for the pre-authorized code grant type.
    public struct PreAuthorizedCodeGrant: Sendable, Equatable {

        /// The pre-authorized code to exchange for an access token.
        public let preAuthorizedCode: String

        public init(preAuthorizedCode: String) {
            self.preAuthorizedCode = preAuthorizedCode
        }
    }
}

// MARK: - Decodable

extension CredentialOffer: Decodable {
    private enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentialConfigurationIds = "credential_configuration_ids"
        case grants
    }
}

extension CredentialOffer.Grants: Decodable {
    /// The grant type key is the full URN per OID4VCI spec.
    private enum CodingKeys: String, CodingKey {
        case preAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

extension CredentialOffer.PreAuthorizedCodeGrant: Decodable {
    private enum CodingKeys: String, CodingKey {
        case preAuthorizedCode = "pre-authorized_code"
    }
}

// MARK: - Credential Offer Parsing

/// Errors when parsing a credential offer URI.
public enum CredentialOfferError: Error, Sendable, Equatable {
    /// The URI scheme is not `openid-credential-offer`.
    case invalidScheme(String)
    /// The `credential_offer` query parameter is missing.
    case missingCredentialOfferParameter
    /// The JSON in the `credential_offer` parameter could not be decoded.
    case invalidJSON(String)
    /// The offer does not contain a pre-authorized code grant.
    case missingPreAuthorizedCode
}

extension CredentialOffer {

    /// Parses a credential offer from a QR code string.
    ///
    /// Expected format:
    /// `openid-credential-offer://?credential_offer=URL_ENCODED_JSON`
    ///
    /// - Parameter qrString: The raw string scanned from the QR code.
    /// - Returns: A parsed `CredentialOffer`.
    /// - Throws: `CredentialOfferError` if parsing fails.
    public static func parse(_ qrString: String) throws -> CredentialOffer {
        guard let components = URLComponents(string: qrString) else {
            throw CredentialOfferError.invalidScheme(qrString)
        }

        guard components.scheme == "openid-credential-offer" else {
            throw CredentialOfferError.invalidScheme(components.scheme ?? "<nil>")
        }

        guard let offerParam = components.queryItems?.first(where: { $0.name == "credential_offer" }),
              let offerJSON = offerParam.value else {
            throw CredentialOfferError.missingCredentialOfferParameter
        }

        guard let jsonData = offerJSON.data(using: .utf8) else {
            throw CredentialOfferError.invalidJSON("Could not convert to UTF-8 data")
        }

        let decoder = JSONDecoder()
        let offer: CredentialOffer
        do {
            offer = try decoder.decode(CredentialOffer.self, from: jsonData)
        } catch {
            throw CredentialOfferError.invalidJSON(error.localizedDescription)
        }

        guard offer.grants?.preAuthorizedCode != nil else {
            throw CredentialOfferError.missingPreAuthorizedCode
        }

        return offer
    }
}
