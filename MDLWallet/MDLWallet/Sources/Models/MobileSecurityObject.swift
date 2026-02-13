// MobileSecurityObject.swift
// Model for the ISO/IEC 18013-5 Mobile Security Object (MSO).
//
// The MSO is the issuer-signed payload inside a COSE_Sign1 structure.
// It binds a credential's data elements (via digests) to a device key
// and a validity period. The wallet stores the MSO; readers verify
// disclosed claims against its valueDigests.

import Foundation

// MARK: - MobileSecurityObject

/// ISO 18013-5 Mobile Security Object (MSO) payload.
/// Carried inside a COSE_Sign1 structure signed by the issuer.
public struct MobileSecurityObject: Sendable, Equatable {

    /// MSO version string (e.g. "1.0").
    /// ISO 18013-5 §9.1.2.4 — mandatory field.
    public let version: String

    /// Digest algorithm used for valueDigests (e.g. "SHA-256", "SHA-384", "SHA-512").
    /// ISO 18013-5 §9.1.2.4 — mandatory field.
    public let digestAlgorithm: String

    /// Document type (e.g. "org.iso.18013.5.1.mDL").
    public let docType: String

    /// Validity period of the credential.
    public let validityInfo: MSOValidityInfo

    /// Device key bound to this credential instance.
    public let deviceKeyInfo: MSODeviceKeyInfo

    /// Digests of issuer-signed data elements, keyed by namespace then digest ID.
    /// Readers verify disclosed claims against these digests.
    /// Structure: namespace → (digestID → digestBytes)
    /// Digest IDs are unsigned integers per ISO 18013-5.
    public let valueDigests: [String: [UInt64: Data]]

    public init(
        version: String,
        digestAlgorithm: String,
        docType: String,
        validityInfo: MSOValidityInfo,
        deviceKeyInfo: MSODeviceKeyInfo,
        valueDigests: [String: [UInt64: Data]]
    ) {
        self.version = version
        self.digestAlgorithm = digestAlgorithm
        self.docType = docType
        self.validityInfo = validityInfo
        self.deviceKeyInfo = deviceKeyInfo
        self.valueDigests = valueDigests
    }
}

// MARK: - MSOValidityInfo

/// Validity period for the MSO (ISO 18013-5 §9.1.2.4).
public struct MSOValidityInfo: Sendable, Equatable {

    /// Date-time when the MSO was signed by the issuer.
    /// Mandatory per ISO 18013-5 §9.1.2.4.
    public let signed: Date

    /// Start of validity (ISO 8601 date-time, UTC).
    public let validFrom: Date

    /// End of validity (ISO 8601 date-time, UTC).
    public let validUntil: Date

    /// Expected next update. Optional per ISO 18013-5 §9.1.2.4.
    public let expectedUpdate: Date?

    public init(signed: Date, validFrom: Date, validUntil: Date, expectedUpdate: Date? = nil) {
        self.signed = signed
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.expectedUpdate = expectedUpdate
    }
}

// MARK: - MSODeviceKeyInfo

/// Device key info inside the MSO (ISO 18013-5 §9.1.2.4).
/// Holds the device public key; the wallet keeps the corresponding private key.
public struct MSODeviceKeyInfo: Sendable, Equatable {

    /// COSE_Key as raw CBOR-encoded bytes.
    /// For EC2 keys this is a CBOR map with kty(1), crv(-1), x(-2), y(-3).
    public let deviceKey: Data

    public init(deviceKey: Data) {
        self.deviceKey = deviceKey
    }
}
