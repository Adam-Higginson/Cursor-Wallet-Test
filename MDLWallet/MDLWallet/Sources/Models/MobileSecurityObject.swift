// MobileSecurityObject.swift
// Model for the ISO/IEC 18013-5 Mobile Security Object (MSO).
//
// The MSO is a COSE_Sign1-signed payload carrying credential validity,
// device public key, and value digests for issuer-signed claims. The wallet
// receives it from the issuer and stores it; it does not create or sign it.

import Foundation

// MARK: - MobileSecurityObject

/// ISO 18013-5 Mobile Security Object (MSO) payload.
/// The signed payload inside the MSO COSE_Sign1 structure.
public struct MobileSecurityObject: Sendable, Equatable {

    /// Document type (e.g. "org.iso.18013.5.1.mDL").
    public let docType: String

    /// Validity period of the credential.
    public let validityInfo: MSOValidityInfo

    /// Device key bound to this credential instance.
    public let deviceKeyInfo: MSODeviceKeyInfo

    /// Digests of issuer-signed namespaces/elements (namespace → digest label → digest bytes).
    /// Used by readers to verify disclosed claims against the signed digests.
    public let valueDigests: [String: [String: Data]]

    public init(
        docType: String,
        validityInfo: MSOValidityInfo,
        deviceKeyInfo: MSODeviceKeyInfo,
        valueDigests: [String: [String: Data]]
    ) {
        self.docType = docType
        self.validityInfo = validityInfo
        self.deviceKeyInfo = deviceKeyInfo
        self.valueDigests = valueDigests
    }
}

// MARK: - MSOValidityInfo

/// Validity period for the MSO (ISO 18013-5).
public struct MSOValidityInfo: Sendable, Equatable {

    /// Start of validity (ISO 8601 date-time).
    public let validFrom: Date

    /// End of validity (ISO 8601 date-time).
    public let validUntil: Date

    public init(validFrom: Date, validUntil: Date) {
        self.validFrom = validFrom
        self.validUntil = validUntil
    }
}

// MARK: - MSODeviceKeyInfo

/// Device key info inside the MSO (ISO 18013-5).
/// Holds the device public key in COSE_Key form; the wallet keeps the corresponding private key for device signing.
public struct MSODeviceKeyInfo: Sendable, Equatable {

    /// COSE_Key map as raw CBOR-encoded data, or the decoded key type and bytes for EC (e.g. P-256 x, y).
    /// For EC2 keys: kty=2, crv, x (bstr), y (bstr).
    public let deviceKey: Data

    public init(deviceKey: Data) {
        self.deviceKey = deviceKey
    }
}
