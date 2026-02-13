// StoredCredential.swift
// Combined document + MSO as decoded from the credential endpoint and stored in the repository.

import Foundation

/// Decoded credential from the issuer: mDL document plus optional Mobile Security Object.
/// The repository stores this object; the view renders the document.
/// When present, `credentialCbor` is the raw CBOR bytes from the issuer; persistence uses it so the exact bytes are stored (no re-encoding).
public struct StoredCredential: Sendable, Equatable {
    public let document: MDLDocument
    public let mso: MobileSecurityObject?
    /// Raw credential CBOR from the issuer when available. When nil (e.g. preview), persistence encodes the document only.
    public let credentialCbor: Data?

    public init(document: MDLDocument, mso: MobileSecurityObject? = nil, credentialCbor: Data? = nil) {
        self.document = document
        self.mso = mso
        self.credentialCbor = credentialCbor
    }
}
