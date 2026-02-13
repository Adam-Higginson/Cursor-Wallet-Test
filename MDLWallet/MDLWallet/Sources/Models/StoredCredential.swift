// StoredCredential.swift
// Combined document + MSO as decoded from the credential endpoint and stored in the repository.

import Foundation

/// Decoded credential from the issuer: mDL document plus optional Mobile Security Object.
/// The repository stores this object; the view renders the document.
public struct StoredCredential: Sendable, Equatable {
    public let document: MDLDocument
    public let mso: MobileSecurityObject?

    public init(document: MDLDocument, mso: MobileSecurityObject? = nil) {
        self.document = document
        self.mso = mso
    }
}
