import Foundation

public protocol CredentialRepository: Sendable {
    /// Saves the decoded credential (document + optional MSO) received from the credential endpoint.
    func save(_ credential: StoredCredential) async throws
    /// Loads the stored credential; the view renders its document.
    func load() async throws -> StoredCredential?
    func delete() async throws
    func exists() async -> Bool
}
