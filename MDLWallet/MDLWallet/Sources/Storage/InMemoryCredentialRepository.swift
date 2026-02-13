import Foundation

public actor InMemoryCredentialRepository: CredentialRepository {

    private var savedCredential: StoredCredential?

    public func save(_ credential: StoredCredential) async throws {
        savedCredential = credential
    }

    public func load() async throws -> StoredCredential? {
        savedCredential
    }

    public func delete() async throws {
        savedCredential = nil
    }

    public func exists() async -> Bool {
        savedCredential != nil
    }
}
