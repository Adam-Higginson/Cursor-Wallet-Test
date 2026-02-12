public actor InMemoryCredentialRepository: CredentialRepository {
    
    private var savedCredential: MDLDocument?
    
    public func save(_ document: MDLDocument) async throws {
        savedCredential = document
    }
    
    public func load() async throws -> MDLDocument? {
        return savedCredential
    }
    
    public func delete() async throws {
        savedCredential = nil
    }
    
    public func exists() async -> Bool {
        return savedCredential != nil
    }
}
