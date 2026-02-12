import Foundation

public protocol CredentialRepository: Sendable {
    func save(_ document: MDLDocument) async throws
    func load() async throws -> MDLDocument?
    func delete() async throws
    func exists() async -> Bool
}
