import Testing
import Foundation
@testable import MDLWallet

/// In-memory store so tests never touch the real Keychain (avoids simulator hangs in Delete and other suites).
private actor InMemoryCredentialDataStore: CredentialDataStore {
    private var data: Data?

    func write(_ newData: Data) async throws {
        data = newData
    }

    func read() async throws -> Data? {
        data
    }

    func delete() async throws {
        data = nil
    }

    func exists() async -> Bool {
        data != nil
    }
}

private func makeRepository() -> KeychainCredentialRepository {
    KeychainCredentialRepository(storage: InMemoryCredentialDataStore())
}

@Suite("KeychainCredentialRepository")
struct KeychainCredentialRepositoryTests {

    @Suite("Initial state")
    struct InitialState {

        @Test("exists returns false when empty")
        func existsFalseWhenEmpty() async throws {
            let repository = makeRepository()
            let exists = await repository.exists()
            #expect(!exists)
        }

        @Test("load returns nil when empty")
        func loadReturnsNilWhenEmpty() async throws {
            let repository = makeRepository()
            let loaded = try await repository.load()
            #expect(loaded == nil)
        }
    }

    @Suite("Save and load with credentialCbor")
    struct SaveAndLoadWithCredentialCbor {

        @Test("save then load returns same document and preserves credentialCbor")
        func saveThenLoadReturnsSameCredential() async throws {
            let repository = makeRepository()

            let document = TestHelpers.makeMinimalDocumentForCBOR()
            let cbor = MDLDocumentCBORCoding.encode(document)
            let credential = StoredCredential(document: document, mso: nil, credentialCbor: cbor)

            try await repository.save(credential)
            let loaded = try await repository.load()
            try? await repository.delete()

            #expect(loaded != nil)
            #expect(loaded?.document == document)
            #expect(loaded?.credentialCbor == cbor)
        }

        @Test("save then load overwrites and returns new credential")
        func saveOverwritesPrevious() async throws {
            let repository = makeRepository()

            let firstDoc = TestHelpers.makeMinimalDocumentForCBOR()
            let firstCbor = MDLDocumentCBORCoding.encode(firstDoc)
            try await repository.save(StoredCredential(document: firstDoc, credentialCbor: firstCbor))

            let secondDoc = TestHelpers.makeMinimalDocument(givenName: "Bob")
            let secondCbor = MDLDocumentCBORCoding.encode(secondDoc)
            try await repository.save(StoredCredential(document: secondDoc, credentialCbor: secondCbor))

            let loaded = try await repository.load()
            try? await repository.delete()

            #expect(loaded?.document.givenName == "Bob")
            #expect(loaded?.credentialCbor == secondCbor)
        }
    }

    @Suite("Save without credentialCbor")
    struct SaveWithoutCredentialCbor {

        @Test("save document-only credential then load returns decoded document")
        func saveWithoutCredentialCborThenLoad() async throws {
            let repository = makeRepository()

            let document = TestHelpers.makeMinimalDocumentForCBOR()
            let credential = StoredCredential(document: document)

            try await repository.save(credential)
            let loaded = try await repository.load()
            try? await repository.delete()

            #expect(loaded != nil)
            #expect(loaded?.document == document)
            #expect(loaded?.credentialCbor != nil)
            #expect(loaded?.credentialCbor == MDLDocumentCBORCoding.encode(document))
        }
    }

    @Suite("Delete")
    struct Delete {

        @Test("delete then exists returns false")
        func deleteThenExistsFalse() async throws {
            let repository = makeRepository()

            let credential = StoredCredential(document: TestHelpers.makeMinimalDocument())
            try await repository.save(credential)
            try await repository.delete()

            let exists = await repository.exists()
            #expect(!exists)
        }

        @Test("delete then load returns nil")
        func deleteThenLoadReturnsNil() async throws {
            let repository = makeRepository()

            let credential = StoredCredential(document: TestHelpers.makeMinimalDocument())
            try await repository.save(credential)
            try await repository.delete()

            let loaded = try await repository.load()
            #expect(loaded == nil)
        }
    }

    @Suite("Exists")
    struct Exists {

        @Test("exists returns true after save")
        func existsTrueAfterSave() async throws {
            let repository = makeRepository()

            #expect(await repository.exists() == false)
            try await repository.save(StoredCredential(document: TestHelpers.makeMinimalDocument()))
            #expect(await repository.exists() == true)
            try? await repository.delete()
        }
    }
}
