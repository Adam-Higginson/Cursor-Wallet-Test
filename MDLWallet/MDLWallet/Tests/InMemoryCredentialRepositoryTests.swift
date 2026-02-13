import Testing
import Foundation
@testable import MDLWallet

@Suite("InMemoryCredentialRepository")
struct InMemoryCredentialRepositoryTests {
    @Suite("Initialisation")
    struct Initialisation {

        @Test("it creates an in memory credential repository that says exists false")
        func createsInMemoryCredentialRepositoryThatIsEmpty() async {
            let repository = InMemoryCredentialRepository()

            let exists = await repository.exists()
            #expect(!exists)
        }

        @Test("it creates an in memory credential repository that has no credential")
        func createsInMemoryCredentialRepositoryThatHasNoCredential() async throws {
            let repository = InMemoryCredentialRepository()

            let loaded = try await repository.load()
            #expect(loaded == nil)
        }
    }

    @Suite("Saving Credentials")
    struct SavingCredentials {

        @Test("it should save a credential and say it exists")
        func saveCredentialAndCheckExists() async throws {
            let repository = InMemoryCredentialRepository()
            let document = TestHelpers.makeMinimalDocument()
            let credential = StoredCredential(document: document)

            try await repository.save(credential)

            let exists = await repository.exists()
            #expect(exists)
        }

        @Test("it should load the saved credential")
        func saveCredentialAndLoad() async throws {
            let repository = InMemoryCredentialRepository()
            let document = TestHelpers.makeMinimalDocument()
            let credential = StoredCredential(document: document)

            try await repository.save(credential)

            let loaded = try await repository.load()
            #expect(loaded?.document == document)
        }

        @Test("it should overwrite an existing credential")
        func saveNewCredentialWhenThereAlreadyIsOne() async throws {
            let repository = InMemoryCredentialRepository()
            let firstDoc = TestHelpers.makeMinimalDocument()
            let updatedDoc = TestHelpers.makeMinimalDocument(givenName: "Bob")

            try await repository.save(StoredCredential(document: firstDoc))
            try await repository.save(StoredCredential(document: updatedDoc))

            let loaded = try await repository.load()
            #expect(loaded?.document == updatedDoc)
        }
    }

    @Suite("Deleting Credentials")
    struct DeletingCredentials {

        @Test("it should remove a credential and say it no longer exists")
        func deleteCredentialAndSayItNoLongerExists() async throws {
            let repository = InMemoryCredentialRepository()
            let credential = StoredCredential(document: TestHelpers.makeMinimalDocument())

            try await repository.save(credential)
            try await repository.delete()

            let exists = await repository.exists()
            #expect(!exists)
        }

        @Test("it should delete a credential and load should return nil")
        func deleteCredentialAndLoadReturnsNil() async throws {
            let repository = InMemoryCredentialRepository()
            let credential = StoredCredential(document: TestHelpers.makeMinimalDocument())

            try await repository.save(credential)
            try await repository.delete()

            let loaded = try await repository.load()
            #expect(loaded == nil)
        }
    }

}
