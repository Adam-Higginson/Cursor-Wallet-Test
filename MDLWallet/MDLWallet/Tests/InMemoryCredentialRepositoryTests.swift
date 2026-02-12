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
        
        @Test("it creates an in memory credential repository that has no document")
        func createsInMemoryCredentialRepositoryThatHasNoDocument() async throws {
            let repository = InMemoryCredentialRepository()
            
            let document = try await repository.load()
            #expect(document == nil)
        }
    }
    
    @Suite("Saving Documents")
    struct SavingDocuments {
        
        @Test("it should save a document and say it exists")
        func saveDocumentAndCheckExists() async throws {
            let repository = InMemoryCredentialRepository()
            let testData = TestHelpers.makeMinimalDocument()
            
            try await repository.save(testData)
            
            let exists = await repository.exists()
            #expect(exists)
        }
        
        @Test("it should load the saved document")
        func saveDocumentAndLoad() async throws {
            let repository = InMemoryCredentialRepository()
            let testData = TestHelpers.makeMinimalDocument()
            
            try await repository.save(testData)
            
            let storedDocument = try await repository.load()
            #expect(testData == storedDocument)
        }
        
        @Test("it should overwrite an existing document")
        func saveNewDocumentWhenThereAlreadyIsOne() async throws {
            let repository = InMemoryCredentialRepository()
            let firstTestData = TestHelpers.makeMinimalDocument()
            let updatedTestData = TestHelpers.makeMinimalDocument(givenName: "Bob")
            
            try await repository.save(firstTestData)
            try await repository.save(updatedTestData)
            
            let storedDocument = try await repository.load()
            #expect(updatedTestData == storedDocument)
        }
    }
    
    @Suite("Deleting Documents")
    struct DeletingDocuments {
        
        @Test("it should remove a document and say it no longer exists")
        func deleteDocumentAndSayItNoLongerExists() async throws {
            let repository = InMemoryCredentialRepository()
            let testData = TestHelpers.makeMinimalDocument()
            
            try await repository.save(testData)
            try await repository.delete()
            
            let exists = await repository.exists()
            #expect(!exists)
        }
        
        @Test("it should delete a document and load should return nil")
        func deleteDocumentAndLoadReturnsNil() async throws {
            let repository = InMemoryCredentialRepository()
            let testData = TestHelpers.makeMinimalDocument()
            
            try await repository.save(testData)
            try await repository.delete()

            let loadedData = try await repository.load()
            #expect(loadedData == nil)
        }
    }
    
}
