import SwiftUI

public struct ContentView: View {
    // ───────────────────────────────────────────────────────────────────
    // MARK: Dependencies
    // ───────────────────────────────────────────────────────────────────
    private let credentialRepository: CredentialRepository


    @State private var currentCredential: MDLDocument? = nil
    @State private var isLoading = true
    @State private var isErrorLoadingCredential = false
    @State private var saveErrorMessage: String? = nil

    
    public init(credentialRepository: CredentialRepository) {
        self.credentialRepository = credentialRepository
    }

    public var body: some View {
        VStack(spacing: 20) {
            if isLoading {
                // Show loading spinner while checking repository
                ProgressView("Checking for credentials...")
            } else if currentCredential != nil {
                // User has an MDL - show success message
                VStack(spacing: 16) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 60))
                        .foregroundStyle(.green)
                    
                    Text("MDL Found")
                        .font(.title)
                        .fontWeight(.bold)
                    
                    Text("Your mobile driver's license is stored securely.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    
                    Text("Driving Licence No: ****" + (currentCredential.map { String($0.documentNumber.suffix(4)) } ?? "****"))
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    
                    Button(action: removeCredential) {
                        Label("Remove MDL", systemImage: "trash.fill")
                            .font(.headline)
                            .foregroundStyle(.white)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(.red)
                            .cornerRadius(12)
                    }
                    .padding(.top, 8)
                }
            } else if isErrorLoadingCredential {
                VStack(spacing: 16) {
                    Text("Error when loading your MDL!")
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)

                    
                    Button(action: addCredential) {
                        Label("Try Adding Credential Again", systemImage: "person.text.rectangle")
                            .font(.headline)
                            .foregroundStyle(.white)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(.blue)
                            .cornerRadius(12)

                    }
                }
            }
            else {
                // No MDL - show button to add one
                VStack(spacing: 16) {
                    Image(systemName: "person.text.rectangle")
                        .font(.system(size: 60))
                        .foregroundStyle(.blue)
                    
                    Text("No MDL Found")
                        .font(.title)
                        .fontWeight(.bold)
                    
                    Text("Add your mobile driver's license to get started.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    
                    Button(action: addCredential) {
                        Label("Add MDL", systemImage: "plus.circle.fill")
                            .font(.headline)
                            .foregroundStyle(.white)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(.blue)
                            .cornerRadius(12)
                    }
                    .padding(.top, 8)
                }
            }
        }
        .padding()
        .overlay(alignment: .bottom) {
            if let message = saveErrorMessage {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(8)
                    .background(.red.opacity(0.1))
                    .cornerRadius(8)
                    .padding(.bottom, 8)
            }
        }
        // .task runs when the view appears - perfect for loading data
        // Similar to useEffect in React or onMounted in Vue
        .task {
            await checkForCredential()
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // MARK: Actions
    // ───────────────────────────────────────────────────────────────────
    
    /// Check if a credential exists in the repository
    private func checkForCredential() async {
        isLoading = true
        if (await credentialRepository.exists()) {
            do {
                currentCredential = try await credentialRepository.load()
                isErrorLoadingCredential = false
            } catch {
                // Handle the error - set error state
                isErrorLoadingCredential = true
                currentCredential = nil
                print("Error loading credential: \(error)")
            }
        } else {
            currentCredential = nil
            isErrorLoadingCredential = false
        }
        
        isLoading = false
    }
    
    /// Handle the "Add MDL" button tap
    private func addCredential() {
        saveErrorMessage = nil
        Task {
            let testDocument = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: Date(timeIntervalSince1970: 645840000), // June 15, 1990
                issueDate: Date(),
                expiryDate: Date(timeIntervalSinceNow: 60 * 60 * 24 * 365 * 5), // 5 years
                issuingCountry: "UK",
                issuingAuthority: "DVLA",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            do {
                try await credentialRepository.save(testDocument)
                await checkForCredential()
            } catch {
                saveErrorMessage = error.localizedDescription
                await checkForCredential()
            }
        }
    }

    /// Handle the "Remove MDL" button tap
    private func removeCredential() {
        saveErrorMessage = nil
        Task {
            do {
                try await credentialRepository.delete()
                await checkForCredential()
            } catch {
                saveErrorMessage = error.localizedDescription
                await checkForCredential()
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════
// MARK: - Previews
// ═══════════════════════════════════════════════════════════════════════
// Xcode Previews let you see your UI without running the app.
// Similar to Storybook in React or Hot Reload in Flutter.

#Preview("Empty Repository") {
    ContentView(credentialRepository: InMemoryCredentialRepository())
}

#Preview("With Credential") {
    // Create a wrapper view that sets up the data before showing ContentView
    PreviewHelperWithCredential()
}

#Preview("Error State") {
    ContentView(credentialRepository: ErrorThrowingCredentialRepository())
}

// Helper view for async preview setup
private struct PreviewHelperWithCredential: View {
    @State private var repository = InMemoryCredentialRepository()
    @State private var isReady = false
    
    var body: some View {
        if isReady {
            ContentView(credentialRepository: repository)
        } else {
            ProgressView("Setting up preview...")
                .task {
                    // Pre-populate the repository for preview
                    try? await repository.save(MDLDocument(
                        familyName: "Smith",
                        givenName: "Alice",
                        birthDate: Date(timeIntervalSince1970: 645840000),
                        issueDate: Date(),
                        expiryDate: Date(timeIntervalSinceNow: 60 * 60 * 24 * 365 * 5),
                        issuingCountry: "UK",
                        issuingAuthority: "DVLA",
                        documentNumber: "DL123456789",
                        drivingPrivileges: [DrivingPrivilege(vehicleCategoryCode: "B")]
                    ))
                    isReady = true
                }
        }
    }
}
// Mock repository that simulates errors for preview testing
private actor ErrorThrowingCredentialRepository: CredentialRepository {
    enum PreviewError: Error {
        case simulatedLoadError
    }
    
    func save(_ document: MDLDocument) async throws {
        // Do nothing
    }
    
    func load() async throws -> MDLDocument? {
        // Throw an error to simulate failure
        throw PreviewError.simulatedLoadError
    }
    
    func delete() async throws {
        // Do nothing
    }
    
    func exists() async -> Bool {
        // Return true to trigger the load attempt
        return true
    }
}

