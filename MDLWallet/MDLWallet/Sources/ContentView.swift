import SwiftUI

public struct ContentView: View {
    // ───────────────────────────────────────────────────────────────────
    // MARK: Dependencies
    // ───────────────────────────────────────────────────────────────────
    private let credentialRepository: CredentialRepository
    private let oid4vciClient: OID4VCIClient

    // ───────────────────────────────────────────────────────────────────
    // MARK: State
    // ───────────────────────────────────────────────────────────────────
    @State private var currentCredential: MDLDocument? = nil
    @State private var isLoading = true
    @State private var isErrorLoadingCredential = false
    @State private var saveErrorMessage: String? = nil
    @State private var showScanner = false
    @State private var isIssuingCredential = false
    @State private var issuanceError: String? = nil

    public init(credentialRepository: CredentialRepository, oid4vciClient: OID4VCIClient) {
        self.credentialRepository = credentialRepository
        self.oid4vciClient = oid4vciClient
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if isLoading {
                    ProgressView("Checking for credentials...")
                } else if isIssuingCredential {
                    issuingView
                } else if currentCredential != nil {
                    credentialFoundView
                } else if isErrorLoadingCredential {
                    errorView
                } else {
                    emptyView
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
            .navigationTitle("MDL Wallet")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showScanner) {
                scannerSheet
            }
            .task {
                await checkForCredential()
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // MARK: Sub-views
    // ───────────────────────────────────────────────────────────────────

    private var credentialFoundView: some View {
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
    }

    private var errorView: some View {
        VStack(spacing: 16) {
            Text("Error when loading your MDL!")
                .font(.title)
                .fontWeight(.bold)
                .foregroundStyle(.red)
                .multilineTextAlignment(.center)

            Button {
                showScanner = true
            } label: {
                Label("Try Adding Credential Again", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .foregroundStyle(.white)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(.blue)
                    .cornerRadius(12)
            }
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.text.rectangle")
                .font(.system(size: 60))
                .foregroundStyle(.blue)

            Text("No MDL Found")
                .font(.title)
                .fontWeight(.bold)

            Text("Scan a QR code to add your mobile driver's license.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button {
                showScanner = true
            } label: {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
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

    private var issuingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)

            Text("Issuing Credential...")
                .font(.title3)
                .fontWeight(.semibold)

            Text("Contacting the issuer to retrieve your mobile driver's license.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let error = issuanceError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(8)
                    .background(.red.opacity(0.1))
                    .cornerRadius(8)

                Button {
                    issuanceError = nil
                    isIssuingCredential = false
                } label: {
                    Text("Dismiss")
                        .font(.headline)
                        .foregroundStyle(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(.gray)
                        .cornerRadius(12)
                }
            }
        }
    }

    private var scannerSheet: some View {
        NavigationStack {
            QRScannerView(
                onScan: { scannedString in
                    showScanner = false
                    handleScannedQR(scannedString)
                },
                onError: { error in
                    showScanner = false
                    saveErrorMessage = error
                }
            )
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        showScanner = false
                    }
                }
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // MARK: Actions
    // ───────────────────────────────────────────────────────────────────

    private func checkForCredential() async {
        isLoading = true
        if await credentialRepository.exists() {
            do {
                currentCredential = try await credentialRepository.load()
                isErrorLoadingCredential = false
            } catch {
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

    private func handleScannedQR(_ qrString: String) {
        isIssuingCredential = true
        issuanceError = nil
        saveErrorMessage = nil

        Task {
            do {
                // 1. Parse the credential offer from the QR code
                let offer = try CredentialOffer.parse(qrString)

                // 2. Run the OID4VCI issuance flow
                let credentialData = try await oid4vciClient.issueCredential(offer: offer)

                // 3. Store the raw credential bytes
                // For now, we store the credential data as-is.
                // In future, we would decode the mdoc and extract the MDLDocument.
                // For this phase, save a placeholder document indicating success.
                print("Received credential: \(credentialData.count) bytes")

                // Future: decode the mdoc credential into an MDLDocument.
                // For now, create a minimal document to indicate issuance succeeded.
                let document = MDLDocument(
                    familyName: "Issued",
                    givenName: "Via QR",
                    birthDate: Date(timeIntervalSince1970: 0),
                    issueDate: Date(),
                    expiryDate: Date(timeIntervalSinceNow: 60 * 60 * 24 * 365 * 5),
                    issuingCountry: "UK",
                    issuingAuthority: "OID4VCI Issuer",
                    documentNumber: "QR-\(credentialData.prefix(4).map { String(format: "%02X", $0) }.joined())",
                    drivingPrivileges: [DrivingPrivilege(vehicleCategoryCode: "B")]
                )

                try await credentialRepository.save(document)
                isIssuingCredential = false
                await checkForCredential()
            } catch {
                issuanceError = error.localizedDescription
                isIssuingCredential = false
                print("Issuance error: \(error)")
            }
        }
    }

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

#Preview("Empty Repository") {
    ContentView(
        credentialRepository: InMemoryCredentialRepository(),
        oid4vciClient: OID4VCIClient(httpClient: URLSessionHTTPClient())
    )
}

#Preview("With Credential") {
    PreviewHelperWithCredential()
}

#Preview("Error State") {
    ContentView(
        credentialRepository: ErrorThrowingCredentialRepository(),
        oid4vciClient: OID4VCIClient(httpClient: URLSessionHTTPClient())
    )
}

// Helper view for async preview setup
private struct PreviewHelperWithCredential: View {
    @State private var repository = InMemoryCredentialRepository()
    @State private var isReady = false

    var body: some View {
        if isReady {
            ContentView(
                credentialRepository: repository,
                oid4vciClient: OID4VCIClient(httpClient: URLSessionHTTPClient())
            )
        } else {
            ProgressView("Setting up preview...")
                .task {
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

    func save(_ document: MDLDocument) async throws {}
    func load() async throws -> MDLDocument? { throw PreviewError.simulatedLoadError }
    func delete() async throws {}
    func exists() async -> Bool { return true }
}
