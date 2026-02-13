import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

public struct ContentView: View {
    // ───────────────────────────────────────────────────────────────────
    // MARK: Dependencies
    // ───────────────────────────────────────────────────────────────────
    private let credentialRepository: CredentialRepository
    private let oid4vciClient: OID4VCIClient
    @Binding private var pendingCredentialOfferURL: URL?

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

    public init(
        credentialRepository: CredentialRepository,
        oid4vciClient: OID4VCIClient,
        pendingCredentialOfferURL: Binding<URL?> = .constant(nil)
    ) {
        self.credentialRepository = credentialRepository
        self.oid4vciClient = oid4vciClient
        self._pendingCredentialOfferURL = pendingCredentialOfferURL
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
            .onChange(of: pendingCredentialOfferURL) { _, url in
                guard let url else { return }
                pendingCredentialOfferURL = nil
                handleScannedQR(url.absoluteString)
            }
            .onAppear {
                // Handle cold start: app opened via openid-credential-offer:// link
                if let url = pendingCredentialOfferURL {
                    pendingCredentialOfferURL = nil
                    handleScannedQR(url.absoluteString)
                }
            }
            .task {
                await checkForCredential()
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // MARK: Sub-views
    // ───────────────────────────────────────────────────────────────────

    private static let mdlDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    private var credentialFoundView: some View {
        Group {
            if let doc = currentCredential {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // ISO 18013-5 §7.2.1: portrait (optional)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Photo")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                                .foregroundStyle(.secondary)
                            PortraitImageView(portraitData: doc.portrait)
                        }

                        // Mandatory elements (§7.2.1) in spec order
                        mdlAttributeRow(label: "Family name", value: doc.familyName)
                        mdlAttributeRow(label: "Given name", value: doc.givenName)
                        mdlAttributeRow(label: "Date of birth", value: Self.mdlDateFormatter.string(from: doc.birthDate))
                        mdlAttributeRow(label: "Issue date", value: Self.mdlDateFormatter.string(from: doc.issueDate))
                        mdlAttributeRow(label: "Expiry date", value: Self.mdlDateFormatter.string(from: doc.expiryDate))
                        mdlAttributeRow(label: "Issuing country", value: doc.issuingCountry)
                        mdlAttributeRow(label: "Issuing authority", value: doc.issuingAuthority)
                        mdlAttributeRow(label: "Document number", value: doc.documentNumber)

                        // Driving privileges (§7.2.4)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Driving privileges")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                                .foregroundStyle(.secondary)
                            ForEach(Array(doc.drivingPrivileges.enumerated()), id: \.offset) { _, privilege in
                                let codes = privilege.vehicleCategoryCode
                                let parts = [privilege.issueDate.map { "Issue: \(Self.mdlDateFormatter.string(from: $0))" }, privilege.expiryDate.map { "Expiry: \(Self.mdlDateFormatter.string(from: $0))" }].compactMap { $0 }
                                Text(parts.isEmpty ? codes : "\(codes) (\(parts.joined(separator: " · ")))")
                                    .font(.body)
                            }
                        }

                        // Optional elements (§7.2.1)
                        if let nationality = doc.nationality {
                            mdlAttributeRow(label: "Nationality", value: nationality)
                        }
                        if let ageOver18 = doc.ageOver18 {
                            mdlAttributeRow(label: "Age over 18", value: ageOver18 ? "Yes" : "No")
                        }
                        if let address = doc.residentAddress {
                            mdlAttributeRow(label: "Resident address", value: address)
                        }

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
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                }
            }
        }
    }

    private func mdlAttributeRow(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body)
        }
    }

    // MARK: - Portrait image (JPEG/JPEG2000 from mDL CBOR)

#if canImport(UIKit)
    private struct PortraitImageView: View {
        let portraitData: Data?

        var body: some View {
            Group {
                if let data = portraitData, let uiImage = UIImage(data: data) {
                    Image(uiImage: uiImage)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 120, height: 150)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3), lineWidth: 1))
                } else {
                    Image(systemName: "person.crop.rectangle.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                        .frame(width: 120, height: 150)
                        .background(Color.secondary.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            .frame(width: 120, height: 150)
        }
    }
#else
    private struct PortraitImageView: View {
        let portraitData: Data?

        var body: some View {
            Image(systemName: "person.crop.rectangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .frame(width: 120, height: 150)
                .background(Color.secondary.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
#endif

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
                let loaded = try await credentialRepository.load()
                currentCredential = loaded?.document
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
            var receivedCredentialData: Data?
            do {
                // 1. Parse the credential offer from the QR code
                let offer = try CredentialOffer.parse(qrString)

                // 2. Run the OID4VCI issuance flow
                let credentialData = try await oid4vciClient.issueCredential(offer: offer)
                receivedCredentialData = credentialData

                // 3. Decode into document + MSO and store that object; view renders the loaded credential.
                print("Received credential: \(credentialData.count) bytes")
                let stored = try MDLDocumentCBORCoding.decodeStoredCredential(credentialData)
                try await credentialRepository.save(stored)
                isIssuingCredential = false
                await checkForCredential()
            } catch {
                issuanceError = userFacingMessage(for: error)
                isIssuingCredential = true
                print("Issuance error: \(error)")
                if let decodeError = error as? MDLCBORDecodeError, let data = receivedCredentialData {
                    print("MDL decode reason: \(decodeError.reason)")
                    print("Credential CBOR top-level keys: \(MDLDocumentCBORCoding.describeCredentialStructure(data))")
                }
            }
        }
    }

    /// Returns a short, user-facing message for scan/issuance errors.
    private func userFacingMessage(for error: Error) -> String {
        switch error {
        case let e as CredentialOfferError:
            switch e {
            case .invalidScheme:
                return "This QR code isn’t a credential offer. Use a code from the document builder."
            case .missingCredentialOfferParameter:
                return "Invalid credential offer: missing data."
            case .invalidJSON:
                return "Invalid credential offer: the QR code may be damaged or from another app."
            case .missingPreAuthorizedCode:
                return "This credential offer doesn’t support the expected flow."
            }
        case let e as OID4VCIError:
            switch e {
            case .invalidIssuerURL:
                return "Invalid issuer address in the credential offer."
            case .invalidIssuerMetadata, .tokenEndpointNotFound:
                return "Could not reach the issuer. If you’re on a device, ensure it can reach the issuer (e.g. same Wi‑Fi as the server)."
            case .tokenRequestFailed(let msg), .credentialRequestFailed(let msg):
                return "Issuer returned an error: \(msg)"
            case .noCredentialInResponse, .invalidCredentialEncoding:
                return "The issuer didn’t return a valid credential."
            }
        case let e as MDLCBORDecodeError:
            return "Credential format error. Check Xcode console for details: \(e.reason)"
        case let e as HTTPClientError:
            if case .httpError(let code, let body) = e {
                if let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                   let msg = (json["error_description"] as? String) ?? (json["message"] as? String) {
                    return "Issuer returned an error: HTTP \(code) – \(msg)"
                }
                return "Issuer returned an error: HTTP \(code)."
            }
            return "Network request failed."
        default:
            return error.localizedDescription
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
                    let document = MDLDocument(
                        familyName: "Smith",
                        givenName: "Alice",
                        birthDate: Date(timeIntervalSince1970: 645840000),
                        issueDate: Date(),
                        expiryDate: Date(timeIntervalSinceNow: 60 * 60 * 24 * 365 * 5),
                        issuingCountry: "UK",
                        issuingAuthority: "DVLA",
                        documentNumber: "DL123456789",
                        drivingPrivileges: [DrivingPrivilege(vehicleCategoryCode: "B")]
                    )
                    try? await repository.save(StoredCredential(document: document))
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

    func save(_ credential: StoredCredential) async throws {}
    func load() async throws -> StoredCredential? { throw PreviewError.simulatedLoadError }
    func delete() async throws {}
    func exists() async -> Bool { return true }
}
