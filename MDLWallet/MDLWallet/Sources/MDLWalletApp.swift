import SwiftUI

@main
struct MDLWalletApp: App {
    @State private var pendingCredentialOfferURL: URL?

    private let credentialRepository: CredentialRepository
    private let oid4vciClient: OID4VCIClient

    init() {
        self.credentialRepository = KeychainCredentialRepository()
        self.oid4vciClient = OID4VCIClient(httpClient: URLSessionHTTPClient())
    }

    var body: some Scene {
        WindowGroup {
            ContentView(
                credentialRepository: credentialRepository,
                oid4vciClient: oid4vciClient,
                pendingCredentialOfferURL: $pendingCredentialOfferURL
            )
            .onOpenURL { url in
                pendingCredentialOfferURL = url
            }
        }
    }
}
