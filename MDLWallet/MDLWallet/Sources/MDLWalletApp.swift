import SwiftUI

@main
struct MDLWalletApp: App {
    private let credentialRepository: CredentialRepository
    private let oid4vciClient: OID4VCIClient

    init() {
        self.credentialRepository = InMemoryCredentialRepository()
        self.oid4vciClient = OID4VCIClient(httpClient: URLSessionHTTPClient())
    }

    var body: some Scene {
        WindowGroup {
            ContentView(
                credentialRepository: self.credentialRepository,
                oid4vciClient: self.oid4vciClient
            )
        }
    }
}
