import SwiftUI

@main
struct MDLWalletApp: App {
    private let credentialRepository: CredentialRepository

    init() {
        self.credentialRepository = InMemoryCredentialRepository()
    }

    var body: some Scene {
        WindowGroup {
            ContentView(credentialRepository: self.credentialRepository)
        }
    }
}
