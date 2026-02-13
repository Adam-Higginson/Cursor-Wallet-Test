// KeychainCredentialRepository.swift
// Persists StoredCredential as raw CBOR bytes in the iOS/macOS Keychain.

import Foundation
import Security

/// Errors thrown by KeychainCredentialRepository when Keychain operations fail.
public enum KeychainCredentialRepositoryError: Error, Sendable, Equatable {
    case keychainError(OSStatus)
}

/// Backing store for credential bytes. Production uses Security framework; tests can inject an in-memory store to avoid simulator Keychain hangs.
public protocol CredentialDataStore: Sendable {
    func write(_ data: Data) async throws
    func read() async throws -> Data?
    func delete() async throws
    func exists() async -> Bool
}

private let keychainQueue = DispatchQueue(label: "dev.tuist.MDLWallet.keychain", qos: .userInitiated)

/// Security framework–backed store. Keychain API calls run on a background queue to avoid blocking.
public struct SecurityCredentialDataStore: CredentialDataStore, Sendable {
    public let service: String
    public let account: String

    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    public func write(_ data: Data) async throws {
        let service = self.service
        let account = self.account
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            keychainQueue.async {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account
                ]
                SecItemDelete(query as CFDictionary)
                let addQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecValueData as String: data,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                ]
                let status = SecItemAdd(addQuery as CFDictionary, nil)
                if status == errSecSuccess {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: KeychainCredentialRepositoryError.keychainError(status))
                }
            }
        }
    }

    public func read() async throws -> Data? {
        let service = self.service
        let account = self.account
        return try await withCheckedThrowingContinuation { continuation in
            keychainQueue.async {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]
                var resultObj: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &resultObj)
                switch status {
                case errSecSuccess:
                    continuation.resume(returning: resultObj as? Data)
                case errSecItemNotFound:
                    continuation.resume(returning: nil)
                default:
                    continuation.resume(throwing: KeychainCredentialRepositoryError.keychainError(status))
                }
            }
        }
    }

    public func delete() async throws {
        let service = self.service
        let account = self.account
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            keychainQueue.async {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account
                ]
                let status = SecItemDelete(query as CFDictionary)
                switch status {
                case errSecSuccess, errSecItemNotFound:
                    continuation.resume()
                default:
                    continuation.resume(throwing: KeychainCredentialRepositoryError.keychainError(status))
                }
            }
        }
    }

    public func exists() async -> Bool {
        let service = self.service
        let account = self.account
        return await withCheckedContinuation { continuation in
            keychainQueue.async {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecReturnData as String: false,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]
                var resultObj: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &resultObj)
                continuation.resume(returning: status == errSecSuccess)
            }
        }
    }
}

/// Persists the credential as raw CBOR. Uses `credentialCbor` when present, otherwise encodes the document.
/// Inject a `CredentialDataStore` in tests to avoid hitting the real Keychain (prevents simulator hangs).
public actor KeychainCredentialRepository: CredentialRepository {

    private let storage: any CredentialDataStore

    public init(service: String = "dev.tuist.MDLWallet.credential", account: String = "storedCredential") {
        self.storage = SecurityCredentialDataStore(service: service, account: account)
    }

    public init(storage: any CredentialDataStore) {
        self.storage = storage
    }

    public func save(_ credential: StoredCredential) async throws {
        let dataToStore: Data
        if let cbor = credential.credentialCbor {
            dataToStore = cbor
        } else {
            dataToStore = MDLDocumentCBORCoding.encode(credential.document)
        }
        try await storage.write(dataToStore)
    }

    public func load() async throws -> StoredCredential? {
        guard let data = try await storage.read() else { return nil }
        let decoded = try MDLDocumentCBORCoding.decodeStoredCredential(data)
        return StoredCredential(
            document: decoded.document,
            mso: decoded.mso,
            credentialCbor: data
        )
    }

    public func delete() async throws {
        try await storage.delete()
    }

    public func exists() async -> Bool {
        await storage.exists()
    }
}
