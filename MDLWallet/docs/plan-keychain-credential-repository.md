# Plan: Keychain-backed credential repository

## Goal

Add a new `KeychainCredentialRepository` that persists `StoredCredential` (document + optional MSO) to the iOS Keychain so the credential survives app restarts. The app will use this repository instead of (or configurable with) `InMemoryCredentialRepository`.

---

## Keychain concept: where is the data, and is it encrypted?

**Where is the data saved?**

- The **Keychain** is a secure storage system provided by the OS (iOS/macOS). It is **not** a normal file in your app’s sandbox.
- When you call `SecItemAdd` with a password/item (e.g. `kSecClassGenericPassword`), the system stores that item in a **Keychain database** managed by the OS. On iOS this is in a protected system area; on device it can use the **Secure Enclave** (hardware-backed) for key material. The actual bytes you pass in are stored in this database, not in your app’s Documents or Caches directory.
- So “where” = **in the system Keychain**, keyed by your app’s bundle ID (and the service/account you choose). Other apps cannot read it; the same app can read it across launches and (depending on accessibility) after device restart.

**Are we encrypting the data?**

- **Yes, but the system does it.** You don’t call an encryption API yourself. The OS encrypts Keychain items at rest. The encryption keys are protected by the Secure Enclave (on supported devices) and by the user’s device passcode / biometrics when you use accessibility options that require them.
- **kSecAttrAccessible** controls *when* the item can be used:
  - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: decryptable only when the device is unlocked; not synced to other devices. Good default for a credential.
  - Other options (e.g. `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) can tie availability to passcode or biometrics (see Biometrics section below).
- So: we store **plain** `Data` (our serialized credential) into the Keychain; the **system** encrypts it at rest and only returns it to our process when the accessibility conditions are met. We are not manually encrypting/decrypting in app code.

---

## Biometrics: should we bind the credential to Face ID / Touch ID now?

**What “biometric binding” means here**

- We can make the Keychain item available only when the user passes a **Local Authentication** (Face ID / Touch ID) check. Two common approaches:
  1. **Accessibility flag:** Use an option like `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` so the item is only available when the device is unlocked (unlock already requires passcode or biometric). That gives “device bound” but not “every read requires biometric”.
  2. **Require biometric on every read:** Before each `load()`, call `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`. If the user fails or cancels, we don’t call Keychain and return nil (or an error). The credential isn’t “stored with” the biometric in the cryptographic sense; we just **gate access** to the Keychain with a biometric check.
  3. **Data Protection + “secure in background”:** We could also combine Keychain accessibility with app-level behaviour (e.g. clear in-memory credential when app goes to background) for extra assurance.

**Recommendation: do Keychain first, add biometric gating as a follow-up**

- **Now:** Implement the Keychain repository with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Credential is encrypted at rest and only available when the device is unlocked. No extra UI or Local Authentication flow.
- **Later (optional):** Add “require Face ID / Touch ID to view credential” by calling `LAContext.evaluatePolicy` before loading and only then calling the repository. That keeps this PR smaller and lets you test persistence first, then add biometric gating in a separate change.

If you prefer biometric gating in this same feature, the plan can add: “Before `load()`, evaluate `.deviceOwnerAuthenticationWithBiometrics`; on failure/cancel return nil or throw; on success call Keychain and return credential.” And in the UI, trigger a load (e.g. “View credential”) that triggers this flow.

---

## Step 1: Branch from main

- Checkout `main`, pull latest.
- Create branch e.g. `feat/keychain-credential-repository`.
- All changes happen on this branch.
- *(Already done.)*

---

## Step 2: Persist raw credential CBOR (no JSON)

We store the **same CBOR bytes** we receive from the issuer. No JSON, no re-serialization of document or MSO into a different format. The credential is already CBOR; we keep it as CBOR in the Keychain.

**Carry raw bytes on StoredCredential**

- Add an optional `credentialCbor: Data?` to `StoredCredential`. When we receive the credential from the issuer we have the raw `Data`; we decode to document + MSO and attach the bytes: `StoredCredential(document: doc, mso: mso, credentialCbor: credentialData)`.
- **Save path:** When persisting, if `credentialCbor != nil`, write that `Data` directly to the Keychain. If `credentialCbor == nil` (e.g. preview with a constructed credential), encode the document with existing `MDLDocumentCBORCoding.encode(document)` and persist that (simple namespace form; no MSO in that case).
- **Load path:** Read `Data` from the Keychain, decode with `MDLDocumentCBORCoding.decodeStoredCredential(data)` to get `StoredCredential`. Set `credentialCbor` on the decoded result to that same `Data` so future saves keep using the original bytes (no re-encode drift).

**No Codable, no JSON**

- We do **not** add Codable to `MDLDocument`, `DrivingPrivilege`, or any MSO types for persistence. The persistence format is CBOR only.
- Existing APIs: `decodeStoredCredential(_ data: Data)`, `encode(_ document: MDLDocument) -> Data`. No new encoding of full IssuerSigned (nameSpaces + issuerAuth) is required for the normal path, because we always persist the bytes we received.

**Issuance flow change**

- When the app receives `credentialData` from the credential endpoint, build `StoredCredential(document: doc, mso: mso, credentialCbor: credentialData)` (instead of omitting the third parameter), then call `save(stored)`. That way the repository has the raw bytes to persist.

---

## Step 3: Keychain API usage

- Use the **Security** framework (`import Security`).
- **Service name:** e.g. `"dev.tuist.MDLWallet.credential"` (or your bundle ID + `.credential`).
- **Account:** e.g. `"storedCredential"` (single credential per app).
- **Operations:**
  - **Save:** Get the credential bytes to persist: if `storedCredential.credentialCbor != nil` use that; else `MDLDocumentCBORCoding.encode(document)`. Then `SecItemAdd` with `kSecClassGenericPassword`, `kSecAttrService`, `kSecAttrAccount`, `kSecValueData` = that `Data`, and `kSecAttrAccessible` (e.g. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). If item already exists, call `SecItemDelete` then `SecItemAdd`, or use `SecItemUpdate` if we first query.
  - **Load:** `SecItemCopyMatching` with same service/account, get `kSecValueData` as `Data`, then decode with `MDLDocumentCBORCoding.decodeStoredCredential(data)` to get `StoredCredential?` (and set `credentialCbor` on the result). If no item found, return `nil`.
  - **Delete:** `SecItemDelete` with same service/account.
  - **Exists:** Same as load but only check whether `SecItemCopyMatching` returns an item (or call load and return `loaded != nil`).
- Handle **errors**: `errSecItemNotFound` for “no credential” is normal; surface other `OSStatus` as a thrown error (e.g. a small `KeychainCredentialRepositoryError` enum).
- **Thread safety:** Keychain APIs are process-safe. The repository can be an `actor` (like `InMemoryCredentialRepository`) so all calls are serialized and we avoid re-entrancy.

---

## Step 4: KeychainCredentialRepository implementation

- **Location:** e.g. `MDLWallet/Sources/Storage/KeychainCredentialRepository.swift`.
- **Conformance:** `CredentialRepository` (same as `InMemoryCredentialRepository`).
- **Actor:** `public actor KeychainCredentialRepository: CredentialRepository`.
- **Dependencies:** None required; use a fixed service/account or inject for tests (optional).
- **Methods:**
  - `save(_ credential: StoredCredential) async throws` → credential bytes from `credential.credentialCbor` or `encode(credential.document)`, then Keychain add (replace if exists).
  - `load() async throws -> StoredCredential?` → Keychain copy, decode with `decodeStoredCredential`, attach `credentialCbor` to result, return.
  - `delete() async throws` → Keychain delete.
  - `exists() async -> Bool` → implement via load or direct SecItemCopyMatching and check for item.
- Keep all Keychain and persistence (CBOR bytes) logic inside this type (or a small private helper). No changes to the `CredentialRepository` protocol.

---

## Step 5: Wire into the app

- **MDLWalletApp** (or wherever the app root is): Replace `InMemoryCredentialRepository()` with `KeychainCredentialRepository()` when creating `ContentView` (and any other consumer of `CredentialRepository`). Optionally make this configurable (e.g. debug = in-memory, release = Keychain) later.
- **Previews:** Keep using `InMemoryCredentialRepository()` in SwiftUI previews so they don’t touch Keychain. No change to `ErrorThrowingCredentialRepository` mock.

---

## Step 6: Tests

- **Unit tests for KeychainCredentialRepository:**
  - Use a **test-only service/account** (e.g. `"dev.tuist.MDLWallet.credential.test"` and `"test"`) so we don’t pollute the real Keychain, and delete in tear-down.
  - Tests: save then load returns same credential; delete then load returns nil; exists returns true/false as expected; save overwrites previous.
- **Persistence:** Add tests that round-trip credential CBOR: save credential (with `credentialCbor` set), load, assert decoded document and MSO match; test save without `credentialCbor` (encode document only) and load.
- **InMemoryCredentialRepository** tests stay as-is; they still validate the protocol contract for the in-memory implementation.

---

## Step 7: Edge cases and security

- **Accessibility:** Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or similar) so the item is only available when the device is unlocked and doesn’t sync to other devices.
- **Large payloads:** Keychain can handle documents of typical mDL size. If we ever support very large credentials, consider size checks or chunking (out of scope for initial implementation).
- **Migration:** If we later change the serialization format, we can add a version byte or key and migrate in load(); not required for the first version.

---

## File and dependency summary

| Action | File / area |
|--------|-------------|
| Branch | `feat/keychain-credential-repository` (from main) |
| Model change | `StoredCredential`: add optional `credentialCbor: Data?`; no Codable; persist raw CBOR only |
| New | `KeychainCredentialRepository.swift` (actor, Security framework, uses serialization above) |
| Change | `MDLWalletApp.swift` (use `KeychainCredentialRepository()` instead of `InMemoryCredentialRepository()`); `ContentView` issuance: build `StoredCredential(..., credentialCbor: credentialData)` so raw bytes are persisted |
| New tests | `KeychainCredentialRepositoryTests.swift` (save/load/delete/exists, test service/account) |
| Optional | CBOR round-trip test: save with `credentialCbor` set, load, assert document/MSO match |
| Later | Biometric gating (LAContext before load) if desired |

No new dependencies: Security and Foundation only (no JSON for persistence).

---

## Order of implementation

1. Create branch from main.
2. Add `credentialCbor: Data?` to `StoredCredential`; issuance flow sets it; Keychain save/load uses raw CBOR only.
3. Implement `KeychainCredentialRepository` (actor, Security, same protocol).
4. Add unit tests for repository and optionally for serialization.
5. Switch app and previews wiring (Keychain in app, keep in-memory in previews).
6. Run app and SwiftLint; fix any issues.
