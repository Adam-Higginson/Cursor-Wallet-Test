# mDL Wallet App: ISO 18013-5 Guide & Architecture

A learning-oriented guide to building a mobile digital license (mDL) wallet following **ISO/IEC 18013-5:2021**, for **native iOS with Swift**.

---

## 1. Key Components of ISO 18013-5 You Need to Implement

The standard defines **three interfaces**. Your wallet app is the **holder** side of **Interface 2** (holder ↔ reader). You also need to support **Interface 1** (issuer → holder) for *provisioning* the mDL. Here’s what each piece means and why it matters.

### 1.1 The Three Interfaces (Ecosystem View)

| Interface | Between | In scope of ISO 18013-5? | Your app’s role |
|-----------|---------|---------------------------|------------------|
| **1** | Issuing Authority (IA) ↔ mDL (holder device) | No (standard doesn’t define it) | **Yes** – you receive and store the mDL. Often done via OpenID4VCI or similar. |
| **2** | mDL ↔ mDL Reader | **Yes** – core of the standard | **Yes** – your app is the mDL; you present data to readers. |
| **3** | mDL Reader ↔ IA infrastructure | Yes | **No** – verifiers/readers talk to IAs; not the wallet’s job. |

**Why this matters:** Your implementation focuses on **storing** the mDL, **engaging** with readers (device retrieval), and **responding** with the right CBOR structures and signatures. Issuer-side and reader–IA flows are separate systems.

### 1.2 Data Model: mDL as an mDoc (CBOR)

The standard uses the **mDoc** (mobile document) model: a **CBOR**-encoded structure that can represent an mDL or other mobile identity documents.

- **Why CBOR:** Compact, binary, well-defined for constrained and mobile environments; same format for NFC/BLE and server retrieval.
- **Namespaces:** Data elements live in namespaces. For mDL, the main one is `org.iso.18013.5.1` (ISO-defined elements like `family_name`, `given_name`, `birth_date`, driving privileges).
- **Issuer-signed content:** The IA signs the document so any reader can verify **origin** and **integrity** without calling the IA for every read (offline-friendly).

**What you implement:** Decode/store CBOR mDocs, understand namespaces and requested items, and (for presentation) build responses in the same CBOR shape the standard expects.

### 1.3 Mobile Security Object (MSO)

The **MSO** is a signed object inside the mDL that carries:

- **Validity period** (validFrom / validUntil) – so readers know the credential is still in date.
- **Device key** – a public key bound to *this* device/instance; used for **device authentication** so the reader can tie the response to the same device that holds the mDL.
- **Issuer signature** – so the reader can verify the mDL came from a trusted IA (via **passive authentication**).

**Why it matters:** Your wallet doesn’t *create* the MSO (the issuer does), but it must **store it**, **expose it** as part of the mDoc, and use the **device private key** to sign **device-signed responses** when presenting. So you need secure storage for the device key pair and logic that builds the correct signed structures.

### 1.4 Device Engagement (How Reader and Holder Find Each Other)

Before any data flows, the **reader** and **holder** must agree on *how* to talk (transport) and *what* to use (keys/session).

- **Engagement methods:** Typically **QR code** (reader shows QR, holder scans) or **NFC** (holder taps phone to reader). The engagement payload carries things like reader ephemeral public key and connection details.
- **Transports for data retrieval:**  
  - **Device retrieval (offline):** BLE, NFC, or Wi‑Fi Aware – direct device-to-device.  
  - **Server retrieval (online):** Web API or OIDC – reader gets data via a server your app or the IA operates.

**What you implement:**  
- **QR:** Show a QR (holder-initiated) or scan reader’s QR, parse engagement, then run the chosen transport (often BLE).  
- **NFC:** Use **Core NFC** to advertise/respond when the reader taps.  
- **BLE:** Use **Core Bluetooth** (`CBPeripheralManager`) to implement the GATT peripheral (holder) role the standard specifies.

So: **device engagement** = “how we discover and agree”; **data retrieval** = “how we send the actual mDL data”.

### 1.5 Request / Response Flow (Interface 2)

1. **Reader request:** Reader sends a **request** that lists:
   - **Namespaces and data elements** it wants (e.g. `org.iso.18013.5.1`: `family_name`, `birth_date`).
   - For each element, whether it will **retain** the value (store it) or not – this drives **privacy** and UX (show “they will save your name”).
2. **Holder consent:** Your app shows the user what’s requested and whether it’s retained; user accepts or denies.
3. **Response:** You build a **response** that includes:
   - The requested **issuer-signed items** (from the mDoc) for those namespaces/elements.
   - A **device signature** over (at least) the engagement bytes, reader key, and handover – binding the response to this device and this session.

**What you implement:** Parse reader requests (CBOR), filter disclosed namespaces/items by consent, build the response CBOR, sign with the device key (e.g. **CryptoKit**), and send over the chosen transport (BLE/NFC).

### 1.6 Trust: Issuer Roots and Reader Trust

- **IACA (Issuing Authority CA):** Root of trust for the IA; its public key (or cert) is what readers use to verify the **issuer signature** on the mDL. Your wallet typically doesn’t need the full IA chain for *presentation*; the reader needs it.
- **mDL Master List / Trust Status List:** Standard way to distribute **trusted issuer** public keys/certs to readers (and optionally to wallets for UI/validation). Your app might use this to show “issued by a trusted DMV” or to validate before storing.

**What you implement:** For a **wallet**, you mainly need to **store** the issuer-signed mDoc and **device key**, and implement **device signing**. Trust of the IA is primarily a **reader** concern; optional in the wallet for UX.

### 1.7 Summary: What Your Wallet Must Do

| Component | Your responsibility |
|-----------|---------------------|
| **Provisioning (Interface 1)** | Receive mDL (e.g. OpenID4VCI), verify and store mDoc + device key in **Keychain**. |
| **Storage** | **Keychain** (or Secure Enclave) for mDoc (CBOR) and device key pair. |
| **Device engagement** | Support at least one method (e.g. QR + BLE or NFC) as per standard. |
| **Request handling** | Parse reader request CBOR; map to namespaces/data elements; enforce consent. |
| **Response building** | Build response with requested issuer-signed items + device signature (CBOR). |
| **Transport** | **Core Bluetooth** (CBPeripheralManager) and optionally **Core NFC** for device retrieval. |
| **Crypto** | **CryptoKit** for device key and signing; optionally verify issuer signature. |

---

## 2. Tech Stack: Native iOS (Swift)

Use Apple’s frameworks for crypto and transport; add CBOR and your own mDL request/response logic. There is no full ISO 18013-5 mDL library in Swift, so you combine CBOR + CryptoKit + Keychain and implement the standard’s data flows.

### 2.1 Core Stack

| Layer | Choice | Why |
|-------|--------|-----|
| **App framework** | **SwiftUI** (or UIKit) | Native iOS; SwiftUI keeps UI declarative and is the default for new apps. |
| **Language** | **Swift** | First-party support, strong typing, direct access to iOS frameworks. |
| **CBOR** | **SwiftCBOR** or **CBORCoding** (Swift Package Manager) | Swift CBOR encode/decode; you define Swift types for mDoc, request, and response and map to/from CBOR. |
| **Crypto** | **CryptoKit** | Apple’s crypto (P-256, ECDSA, hashing); use for device key (e.g. `P256.Signing`) and verifying issuer signatures. |
| **Secure storage** | **Keychain Services** (Security.framework) | Store device private key and mDoc via `SecItemAdd`/`SecItemCopyMatching`; use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and a dedicated service/account. |
| **BLE** | **Core Bluetooth** (`CoreBluetooth`) | **`CBPeripheralManager`** for the holder role: advertise the mDL service, expose GATT characteristics, respond to read/write from the reader (central). |
| **NFC** | **Core NFC** (`CoreNFC`) | For device engagement and/or data retrieval when the standard specifies NFC. |
| **QR** | **AVFoundation** / **Vision** | Scan reader’s QR for engagement; generate QR for holder-initiated engagement. |

### 2.2 Optional / Later

- **Secure Enclave:** Generate the device key with `SecKeyCreateRandomKey` and `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` so the private key never leaves the device; signing happens on-device. Requires non-exportable key.
- **Combine:** Use for async flows (provisioning, BLE events) if you prefer a reactive style.
- **Testing:** XCTest; mock `CBPeripheralManager` and Keychain to test mDL parsing and response building in isolation.

### 2.3 What to Avoid

- Implementing CBOR from scratch – use **SwiftCBOR** or **CBORCoding**.
- Storing the device private key in UserDefaults or a file – **Keychain** (or Secure Enclave) only.
- Skipping the “retain” flags in the reader request – required for privacy and standard compliance.

---

## 3. High-Level Architecture (iOS / Swift)

### 3.1 Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  UI Layer (SwiftUI)                                                      │
│  – Home (no mDL / mDL present)  – Provisioning flow  – Presentation UX  │
│  – Consent screen (requested items, retain)  – Settings / About          │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────────────────────────────────────────┐
│  Wallet / Use-Case Layer                                                 │
│  – ProvisioningService (fetch mDL, verify, store)                        │
│  – PresentationService (engagement → request → consent → response)       │
│  – CredentialRepository (load/save mDoc + metadata from Keychain)         │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────────────────────────────────────────┐
│  mDL / Standard Layer                                                    │
│  – Request parsing (CBOR)  – Response building (CBOR)  – Device signing   │
│  – Namespace / data element mapping  – MSO handling (read-only)          │
│  – Swift types + SwiftCBOR/CBORCoding                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────────────────────────────────────────┐
│  Transport & Crypto (Apple frameworks)                                   │
│  – Core Bluetooth (CBPeripheralManager)  – Core NFC  – AVFoundation QR     │
│  – CryptoKit (device key, signing)  – Keychain (key + mDoc)               │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Main Flows

**A. Provisioning (getting an mDL)**  
1. User logs in / proves identity to issuer (out of scope of ISO 18013-5).  
2. App calls issuer’s **OpenID4VCI** (or similar) endpoint; receives mDL as a verifiable credential / signed mDoc.  
3. **ProvisioningService** decodes mDoc (CBOR), optionally verifies issuer signature with CryptoKit, generates or receives **device key pair**, stores **mDoc + device private key** in **CredentialRepository** (Keychain).  
4. UI shows “mDL added” and optional details (e.g. issuer, validity).

**B. Presentation (reader requests data)**  
1. **Device engagement:** Reader shows QR (or NFC tap). App scans QR (or receives NFC) and gets reader ephemeral key + transport info.  
2. **Transport:** App uses **CBPeripheralManager** to advertise and accept BLE connection from reader (or Core NFC if using NFC path).  
3. **Request:** Reader sends request CBOR. **PresentationService** parses it (namespace + items + retain flags).  
4. **Consent:** UI shows “Reader wants: name, DoB; will retain: name”. User approves or denies.  
5. **Response:** **PresentationService** builds response: selected issuer-signed items + **device signature** (CryptoKit) over engagement, reader key, handover. Encode as CBOR.  
6. Send response over BLE (or NFC). Reader verifies issuer + device signature and uses the data.

### 3.3 Data You Store (Minimal)

- **mDoc** (CBOR blob) – issuer-signed; contains namespaces, data elements, MSO. Stored in Keychain.
- **Device key pair** – generated at provisioning (or provided by issuer); private key in Keychain or Secure Enclave only.
- **Metadata** (optional) – issuer name, validity, doc type – for UI only; can be derived from mDoc when needed.

You do **not** need to store the full IA PKI; that’s for readers.

### 3.4 Security and Privacy Notes

- **Consent:** Always show requested elements and “retain” before sending; central to the standard’s privacy model.  
- **Device key:** Never export the device private key; use it only in secure code (Keychain/Secure Enclave).  
- **Storage:** mDoc in Keychain; optionally encrypt with a key derived from device key or user auth if you need an extra layer.

---

## 4. Learning Order (iOS / Swift)

1. **Read** the ISO 18013-5 summary and clause 7 (data model) if you have access; otherwise use Kantara PImDL and STA/MATTR/Spruce docs.  
2. **Add SwiftCBOR** (or CBORCoding) via SPM; decode a sample mDoc CBOR and map to Swift structs.  
3. **Scaffold** the iOS app (SwiftUI); implement **Keychain** read/write for a test mDoc blob and device key.  
4. **Implement CBPeripheralManager:** advertise the mDL service, add the required GATT characteristics, handle read/write from a central (reader simulator or second device).  
5. **Wire** device engagement (e.g. QR scan) → BLE connection → request parsing → consent UI → response building with **CryptoKit** device signature → send response.  
6. **Add** Core NFC for NFC-based engagement/presentation if needed.

Good next step: create an Xcode project, add SwiftCBOR via SPM, and implement **CredentialRepository** + Keychain so you can store and load one test mDoc.
