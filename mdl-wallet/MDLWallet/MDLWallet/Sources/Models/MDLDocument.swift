// MDLDocument.swift
// Core data model for an mDL (mobile driver's license).
//
// Maps to the mandatory and optional data elements defined in
// ISO 18013-5 §7.2.1, namespace "org.iso.18013.5.1".

import Foundation

// ═══════════════════════════════════════════════════════════════════════
// MARK: - MDLDocument
// ═══════════════════════════════════════════════════════════════════════
//
// Swift Concept: STRUCT vs CLASS
// ─────────────────────────────────────────────────────────────────────
// We use a struct, not a class. Here's why:
//
// In Java, everything is a class (reference type, heap-allocated).
// In TypeScript, you'd typically use an interface + plain object.
// In Swift, you choose:
//
//   struct  → Value type (copied on assignment, like an int).
//             No inheritance. Automatically thread-safe.
//             Preferred for data/models in Swift.
//
//   class   → Reference type (shared pointer, like Java objects).
//             Supports inheritance. Needs care for thread safety.
//             Use for identity-based objects (e.g., a BLE manager).
//
// MDLDocument is pure data — no identity, no inheritance needed.
// Making it a struct means:
//   let a = doc
//   var b = a       // b is a full COPY; changing b doesn't touch a
//
// Java analogy:    Imagine if every object was auto-cloned on assignment.
// TS analogy:      Like spreading { ...obj } but enforced by the compiler.
//
// Swift Concept: Sendable
// ─────────────────────────────────────────────────────────────────────
// Sendable tells the compiler this type is safe to pass between threads
// (concurrency contexts). Structs with only Sendable properties conform
// automatically, but marking it explicitly is good practice — it makes
// the intent clear and the compiler will enforce it.
// Java analogy: roughly like implementing Serializable, but for threads.

/// An mDL document representing a mobile driver's license.
/// Contains both mandatory and optional data elements as defined
/// by ISO 18013-5 §7.2.1.
public struct MDLDocument: Sendable, Equatable {

    // ─────────────────────────────────────────────────────────────
    // MARK: Required fields (ISO 18013-5 §7.2.1 mandatory elements)
    // ─────────────────────────────────────────────────────────────
    //
    // Swift Concept: "let" properties in a struct
    // All of these are "let" (immutable). Once you create an
    // MDLDocument, you can't change its familyName — you'd create
    // a new one instead. This is the same philosophy as:
    //   Java: record MDLDocument(String familyName, ...) { }
    //   TS:   Readonly<MDLDocument>
    //
    // Why immutable? An mDL comes from an issuer, signed. You
    // shouldn't be mutating the data after issuance.

    /// Family name (surname) of the license holder.
    /// ISO element: "family_name"
    public let familyName: String

    /// Given name (first name) of the license holder.
    /// ISO element: "given_name"
    public let givenName: String

    /// Date of birth of the license holder.
    /// ISO element: "birth_date"
    public let birthDate: Date

    /// Date the document was issued.
    /// ISO element: "issue_date"
    public let issueDate: Date

    /// Date the document expires.
    /// ISO element: "expiry_date"
    public let expiryDate: Date

    /// Two-letter country code (ISO 3166-1 alpha-2) of the issuing country.
    /// ISO element: "issuing_country"
    public let issuingCountry: String

    /// Name of the authority that issued the document.
    /// ISO element: "issuing_authority"
    public let issuingAuthority: String

    /// Unique document identifier assigned by the issuing authority.
    /// ISO element: "document_number"
    public let documentNumber: String

    /// Vehicle categories the holder is authorized to drive.
    /// ISO element: "driving_privileges"
    public let drivingPrivileges: [DrivingPrivilege]

    // ─────────────────────────────────────────────────────────────
    // MARK: Optional fields (ISO 18013-5 §7.2.1 optional elements)
    // ─────────────────────────────────────────────────────────────
    //
    // Swift Concept: Optionals (the ? suffix)
    //
    // In TypeScript:   portrait?: Uint8Array      // can be undefined
    // In Java:         @Nullable byte[] portrait   // can be null
    // In Swift:        let portrait: Data?          // can be nil
    //
    // The "?" means "this might be nil." The compiler forces you to
    // handle both cases before using the value. You can't accidentally
    // call .count on a nil Data? — it won't compile.
    //
    // This is Swift's biggest safety feature vs Java's NullPointerException
    // and TypeScript's "undefined is not an object."

    /// Portrait photo (JPEG or JPEG2000 bytes).
    /// ISO element: "portrait"
    public let portrait: Data?

    /// Nationality of the holder.
    /// ISO element: "nationality"
    public let nationality: String?

    /// Whether the holder is over 18.
    /// ISO element: "age_over_18"
    public let ageOver18: Bool?

    /// Residential address of the holder.
    /// ISO element: "resident_address"
    public let residentAddress: String?

    // ─────────────────────────────────────────────────────────────
    // MARK: Initializer
    // ─────────────────────────────────────────────────────────────
    //
    // Swift Concept: Why we need an explicit public init
    //
    // Swift structs get a free "memberwise initializer" that takes
    // every property as a parameter. BUT that auto-generated init
    // is always "internal" — code outside this module can't use it.
    //
    // Since MDLDocument is public, we must write a public init.
    // Putting it HERE (inside the struct body) tells Swift: "don't
    // generate the memberwise init, I'm providing my own."
    //
    // If we tried putting this in an extension with the same
    // signature, it would collide with the synthesized one.
    //
    // Common Swift gotcha for newcomers!

    public init(
        familyName: String,
        givenName: String,
        birthDate: Date,
        issueDate: Date,
        expiryDate: Date,
        issuingCountry: String,
        issuingAuthority: String,
        documentNumber: String,
        drivingPrivileges: [DrivingPrivilege],
        portrait: Data? = nil,
        nationality: String? = nil,
        ageOver18: Bool? = nil,
        residentAddress: String? = nil
    ) {
        self.familyName = familyName
        self.givenName = givenName
        self.birthDate = birthDate
        self.issueDate = issueDate
        self.expiryDate = expiryDate
        self.issuingCountry = issuingCountry
        self.issuingAuthority = issuingAuthority
        self.documentNumber = documentNumber
        self.drivingPrivileges = drivingPrivileges
        self.portrait = portrait
        self.nationality = nationality
        self.ageOver18 = ageOver18
        self.residentAddress = residentAddress
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: Computed properties
    // ─────────────────────────────────────────────────────────────
    //
    // Swift Concept: Computed properties
    // Like Java's getter methods or TypeScript's get accessors,
    // but declared as properties (no parentheses when called).
    //
    // Java:        public boolean isExpired() { return ...; }
    // TypeScript:  get isExpired(): boolean { return ...; }
    // Swift:       var isExpired: Bool { ... }
    //
    // Called as: doc.isExpired (not doc.isExpired())

    /// Whether the document has passed its expiry date.
    public var isExpired: Bool {
        expiryDate < Date.now
    }

    /// Full display name: "Given Family".
    public var fullName: String {
        "\(givenName) \(familyName)"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Validation
// ═══════════════════════════════════════════════════════════════════════
//
// Swift Concept: Extensions
// ─────────────────────────────────────────────────────────────────────
// Extensions add functionality to an existing type WITHOUT modifying
// the original definition. Think of it as:
//   Java: You can't do this (you'd use a utility class or inherit).
//   TS:   Like declaration merging, but more structured.
//
// We put validate() in an extension to keep the struct definition
// focused on data, and group behavior separately. This is common
// Swift style — organize by concern, not by putting everything in
// one block.

extension MDLDocument {

    /// Validates the document's data for basic consistency.
    /// Throws `MDLDocumentError` describing what's wrong.
    ///
    /// Swift Concept: "throws"
    /// ─────────────────────────────────────────────────────────────
    /// Functions marked "throws" can throw errors. The caller MUST use
    /// "try" when calling them. This is similar to Java's checked
    /// exceptions but lighter:
    ///   Java:  void validate() throws ValidationException { ... }
    ///   TS:    No equivalent (you'd just throw and hope callers catch)
    ///   Swift: func validate() throws { ... }
    ///
    /// Callers do: try doc.validate()
    /// Or:         do { try doc.validate() } catch { print(error) }
    public func validate() throws {
        // Swift Concept: guard
        // ─────────────────────────────────────────────────────────
        // "guard" is like an inverted "if" that MUST exit the current
        // scope (return, throw, break, etc.) in its else clause.
        // It's idiomatic Swift for "bail out early if precondition fails."
        //
        // Instead of deeply nested if-else chains (common in Java),
        // Swift code reads top-down with guards:
        //   guard precondition else { throw/return }
        //   guard precondition else { throw/return }
        //   // Happy path continues un-indented

        guard !familyName.isEmpty else {
            throw MDLDocumentError.emptyField("familyName")
        }

        guard !givenName.isEmpty else {
            throw MDLDocumentError.emptyField("givenName")
        }

        guard !documentNumber.isEmpty else {
            throw MDLDocumentError.emptyField("documentNumber")
        }

        guard !issuingAuthority.isEmpty else {
            throw MDLDocumentError.emptyField("issuingAuthority")
        }

        guard !drivingPrivileges.isEmpty else {
            throw MDLDocumentError.emptyDrivingPrivileges
        }

        // ISO 3166-1 alpha-2: exactly 2 uppercase ASCII letters
        guard issuingCountry.count == 2,
              issuingCountry.allSatisfy({ $0.isUppercase && $0.isASCII }) else {
            throw MDLDocumentError.invalidCountryCode(issuingCountry)
        }

        guard expiryDate > issueDate else {
            throw MDLDocumentError.expiryBeforeIssue
        }
        
        guard birthDate < Date.now else {
            throw MDLDocumentError.birthdateInFuture
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - DrivingPrivilege
// ═══════════════════════════════════════════════════════════════════════
//
// ISO 18013-5 §7.2.4: Each entry in driving_privileges has at minimum
// a vehicle_category_code (e.g. "A", "B", "C", "D").

/// A single driving privilege (vehicle category authorization).
public struct DrivingPrivilege: Sendable, Equatable {

    /// Vehicle category code (e.g. "B" for standard passenger vehicles).
    public let vehicleCategoryCode: String

    /// Date from which this privilege is valid (optional).
    public let issueDate: Date?

    /// Date this privilege expires (optional).
    public let expiryDate: Date?

    // Swift Concept: Memberwise initializer with defaults
    // ─────────────────────────────────────────────────────────────
    // Swift auto-generates an initializer for structs (the "memberwise
    // init") — but ONLY if you don't write one yourself AND only for
    // internal access. Since we marked properties as "public", we need
    // an explicit public init.
    //
    // Default parameter values (= nil) let callers omit those arguments:
    //   DrivingPrivilege(vehicleCategoryCode: "B")         // OK
    //   DrivingPrivilege(vehicleCategoryCode: "B", ...)    // Also OK
    //
    // Java doesn't have default parameters (you'd overload).
    // TypeScript does: function foo(x: string, y?: Date) { ... }

    public init(
        vehicleCategoryCode: String,
        issueDate: Date? = nil,
        expiryDate: Date? = nil
    ) {
        self.vehicleCategoryCode = vehicleCategoryCode
        self.issueDate = issueDate
        self.expiryDate = expiryDate
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - MDLDocumentError
// ═══════════════════════════════════════════════════════════════════════
//
// Swift Concept: Enums for errors
// ─────────────────────────────────────────────────────────────────────
// In Java, you'd create a class hierarchy:
//   class ValidationException extends Exception { ... }
//   class EmptyFieldException extends ValidationException { ... }
//
// In Swift, errors are typically enums. Each case is a distinct error.
// Enums in Swift are MUCH more powerful than Java enums — they can
// carry associated values (data attached to each case).
//
//   Java:  new EmptyFieldException("familyName")   ← need a whole class
//   Swift: .emptyField("familyName")                ← one line in an enum
//
// The "Error" protocol is like Java's Exception interface — it marks
// this type as throwable.

/// Errors that can occur when validating an `MDLDocument`.
public enum MDLDocumentError: Error, Sendable {
    /// A required string field is empty.
    case emptyField(String)

    /// The driving privileges array is empty (at least one required).
    case emptyDrivingPrivileges

    /// The issuing country code is not a valid 2-letter ISO 3166-1 alpha-2 code.
    case invalidCountryCode(String)

    /// The expiry date is before the issue date.
    case expiryBeforeIssue
    
    /// The birth date is in the future.
    case birthdateInFuture
}

