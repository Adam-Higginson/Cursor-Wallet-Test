// MDLDocumentTests.swift
// TDD: We write these tests FIRST, before MDLDocument exists.
// They won't compile until we create the model. That's the point.

import Testing
import Foundation  // For Date, Calendar, etc.
@testable import MDLWallet

// MARK: - Swift Concept: @Suite
// ─────────────────────────────────────────────────────────────────────
// @Suite groups related tests, like Jest's `describe` or JUnit 5's @Nested.
// Unlike XCTest (which requires a CLASS inheriting from XCTestCase),
// Swift Testing uses a plain STRUCT. This is idiomatic Swift:
// prefer value types (structs) over reference types (classes).
//
// Java equivalent:   @Nested class InitializationTests { ... }
// Jest equivalent:   describe('Initialization', () => { ... })
// Swift Testing:     @Suite struct Initialization { ... }

@Suite("MDLDocument")
struct MDLDocumentTests {

    // ═══════════════════════════════════════════════════════════════════
    // MARK: - Initialization with Required Fields
    // ═══════════════════════════════════════════════════════════════════
    // ISO 18013-5 §7.2.1 defines mandatory data elements in the
    // "org.iso.18013.5.1" namespace. These must always be present.
    
    @Suite("Initialisation")
    struct Initialisation {

        // Swift Concept: @Test + display name
        // ─────────────────────────────────────────────────────────────
        // The string in @Test("...") is a human-readable label shown
        // in test results. Like JUnit's @DisplayName or Jest's test description.
        
        @Test("creates document with all required fields")
        func initWithRequiredFields() {
            // GIVEN: Valid data for all mandatory ISO 18013-5 fields
            // ─────────────────────────────────────────────────────────
            // Swift Concept: "let" vs "var"
            //   let = immutable (like Java's final or TS's const)
            //   var = mutable (like Java's non-final or TS's let)
            // Always prefer "let" unless you need to mutate.
            
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "UK",
                issuingAuthority: "DVLA",
                documentNumber: "DL123456789",
                // ISO 18013-5 §7.2.4: driving_privileges is an array of
                // vehicle categories the holder is authorized to drive.
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            // THEN: All properties should be set correctly
            // ─────────────────────────────────────────────────────────
            // Swift Testing: #expect(expression)
            //   Unlike XCTAssertEqual(a, b), you write a plain expression.
            //   If it fails, Swift shows you what both sides actually were.
            //
            //   Jest equivalent:     expect(doc.familyName).toBe("Smith")
            //   JUnit equivalent:    assertEquals("Smith", doc.getFamilyName())
            //   Swift Testing:       #expect(doc.familyName == "Smith")
            
            #expect(doc.familyName == "Smith")
            #expect(doc.givenName == "Alice")
            #expect(doc.documentNumber == "DL123456789")
            #expect(doc.issuingCountry == "UK")
            #expect(doc.issuingAuthority == "DVLA")
            #expect(doc.drivingPrivileges.count == 1)
            #expect(doc.drivingPrivileges[0].vehicleCategoryCode == "B")
        }

        @Test("optional fields default to nil")
        func initOptionalFieldsNil() {
            // GIVEN: A document with only required fields
            let doc = TestHelpers.makeMinimalDocument()
            
            // THEN: Optional fields should be nil
            // ─────────────────────────────────────────────────────────
            // Swift Concept: Optionals
            //   In TypeScript: middleName?: string     (undefined if not set)
            //   In Java:       @Nullable String        (null if not set)
            //   In Swift:      var middleName: String?  (nil if not set)
            //
            // Swift forces you to handle the "might be absent" case at
            // compile time. You can't accidentally call .count on a nil
            // String? without the compiler stopping you.
            
            #expect(doc.portrait == nil)
            #expect(doc.nationality == nil)
            #expect(doc.ageOver18 == nil)
            #expect(doc.residentAddress == nil)
        }

        @Test("creates document with optional fields populated")
        func initWithOptionalFields() {
            // GIVEN: A document with both required and optional fields
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ],
                // Optional fields
                portrait: Data([0xFF, 0xD8, 0xFF]),  // JPEG header bytes
                nationality: "US",
                ageOver18: true,
                residentAddress: "123 Main St, Sacramento, CA"
            )

            // THEN
            // ─────────────────────────────────────────────────────────
            // Swift Concept: != nil check
            //   #expect(doc.portrait != nil) — verifies it's not nil.
            //   We'll look at unwrapping (if let, guard let) when we
            //   write implementation code.
            
            #expect(doc.portrait != nil)
            #expect(doc.nationality == "US")
            #expect(doc.ageOver18 == true)
            #expect(doc.residentAddress == "123 Main St, Sacramento, CA")
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // MARK: - Validation
    // ═══════════════════════════════════════════════════════════════════
    // The standard doesn't strictly define validation rules in the holder,
    // but a good wallet should sanity-check before storing.

    @Suite("Validation")
    struct Validation {
        
        @Test("valid document passes validation")
        func validDocumentPasses() throws {
            // Swift Concept: "throws" in test signature
            // ─────────────────────────────────────────────────────────
            // If validate() throws an error, Swift Testing will catch it
            // and fail the test with the error message. You don't need
            // a try/catch block — just mark the test func as "throws".
            //
            // JUnit equivalent:  @Test void foo() throws Exception { ... }
            // Jest equivalent:    expect(() => validate()).not.toThrow()
            
            let doc = TestHelpers.makeMinimalDocument()
            
            // This should NOT throw. If it does, the test fails automatically.
            try doc.validate()
        }
        
        @Test("rejects empty family name")
        func rejectsEmptyFamilyName() {
            let doc = MDLDocument(
                familyName: "",  // Invalid!
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            // Swift Concept: #expect(throws:) { ... }
            // ─────────────────────────────────────────────────────────
            // Verifies that the closure throws a specific error type.
            //   Jest:  expect(() => doc.validate()).toThrow(ValidationError)
            //   JUnit: assertThrows(ValidationError.class, () -> doc.validate())
            //   Swift: #expect(throws: MDLDocumentError.self) { try doc.validate() }
            
            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }
        
        @Test("rejects empty given name")
        func rejectsEmptyGivenName() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "",  // Invalid!
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }

        @Test("rejects empty document number")
        func rejectsEmptyDocumentNumber() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "",  // Invalid!
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }

        @Test("rejects expiry date before issue date")
        func rejectsExpiryBeforeIssue() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2023, month: 1, day: 1),  // Before issue!
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )

            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }
        
        @Test("rejects empty driving privileges")
        func rejectsEmptyDrivingPrivileges() {
            // ISO 18013-5: driving_privileges is mandatory and must have at least one entry
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: []  // Invalid!
            )

            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }
        
        @Test("rejects issuing country that isn't 2-letter code")
        func rejectsInvalidCountryCode() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "United States",  // Should be "US"
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )

            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }
        
        @Test("allows DrivingPrivilege with optional dates")
        func allowsOptionDatesInDrivingPrivilege() throws {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "UK",
                issuingAuthority: "DVLA",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(
                        vehicleCategoryCode: "B",
                        issueDate: TestHelpers.makeDate(year: 2023, month: 1, day: 1),
                        expiryDate: TestHelpers.makeDate(year: 2025, month: 1, day: 1)
                    )
                ]
            )
            
            // This should not throw
            try doc.validate()
        }
        
        @Test("rejects birth date in the future")
        func rejectsBirthdayInTheFuture() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 2999, month: 6, day: 15), // In the future
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2029, month: 1, day: 1),
                issuingCountry: "UK",
                issuingAuthority: "DVLA",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(
                        vehicleCategoryCode: "B",
                        issueDate: TestHelpers.makeDate(year: 2023, month: 1, day: 1),
                        expiryDate: TestHelpers.makeDate(year: 2025, month: 1, day: 1)
                    )
                ]
            )

            #expect(throws: MDLDocumentError.self) {
                try doc.validate()
            }
        }
        
        
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // MARK: - Computed Properties
    // ═══════════════════════════════════════════════════════════════════

    @Suite("Computed properties")
    struct ComputedProperties {

        @Test("isExpired returns true for past expiry date")
        func isExpiredTrue() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2020, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2021, month: 1, day: 1),  // In the past
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            #expect(doc.isExpired == true)
        }

        @Test("isExpired returns false for future expiry date")
        func isExpiredFalse() {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDate(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDate(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDate(year: 2099, month: 1, day: 1),  // Far future
                issuingCountry: "US",
                issuingAuthority: "State of California",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B")
                ]
            )
            
            #expect(doc.isExpired == false)
        }
        
        @Test("fullName combines given and family name")
        func fullNameCombination() {
            let doc = TestHelpers.makeMinimalDocument()
            #expect(doc.fullName == "Alice Smith")
        }
    }
}
