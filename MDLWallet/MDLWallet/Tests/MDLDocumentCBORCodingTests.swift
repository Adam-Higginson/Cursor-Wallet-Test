// MDLDocumentCBORCodingTests.swift
// Round-trip and decode error tests for ISO 18013-5 CBOR encoding.

import Testing
import Foundation
import SwiftCBOR
@testable import MDLWallet

@Suite("MDLDocumentCBORCoding")
struct MDLDocumentCBORCodingTests {

    @Suite("Encode / Decode round-trip")
    struct RoundTrip {

        @Test("minimal document round-trips unchanged")
        func minimalRoundTrip() throws {
            let doc = TestHelpers.makeMinimalDocumentForCBOR()
            let data = MDLDocumentCBORCoding.encode(doc)
            let decoded = try MDLDocumentCBORCoding.decode(data)
            #expect(decoded == doc)
        }

        @Test("document with optional fields round-trips")
        func optionalFieldsRoundTrip() throws {
            let doc = MDLDocument(
                familyName: "Smith",
                givenName: "Alice",
                birthDate: TestHelpers.makeDateUTC(year: 1990, month: 6, day: 15),
                issueDate: TestHelpers.makeDateUTC(year: 2024, month: 1, day: 1),
                expiryDate: TestHelpers.makeDateUTC(year: 2029, month: 1, day: 1),
                issuingCountry: "UK",
                issuingAuthority: "DVLA",
                documentNumber: "DL123456789",
                drivingPrivileges: [
                    DrivingPrivilege(vehicleCategoryCode: "B"),
                    DrivingPrivilege(
                        vehicleCategoryCode: "A",
                        issueDate: TestHelpers.makeDateUTC(year: 2023, month: 1, day: 1),
                        expiryDate: TestHelpers.makeDateUTC(year: 2028, month: 12, day: 31)
                    )
                ],
                portrait: Data([0xFF, 0xD8, 0xFF]),
                nationality: "GB",
                ageOver18: true,
                residentAddress: "123 High Street, London"
            )
            let data = MDLDocumentCBORCoding.encode(doc)
            let decoded = try MDLDocumentCBORCoding.decode(data)
            #expect(decoded == doc)
        }
    }

    @Suite("Decode errors")
    struct DecodeErrors {

        @Test("decode throws when data is not a map")
        func notAMap() {
            // CBOR encoding of a plain array, not a map
            var bytes: [UInt8] = [0x81] // array of length 1
            bytes.append(0x63) // text(3)
            bytes.append(contentsOf: [0x61, 0x62, 0x63]) // "abc"
            let data = Data(bytes)
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }

        @Test("decode throws when namespace is missing")
        func missingNamespace() {
            // Top-level map with key "other.namespace" and empty map value (not org.iso.18013.5.1)
            let key = "other.namespace"
            var bytes: [UInt8] = [0xa1, 0x6f] // map(1), text(15)
            bytes.append(contentsOf: Array(key.utf8))
            bytes.append(0xa0) // value = empty map
            let data = Data(bytes)
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }

        @Test("decode throws when required key is missing")
        func missingRequiredKey() {
            // Top-level map with correct namespace but empty items map (no family_name etc.)
            let topLevel = CBOR.map([.utf8String("org.iso.18013.5.1"): .map([:])])
            let data = Data(topLevel.encode())
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }

        @Test("decode throws when payload exceeds size limit")
        func dataTooLarge() {
            // Payload larger than 1 MiB limit
            let tooBig = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(tooBig)
            }
        }

        @Test("decode throws on invalid date format in required field")
        func invalidDateFormat() {
            // Valid structure but birth_date is not YYYY-MM-DD
            let topLevel = CBOR.map([
                .utf8String("org.iso.18013.5.1"): .map([
                    .utf8String("family_name"): .utf8String("Smith"),
                    .utf8String("given_name"): .utf8String("Alice"),
                    .utf8String("birth_date"): .utf8String("not-a-date"),
                    .utf8String("issue_date"): .utf8String("2024-01-01"),
                    .utf8String("expiry_date"): .utf8String("2029-01-01"),
                    .utf8String("issuing_country"): .utf8String("UK"),
                    .utf8String("issuing_authority"): .utf8String("DVLA"),
                    .utf8String("document_number"): .utf8String("DL123456789"),
                    .utf8String("driving_privileges"): .array([.map([.utf8String("vehicle_category_code"): .utf8String("B")])])
                ])
            ])
            let data = Data(topLevel.encode())
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }

        @Test("decode throws when driving_privileges is not an array")
        func invalidDrivingPrivilegesType() {
            let topLevel = CBOR.map([
                .utf8String("org.iso.18013.5.1"): .map([
                    .utf8String("family_name"): .utf8String("Smith"),
                    .utf8String("given_name"): .utf8String("Alice"),
                    .utf8String("birth_date"): .utf8String("1990-06-15"),
                    .utf8String("issue_date"): .utf8String("2024-01-01"),
                    .utf8String("expiry_date"): .utf8String("2029-01-01"),
                    .utf8String("issuing_country"): .utf8String("UK"),
                    .utf8String("issuing_authority"): .utf8String("DVLA"),
                    .utf8String("document_number"): .utf8String("DL123456789"),
                    .utf8String("driving_privileges"): .utf8String("not-an-array")
                ])
            ])
            let data = Data(topLevel.encode())
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }

        @Test("decode throws when required string field is wrong type")
        func invalidRequiredFieldType() {
            // document_number as integer instead of string
            let topLevel = CBOR.map([
                .utf8String("org.iso.18013.5.1"): .map([
                    .utf8String("family_name"): .utf8String("Smith"),
                    .utf8String("given_name"): .utf8String("Alice"),
                    .utf8String("birth_date"): .utf8String("1990-06-15"),
                    .utf8String("issue_date"): .utf8String("2024-01-01"),
                    .utf8String("expiry_date"): .utf8String("2029-01-01"),
                    .utf8String("issuing_country"): .utf8String("UK"),
                    .utf8String("issuing_authority"): .utf8String("DVLA"),
                    .utf8String("document_number"): .unsignedInt(123),
                    .utf8String("driving_privileges"): .array([.map([.utf8String("vehicle_category_code"): .utf8String("B")])])
                ])
            ])
            let data = Data(topLevel.encode())
            #expect(throws: MDLCBORDecodeError.self) {
                _ = try MDLDocumentCBORCoding.decode(data)
            }
        }
    }
}
