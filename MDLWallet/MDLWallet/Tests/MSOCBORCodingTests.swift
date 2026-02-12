// MSOCBORCodingTests.swift
// Tests for decoding ISO 18013-5 MSO from CBOR (COSE_Sign1).

import Testing
import Foundation
import SwiftCBOR
@testable import MDLWallet

@Suite("MSOCBORCoding")
struct MSOCBORCodingTests {

    @Suite("Decode full MSO (COSE_Sign1)")
    struct DecodeFull {

        @Test("decodes untagged COSE_Sign1 with MSO payload")
        func decodesUntaggedCOSESign1() throws {
            let validFrom = "2024-09-02T22:28:41Z"
            let validUntil = "2025-10-02T22:28:41Z"
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String(validFrom),
                    .utf8String("validUntil"): .utf8String(validUntil)
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .map([
                        .unsignedInt(1): .unsignedInt(2),
                        .negativeInt(0): .unsignedInt(1),
                        .negativeInt(1): .byteString(Array(repeating: 0x41, count: 32)),
                        .negativeInt(2): .byteString(Array(repeating: 0x42, count: 32))
                    ])
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .byteString(Array(repeating: 0xAB, count: 32))
                    ])
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            let result = try MSOCBORCoding.decode(data)

            #expect(result.mso.docType == "org.iso.18013.5.1.mDL")
            #expect(result.protectedHeader.isEmpty)
            #expect(result.payloadBytes == Data(payloadBytes))
            #expect(result.signature.count == 64)
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
            dateFormatter.timeZone = TimeZone(identifier: "UTC")
            if let fromDate = dateFormatter.date(from: validFrom), let untilDate = dateFormatter.date(from: validUntil) {
                #expect(abs(result.mso.validityInfo.validFrom.timeIntervalSince(fromDate)) < 1)
                #expect(abs(result.mso.validityInfo.validUntil.timeIntervalSince(untilDate)) < 1)
            }
            #expect(!result.mso.deviceKeyInfo.deviceKey.isEmpty)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["0"]?.count == 32)
        }

        @Test("decodePayload decodes payload bytes only")
        func decodePayloadOnly() throws {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let data = Data(CBOR.map(payloadMap).encode())

            let mso = try MSOCBORCoding.decodePayload(data)

            #expect(mso.docType == "org.iso.18013.5.1.mDL")
            #expect(mso.deviceKeyInfo.deviceKey.count == 65)
            #expect(mso.valueDigests.isEmpty)
        }
    }

    @Suite("Decode errors")
    struct DecodeErrors {

        @Test("decode throws when data is not COSE_Sign1 array")
        func notCOSESign1() {
            let data = Data(CBOR.utf8String("not an array").encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when payload exceeds size limit")
        func payloadTooLarge() {
            let data = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when valueDigests label key is negativeInt(UInt64.max) (overflow)")
        func valueDigestsNegativeIntOverflow() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map([
                        .negativeInt(UInt64.max): .byteString(Array(repeating: 0x00, count: 32))
                    ])
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when device key exceeds size limit")
        func deviceKeyTooLarge() {
            let oversizedKeySize = 16 * 1024 + 1
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: oversizedKeySize))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when device key as map encodes to over size limit")
        func deviceKeyMapTooLarge() {
            let oversizedPayload = Array(repeating: UInt8(0x41), count: 16 * 1024 + 1)
            let largeKeyMap: [CBOR: CBOR] = [
                .unsignedInt(1): .unsignedInt(2),
                .utf8String("extra"): .byteString(oversizedPayload)
            ]
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .map(largeKeyMap)
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when value digest has non-standard size")
        func valueDigestInvalidSize() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .byteString(Array(repeating: 0xAB, count: 31))
                    ])
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when docType is not allowed")
        func docTypeNotAllowed() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("com.example.other.credential"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when valueDigests has too many namespaces")
        func valueDigestsTooManyNamespaces() {
            var nsMap: [CBOR: CBOR] = [:]
            for i in 0..<129 {
                nsMap[.utf8String("ns\(i)")] = .map([.utf8String("0"): .byteString(Array(repeating: 0xAB, count: 32))])
            }
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map(nsMap)
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when valueDigests namespace has too many entries")
        func valueDigestsTooManyEntriesPerNamespace() {
            var labelToDigest: [CBOR: CBOR] = [:]
            for i in 0..<257 {
                labelToDigest[.utf8String("\(i)")] = .byteString(Array(repeating: 0xAB, count: 32))
            }
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map(labelToDigest)
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when validFrom is at or before epoch")
        func validityFromBeforeEpoch() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("1970-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when validUntil is at or after year 2100")
        func validityUntilAfterMax() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2100-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }
    }

    @Suite("Security edge cases and attack scenarios")
    struct SecurityEdgeCases {

        // MARK: - Boundary (accept at limit – ensures limits are enforced, not exceeded)

        @Test("accepts device key at exactly 16KB boundary")
        func deviceKeyAtBoundaryAccepted() throws {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 16 * 1024))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.deviceKeyInfo.deviceKey.count == 16 * 1024)
        }

        @Test("accepts SHA-384 (48) and SHA-512 (64) digest sizes")
        func acceptsStandardDigestSizes() throws {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("48"): .byteString(Array(repeating: 0xCC, count: 48)),
                        .utf8String("64"): .byteString(Array(repeating: 0xDD, count: 64))
                    ])
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["48"]?.count == 48)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["64"]?.count == 64)
        }

        // MARK: - Malformed / invalid structure

        @Test("decode throws on unparseable validity date (malformed date attack)")
        func invalidDateFormatRejected() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("not-a-date"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when COSE_Sign1 has too few elements")
        func coseSign1TooFewElements() {
            let payloadBytes = CBOR.map([.utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL")]).encode()
            let badCOSE: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes)
            ])
            let data = Data(badCOSE.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when payload is not a CBOR map")
        func payloadNotMap() {
            let payloadBytes = CBOR.array([.utf8String("wrong")]).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when docType is wrong type (integer)")
        func docTypeWrongType() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .unsignedInt(999),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when validityInfo is wrong type (string)")
        func validityInfoWrongType() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .utf8String("not a map"),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([:])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when valueDigests namespace value is not a map")
        func valueDigestsNamespaceNotMap() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .utf8String("not a map")
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decode throws when digest value is not byte string")
        func digestValueNotByteString() {
            let payloadMap: [CBOR: CBOR] = [
                .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
                .utf8String("validityInfo"): .map([
                    .utf8String("validFrom"): .utf8String("2024-01-01T00:00:00Z"),
                    .utf8String("validUntil"): .utf8String("2029-01-01T00:00:00Z")
                ]),
                .utf8String("deviceKeyInfo"): .map([
                    .utf8String("deviceKey"): .byteString(Array(repeating: 0x01, count: 65))
                ]),
                .utf8String("valueDigests"): .map([
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .unsignedInt(32)
                    ])
                ])
            ]
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseSign1: CBOR = .array([
                .byteString([]),
                .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())

            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decodePayload throws when payload exceeds size limit")
        func decodePayloadTooLarge() {
            let data = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decodePayload(data)
            }
        }
    }
}
