// MSOCBORCodingTests.swift
// Tests for encoding and decoding ISO 18013-5 MSO to/from CBOR (COSE_Sign1).

import Testing
import Foundation
import SwiftCBOR
@testable import MDLWallet

@Suite("MSOCBORCoding")
struct MSOCBORCodingTests {

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Helpers
    // ═══════════════════════════════════════════════════════════════

    /// Builds a minimal valid MSO for testing.
    private static func makeTestMSO(
        docType: String = "org.iso.18013.5.1.mDL",
        validFrom: Date = TestHelpers.makeDateUTC(year: 2024, month: 9, day: 2),
        validUntil: Date = TestHelpers.makeDateUTC(year: 2025, month: 10, day: 2),
        deviceKey: Data = Data(repeating: 0x01, count: 65),
        valueDigests: [String: [String: Data]] = [:]
    ) -> MobileSecurityObject {
        MobileSecurityObject(
            docType: docType,
            validityInfo: MSOValidityInfo(validFrom: validFrom, validUntil: validUntil),
            deviceKeyInfo: MSODeviceKeyInfo(deviceKey: deviceKey),
            valueDigests: valueDigests
        )
    }

    /// Wraps a CBOR payload map into a COSE_Sign1 array and returns encoded Data.
    private static func wrapInCOSESign1(payloadMap: [CBOR: CBOR]) -> Data {
        let payloadBytes = CBOR.map(payloadMap).encode()
        let coseSign1: CBOR = .array([
            .byteString([]),
            .map([:]),
            .byteString(payloadBytes),
            .byteString(Array(repeating: 0x99, count: 64))
        ])
        return Data(coseSign1.encode())
    }

    /// Builds a minimal valid MSO payload map for decode tests.
    private static func makeValidPayloadMap(
        docType: String = "org.iso.18013.5.1.mDL",
        validFrom: String = "2024-09-02T00:00:00Z",
        validUntil: String = "2025-10-02T00:00:00Z",
        deviceKey: CBOR = .byteString(Array(repeating: 0x01, count: 65)),
        valueDigests: [CBOR: CBOR] = [:]
    ) -> [CBOR: CBOR] {
        [
            .utf8String("docType"): .utf8String(docType),
            .utf8String("validityInfo"): .map([
                .utf8String("validFrom"): .utf8String(validFrom),
                .utf8String("validUntil"): .utf8String(validUntil)
            ]),
            .utf8String("deviceKeyInfo"): .map([
                .utf8String("deviceKey"): deviceKey
            ]),
            .utf8String("valueDigests"): .map(valueDigests)
        ]
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Encode / Decode round-trip
    // ═══════════════════════════════════════════════════════════════

    @Suite("Encode / Decode round-trip")
    struct RoundTrip {

        @Test("MSO payload encodes and decodes back to the same values")
        func payloadRoundTrip() throws {
            let digests: [String: [String: Data]] = [
                "org.iso.18013.5.1": [
                    "0": Data(repeating: 0xAA, count: 32),
                    "1": Data(repeating: 0xBB, count: 32)
                ]
            ]
            let mso = MSOCBORCodingTests.makeTestMSO(valueDigests: digests)

            let encoded = MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(decoded.docType == mso.docType)
            #expect(decoded.deviceKeyInfo == mso.deviceKeyInfo)
            #expect(decoded.valueDigests == mso.valueDigests)
            #expect(abs(decoded.validityInfo.validFrom.timeIntervalSince(mso.validityInfo.validFrom)) < 1)
            #expect(abs(decoded.validityInfo.validUntil.timeIntervalSince(mso.validityInfo.validUntil)) < 1)
        }

        @Test("COSE_Sign1 wrapping round-trips through decode")
        func coseSign1RoundTrip() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let signature = Data(repeating: 0xFF, count: 64)

            let encoded = MSOCBORCoding.encodeCOSESign1(mso: mso, signature: signature)
            let result = try MSOCBORCoding.decode(encoded)

            #expect(result.mso.docType == mso.docType)
            #expect(result.protectedHeader.isEmpty)
            #expect(result.signature == signature)
            #expect(result.mso.deviceKeyInfo == mso.deviceKeyInfo)
        }

        @Test("MSO with device key as CBOR map round-trips")
        func deviceKeyMapRoundTrip() throws {
            // Build a COSE_Key-like CBOR map: {1: 2, -1: 1, -2: x, -3: y}
            let coseKeyMap: [CBOR: CBOR] = [
                .unsignedInt(1): .unsignedInt(2),         // kty = EC2
                .unsignedInt(3): .unsignedInt(1)          // crv placeholder
            ]
            let keyData = Data(CBOR.map(coseKeyMap).encode())
            let mso = MSOCBORCodingTests.makeTestMSO(deviceKey: keyData)

            let encoded = MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            // The device key should decode as a CBOR map and re-encode
            #expect(!decoded.deviceKeyInfo.deviceKey.isEmpty)
        }

        @Test("MSO with SHA-384 and SHA-512 digests round-trips")
        func multipleDigestSizes() throws {
            let digests: [String: [String: Data]] = [
                "org.iso.18013.5.1": [
                    "0": Data(repeating: 0xAA, count: 48),  // SHA-384
                    "1": Data(repeating: 0xBB, count: 64)   // SHA-512
                ]
            ]
            let mso = MSOCBORCodingTests.makeTestMSO(valueDigests: digests)

            let encoded = MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(decoded.valueDigests["org.iso.18013.5.1"]?["0"]?.count == 48)
            #expect(decoded.valueDigests["org.iso.18013.5.1"]?["1"]?.count == 64)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Decode from raw COSE_Sign1
    // ═══════════════════════════════════════════════════════════════

    @Suite("Decode COSE_Sign1")
    struct DecodeCOSESign1 {

        @Test("decodes untagged COSE_Sign1 with MSO payload")
        func decodesUntagged() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .byteString(Array(repeating: 0xAB, count: 32))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)

            let result = try MSOCBORCoding.decode(data)

            #expect(result.mso.docType == "org.iso.18013.5.1.mDL")
            #expect(result.protectedHeader.isEmpty)
            #expect(result.signature.count == 64)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["0"]?.count == 32)
        }

        @Test("decodePayload decodes payload bytes only")
        func decodePayloadOnly() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            let data = Data(CBOR.map(payloadMap).encode())

            let mso = try MSOCBORCoding.decodePayload(data)

            #expect(mso.docType == "org.iso.18013.5.1.mDL")
            #expect(mso.valueDigests.isEmpty)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Decode errors
    // ═══════════════════════════════════════════════════════════════

    @Suite("Decode errors")
    struct DecodeErrors {

        @Test("throws when data is not a COSE_Sign1 array")
        func notCOSESign1() {
            let data = Data(CBOR.utf8String("not an array").encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when COSE_Sign1 has too few elements")
        func tooFewElements() {
            let bad: CBOR = .array([.byteString([]), .map([:]), .byteString([])])
            let data = Data(bad.encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when payload exceeds size limit")
        func payloadTooLarge() {
            let data = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when payload is not a CBOR map")
        func payloadNotMap() {
            let payloadBytes = CBOR.array([.utf8String("wrong")]).encode()
            let coseSign1: CBOR = .array([
                .byteString([]), .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            let data = Data(coseSign1.encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when docType is not allowed")
        func docTypeNotAllowed() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(docType: "com.evil.credential")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when docType is wrong type")
        func docTypeWrongType() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap[.utf8String("docType")] = .unsignedInt(999)
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws on unparseable validity date")
        func invalidDateFormat() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validFrom: "not-a-date")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when validFrom is at epoch")
        func validFromAtEpoch() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validFrom: "1970-01-01T00:00:00Z")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when validUntil is at year 2100")
        func validUntilAtMax() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validUntil: "2100-01-01T00:00:00Z")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when validityInfo is wrong type")
        func validityInfoWrongType() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap[.utf8String("validityInfo")] = .utf8String("nope")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when device key as byte string exceeds size limit")
        func deviceKeyBytesTooLarge() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                deviceKey: .byteString(Array(repeating: 0x01, count: 16 * 1024 + 1))
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when device key as map exceeds size limit")
        func deviceKeyMapTooLarge() {
            let largeMap: [CBOR: CBOR] = [
                .unsignedInt(1): .unsignedInt(2),
                .utf8String("big"): .byteString(Array(repeating: 0x41, count: 16 * 1024 + 1))
            ]
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(deviceKey: .map(largeMap))
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when value digest has non-standard byte length")
        func digestInvalidSize() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .byteString(Array(repeating: 0xAB, count: 31))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when digest value is not byte string")
        func digestNotByteString() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("0"): .unsignedInt(42)
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when namespace value is not a map")
        func namespaceNotMap() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [.utf8String("org.iso.18013.5.1"): .utf8String("bad")]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when valueDigests has too many namespaces")
        func tooManyNamespaces() {
            var nsMap: [CBOR: CBOR] = [:]
            for i in 0..<129 {
                nsMap[.utf8String("ns\(i)")] = .map([
                    .utf8String("0"): .byteString(Array(repeating: 0xAB, count: 32))
                ])
            }
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(valueDigests: nsMap)
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws when namespace has too many digest entries")
        func tooManyDigestsPerNamespace() {
            var labels: [CBOR: CBOR] = [:]
            for i in 0..<257 {
                labels[.utf8String("\(i)")] = .byteString(Array(repeating: 0xAB, count: 32))
            }
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [.utf8String("org.iso.18013.5.1"): .map(labels)]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
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

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Boundary acceptance
    // ═══════════════════════════════════════════════════════════════

    @Suite("Boundary acceptance")
    struct BoundaryAcceptance {

        @Test("accepts device key at exactly 16KB")
        func deviceKeyAtLimit() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                deviceKey: .byteString(Array(repeating: 0x01, count: 16 * 1024))
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.deviceKeyInfo.deviceKey.count == 16 * 1024)
        }

        @Test("accepts digests of all standard hash sizes")
        func allDigestSizes() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("sha256"): .byteString(Array(repeating: 0xAA, count: 32)),
                        .utf8String("sha384"): .byteString(Array(repeating: 0xBB, count: 48)),
                        .utf8String("sha512"): .byteString(Array(repeating: 0xCC, count: 64))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?.count == 3)
        }

        @Test("accepts digest labels as unsigned integers")
        func unsignedIntDigestLabels() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .unsignedInt(0): .byteString(Array(repeating: 0xAA, count: 32)),
                        .unsignedInt(42): .byteString(Array(repeating: 0xBB, count: 32))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["0"]?.count == 32)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?["42"]?.count == 32)
        }
    }
}
