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
        version: String = "1.0",
        digestAlgorithm: String = "SHA-256",
        docType: String = "org.iso.18013.5.1.mDL",
        signed: Date = TestHelpers.makeDateUTC(year: 2024, month: 9, day: 1),
        validFrom: Date = TestHelpers.makeDateUTC(year: 2024, month: 9, day: 2),
        validUntil: Date = TestHelpers.makeDateUTC(year: 2025, month: 10, day: 2),
        expectedUpdate: Date? = nil,
        deviceKey: Data = Data(repeating: 0x01, count: 65),
        valueDigests: [String: [UInt64: Data]] = [:]
    ) -> MobileSecurityObject {
        MobileSecurityObject(
            version: version,
            digestAlgorithm: digestAlgorithm,
            docType: docType,
            validityInfo: MSOValidityInfo(
                signed: signed,
                validFrom: validFrom,
                validUntil: validUntil,
                expectedUpdate: expectedUpdate
            ),
            deviceKeyInfo: MSODeviceKeyInfo(deviceKey: deviceKey),
            valueDigests: valueDigests
        )
    }

    /// Wraps a CBOR payload map into an untagged COSE_Sign1 array and returns encoded Data.
    private static func wrapInCOSESign1(payloadMap: [CBOR: CBOR], tagged: Bool = false) -> Data {
        let payloadBytes = CBOR.map(payloadMap).encode()
        let coseArray: CBOR = .array([
            .byteString([]),
            .map([:]),
            .byteString(payloadBytes),
            .byteString(Array(repeating: 0x99, count: 64))
        ])
        let output: CBOR = tagged
            ? .tagged(CBOR.Tag(rawValue: 18), coseArray)
            : coseArray
        return Data(output.encode())
    }

    /// Builds a minimal valid MSO payload map for decode tests.
    private static func makeValidPayloadMap(
        version: String = "1.0",
        digestAlgorithm: String = "SHA-256",
        docType: String = "org.iso.18013.5.1.mDL",
        signed: String = "2024-09-01T00:00:00Z",
        validFrom: String = "2024-09-02T00:00:00Z",
        validUntil: String = "2025-10-02T00:00:00Z",
        expectedUpdate: String? = nil,
        deviceKey: CBOR = .byteString(Array(repeating: 0x01, count: 65)),
        valueDigests: [CBOR: CBOR] = [:]
    ) -> [CBOR: CBOR] {
        var validityMap: [CBOR: CBOR] = [
            .utf8String("signed"): .utf8String(signed),
            .utf8String("validFrom"): .utf8String(validFrom),
            .utf8String("validUntil"): .utf8String(validUntil)
        ]
        if let eu = expectedUpdate {
            validityMap[.utf8String("expectedUpdate")] = .utf8String(eu)
        }
        return [
            .utf8String("version"): .utf8String(version),
            .utf8String("digestAlgorithm"): .utf8String(digestAlgorithm),
            .utf8String("docType"): .utf8String(docType),
            .utf8String("validityInfo"): .map(validityMap),
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
            let digests: [String: [UInt64: Data]] = [
                "org.iso.18013.5.1": [
                    0: Data(repeating: 0xAA, count: 32),
                    1: Data(repeating: 0xBB, count: 32)
                ]
            ]
            let mso = MSOCBORCodingTests.makeTestMSO(valueDigests: digests)

            let encoded = try MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(decoded.version == mso.version)
            #expect(decoded.digestAlgorithm == mso.digestAlgorithm)
            #expect(decoded.docType == mso.docType)
            #expect(decoded.deviceKeyInfo == mso.deviceKeyInfo)
            #expect(decoded.valueDigests == mso.valueDigests)
            #expect(abs(decoded.validityInfo.signed.timeIntervalSince(mso.validityInfo.signed)) < 1)
            #expect(abs(decoded.validityInfo.validFrom.timeIntervalSince(mso.validityInfo.validFrom)) < 1)
            #expect(abs(decoded.validityInfo.validUntil.timeIntervalSince(mso.validityInfo.validUntil)) < 1)
        }

        @Test("COSE_Sign1 wrapping round-trips through decode (tagged)")
        func coseSign1RoundTrip() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let signature = Data(repeating: 0xFF, count: 64)

            let encoded = try MSOCBORCoding.encodeCOSESign1(mso: mso, signature: signature)
            let result = try MSOCBORCoding.decode(encoded)

            #expect(result.mso.docType == mso.docType)
            #expect(result.mso.version == "1.0")
            #expect(result.mso.digestAlgorithm == "SHA-256")
            #expect(result.protectedHeader.isEmpty)
            #expect(result.signature == signature)
            #expect(result.mso.deviceKeyInfo == mso.deviceKeyInfo)
        }

        @Test("COSE_Sign1 untagged round-trip works")
        func coseSign1UntaggedRoundTrip() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let signature = Data(repeating: 0xFF, count: 64)

            let encoded = try MSOCBORCoding.encodeCOSESign1(mso: mso, signature: signature, tagged: false)
            let result = try MSOCBORCoding.decode(encoded)

            #expect(result.mso.docType == mso.docType)
            #expect(result.signature == signature)
        }

        @Test("MSO with device key as CBOR map round-trips")
        func deviceKeyMapRoundTrip() throws {
            let coseKeyMap: [CBOR: CBOR] = [
                .unsignedInt(1): .unsignedInt(2),         // kty = EC2
                .unsignedInt(3): .unsignedInt(1)          // crv placeholder
            ]
            let keyData = Data(CBOR.map(coseKeyMap).encode())
            let mso = MSOCBORCodingTests.makeTestMSO(deviceKey: keyData)

            let encoded = try MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(!decoded.deviceKeyInfo.deviceKey.isEmpty)
        }

        @Test("MSO with SHA-384 and SHA-512 digests round-trips")
        func multipleDigestSizes() throws {
            let digests: [String: [UInt64: Data]] = [
                "org.iso.18013.5.1": [
                    0: Data(repeating: 0xAA, count: 48),  // SHA-384
                    1: Data(repeating: 0xBB, count: 64)   // SHA-512
                ]
            ]
            let mso = MSOCBORCodingTests.makeTestMSO(valueDigests: digests)

            let encoded = try MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(decoded.valueDigests["org.iso.18013.5.1"]?[0]?.count == 48)
            #expect(decoded.valueDigests["org.iso.18013.5.1"]?[1]?.count == 64)
        }

        @Test("MSO with expectedUpdate round-trips")
        func expectedUpdateRoundTrip() throws {
            let mso = MSOCBORCodingTests.makeTestMSO(
                expectedUpdate: TestHelpers.makeDateUTC(year: 2025, month: 3, day: 15)
            )

            let encoded = try MSOCBORCoding.encodePayload(mso)
            let decoded = try MSOCBORCoding.decodePayload(encoded)

            #expect(decoded.validityInfo.expectedUpdate != nil)
            #expect(
                abs(decoded.validityInfo.expectedUpdate!.timeIntervalSince(mso.validityInfo.expectedUpdate!)) < 1
            )
        }

        @Test("MSODecodeResult is Equatable")
        func decodeResultEquatable() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let signature = Data(repeating: 0xFF, count: 64)
            let encoded = try MSOCBORCoding.encodeCOSESign1(mso: mso, signature: signature)

            let result1 = try MSOCBORCoding.decode(encoded)
            let result2 = try MSOCBORCoding.decode(encoded)

            #expect(result1 == result2)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Decode COSE_Sign1
    // ═══════════════════════════════════════════════════════════════

    @Suite("Decode COSE_Sign1")
    struct DecodeCOSESign1 {

        @Test("decodes untagged COSE_Sign1 with MSO payload")
        func decodesUntagged() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .unsignedInt(0): .byteString(Array(repeating: 0xAB, count: 32))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)

            let result = try MSOCBORCoding.decode(data)

            #expect(result.mso.docType == "org.iso.18013.5.1.mDL")
            #expect(result.protectedHeader.isEmpty)
            #expect(result.signature.count == 64)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?[0]?.count == 32)
        }

        @Test("decodes tagged COSE_Sign1 (tag 18)")
        func decodesTagged() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap, tagged: true)

            let result = try MSOCBORCoding.decode(data)

            #expect(result.mso.docType == "org.iso.18013.5.1.mDL")
            #expect(result.mso.version == "1.0")
        }

        @Test("decodePayload decodes payload bytes only")
        func decodePayloadOnly() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            let data = Data(CBOR.map(payloadMap).encode())

            let mso = try MSOCBORCoding.decodePayload(data)

            #expect(mso.docType == "org.iso.18013.5.1.mDL")
            #expect(mso.version == "1.0")
            #expect(mso.digestAlgorithm == "SHA-256")
            #expect(mso.valueDigests.isEmpty)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Decode errors
    // ═══════════════════════════════════════════════════════════════

    @Suite("Decode errors")
    struct DecodeErrors {

        @Test("throws invalidCOSESign1Structure when data is not a COSE_Sign1 array")
        func notCOSESign1() {
            let data = Data(CBOR.utf8String("not an array").encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidCOSESign1Structure when COSE_Sign1 has too few elements")
        func tooFewElements() {
            let bad: CBOR = .array([.byteString([]), .map([:]), .byteString([])])
            let data = Data(bad.encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidCOSESign1Structure when tagged with wrong tag")
        func wrongTag() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            let payloadBytes = CBOR.map(payloadMap).encode()
            let coseArray: CBOR = .array([
                .byteString([]), .map([:]),
                .byteString(payloadBytes),
                .byteString(Array(repeating: 0x99, count: 64))
            ])
            // Tag 96 = COSE_Encrypt, not COSE_Sign1
            let tagged: CBOR = .tagged(CBOR.Tag(rawValue: 96), coseArray)
            let data = Data(tagged.encode())
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws dataTooLarge when payload exceeds size limit")
        func payloadTooLarge() {
            let data = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when payload is not a CBOR map")
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

        @Test("throws invalidPayload when version is missing")
        func versionMissing() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap.removeValue(forKey: .utf8String("version"))
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when digestAlgorithm is missing")
        func digestAlgorithmMissing() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap.removeValue(forKey: .utf8String("digestAlgorithm"))
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws unsupportedDocType when docType is not allowed")
        func docTypeNotAllowed() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(docType: "com.evil.credential")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when docType is wrong type")
        func docTypeWrongType() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap[.utf8String("docType")] = .unsignedInt(999)
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidDateFormat on unparseable validity date")
        func invalidDateFormat() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validFrom: "not-a-date")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when signed date is missing")
        func signedMissing() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            // Rebuild validityInfo without "signed"
            payloadMap[.utf8String("validityInfo")] = .map([
                .utf8String("validFrom"): .utf8String("2024-09-02T00:00:00Z"),
                .utf8String("validUntil"): .utf8String("2025-10-02T00:00:00Z")
            ])
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws validityOutOfRange when validFrom is at epoch")
        func validFromAtEpoch() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validFrom: "1970-01-01T00:00:00Z")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws validityOutOfRange when validUntil is at year 2100")
        func validUntilAtMax() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(validUntil: "2100-01-01T00:00:00Z")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws validityOutOfRange when validFrom >= validUntil")
        func validFromAfterValidUntil() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                validFrom: "2026-01-01T00:00:00Z",
                validUntil: "2025-01-01T00:00:00Z"
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws validityOutOfRange when validFrom equals validUntil")
        func validFromEqualsValidUntil() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                validFrom: "2025-01-01T00:00:00Z",
                validUntil: "2025-01-01T00:00:00Z"
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when validityInfo is wrong type")
        func validityInfoWrongType() {
            var payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            payloadMap[.utf8String("validityInfo")] = .utf8String("nope")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws deviceKeyTooLarge when device key as byte string exceeds size limit")
        func deviceKeyBytesTooLarge() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                deviceKey: .byteString(Array(repeating: 0x01, count: 16 * 1024 + 1))
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws deviceKeyTooLarge when device key as map exceeds size limit")
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

        @Test("throws invalidDigest when value digest has non-standard byte length")
        func digestInvalidSize() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .unsignedInt(0): .byteString(Array(repeating: 0xAB, count: 31))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidDigest when digest value is not byte string")
        func digestNotByteString() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .unsignedInt(0): .unsignedInt(42)
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidDigest when digest ID is a string instead of unsigned int")
        func digestIDNotUnsignedInt() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [
                    .utf8String("org.iso.18013.5.1"): .map([
                        .utf8String("not-a-uint"): .byteString(Array(repeating: 0xAB, count: 32))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws invalidPayload when namespace value is not a map")
        func namespaceNotMap() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [.utf8String("org.iso.18013.5.1"): .utf8String("bad")]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws tooManyNamespaces when valueDigests has too many namespaces")
        func tooManyNamespaces() {
            var nsMap: [CBOR: CBOR] = [:]
            for idx in 0..<129 {
                nsMap[.utf8String("ns\(idx)")] = .map([
                    .unsignedInt(0): .byteString(Array(repeating: 0xAB, count: 32))
                ])
            }
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(valueDigests: nsMap)
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("throws tooManyDigestsPerNamespace when namespace has too many entries")
        func tooManyDigestsPerNamespace() {
            var labels: [CBOR: CBOR] = [:]
            for idx: UInt64 in 0..<257 {
                labels[.unsignedInt(idx)] = .byteString(Array(repeating: 0xAB, count: 32))
            }
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(
                valueDigests: [.utf8String("org.iso.18013.5.1"): .map(labels)]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }

        @Test("decodePayload throws dataTooLarge when payload exceeds size limit")
        func decodePayloadTooLarge() {
            let data = Data(repeating: 0x00, count: 1024 * 1024 + 1)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decodePayload(data)
            }
        }

        @Test("throws invalidDateFormat when expectedUpdate is unparseable")
        func invalidExpectedUpdate() {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap(expectedUpdate: "not-a-date")
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            #expect(throws: MSOCBORDecodeError.self) {
                _ = try MSOCBORCoding.decode(data)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Encode errors
    // ═══════════════════════════════════════════════════════════════

    @Suite("Encode validation")
    struct EncodeValidation {

        @Test("throws when version is empty")
        func emptyVersion() {
            let mso = MSOCBORCodingTests.makeTestMSO(version: "")
            #expect(throws: MSOCBOREncodeError.self) {
                _ = try MSOCBORCoding.encodePayload(mso)
            }
        }

        @Test("throws when digestAlgorithm is empty")
        func emptyDigestAlgorithm() {
            let mso = MSOCBORCodingTests.makeTestMSO(digestAlgorithm: "")
            #expect(throws: MSOCBOREncodeError.self) {
                _ = try MSOCBORCoding.encodePayload(mso)
            }
        }

        @Test("throws when docType is empty")
        func emptyDocType() {
            let mso = MSOCBORCodingTests.makeTestMSO(docType: "")
            #expect(throws: MSOCBOREncodeError.self) {
                _ = try MSOCBORCoding.encodePayload(mso)
            }
        }

        @Test("throws when validFrom >= validUntil")
        func datesOutOfOrder() {
            let mso = MSOCBORCodingTests.makeTestMSO(
                validFrom: TestHelpers.makeDateUTC(year: 2026, month: 1, day: 1),
                validUntil: TestHelpers.makeDateUTC(year: 2025, month: 1, day: 1)
            )
            #expect(throws: MSOCBOREncodeError.self) {
                _ = try MSOCBORCoding.encodePayload(mso)
            }
        }

        @Test("throws when deviceKey is empty")
        func emptyDeviceKey() {
            let mso = MSOCBORCodingTests.makeTestMSO(deviceKey: Data())
            #expect(throws: MSOCBOREncodeError.self) {
                _ = try MSOCBORCoding.encodePayload(mso)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: - Encode features
    // ═══════════════════════════════════════════════════════════════

    @Suite("Encode features")
    struct EncodeFeatures {

        @Test("encodeCOSESign1 produces tagged output by default")
        func defaultTagged() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let encoded = try MSOCBORCoding.encodeCOSESign1(mso: mso, signature: Data(repeating: 0xFF, count: 64))
            let cbor = try CBOR.decode([UInt8](encoded))

            // Should be tagged with tag 18
            if case .tagged(let tag, .array) = cbor {
                #expect(tag.rawValue == 18)
            } else {
                #expect(Bool(false), "Expected tagged CBOR, got \(String(describing: cbor))")
            }
        }

        @Test("encodeCOSESign1 can produce untagged output")
        func explicitUntagged() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let encoded = try MSOCBORCoding.encodeCOSESign1(mso: mso, signature: Data(repeating: 0xFF, count: 64), tagged: false)
            let cbor = try CBOR.decode([UInt8](encoded))

            if case .array(let arr) = cbor {
                #expect(arr.count == 4)
            } else {
                #expect(Bool(false), "Expected untagged array, got \(String(describing: cbor))")
            }
        }

        @Test("encodeCOSESign1 passes through unprotected header")
        func unprotectedHeader() throws {
            let mso = MSOCBORCodingTests.makeTestMSO()
            let certChain: [CBOR: CBOR] = [.unsignedInt(33): .byteString([0x01, 0x02, 0x03])] // x5chain
            let encoded = try MSOCBORCoding.encodeCOSESign1(
                mso: mso,
                unprotectedHeader: certChain,
                signature: Data(repeating: 0xFF, count: 64)
            )

            let result = try MSOCBORCoding.decode(encoded)
            #expect(result.mso.docType == "org.iso.18013.5.1.mDL")
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
                        .unsignedInt(0): .byteString(Array(repeating: 0xAA, count: 32)),
                        .unsignedInt(1): .byteString(Array(repeating: 0xBB, count: 48)),
                        .unsignedInt(2): .byteString(Array(repeating: 0xCC, count: 64))
                    ])
                ]
            )
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.valueDigests["org.iso.18013.5.1"]?.count == 3)
        }

        @Test("accepts MSO with no value digests")
        func emptyValueDigests() throws {
            let payloadMap = MSOCBORCodingTests.makeValidPayloadMap()
            let data = MSOCBORCodingTests.wrapInCOSESign1(payloadMap: payloadMap)
            let result = try MSOCBORCoding.decode(data)
            #expect(result.mso.valueDigests.isEmpty)
        }
    }
}
