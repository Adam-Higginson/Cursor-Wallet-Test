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
    }
}
