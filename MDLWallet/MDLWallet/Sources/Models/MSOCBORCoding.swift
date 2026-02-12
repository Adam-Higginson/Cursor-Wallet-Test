// MSOCBORCoding.swift
// Decodes an ISO 18013-5 Mobile Security Object (MSO) from CBOR.
//
// The MSO is transmitted as a COSE_Sign1 structure (RFC 9052): the payload
// is a CBOR map with docType, validityInfo, deviceKeyInfo, and valueDigests.
// This module decodes that payload into a MobileSecurityObject. It does not
// verify the issuer signature; callers should verify using the Document
// Signer Certificate (DSC) and IACA chain.

import Foundation
import SwiftCBOR

// MARK: - COSE_Sign1 layout (RFC 9052)

/// COSE_Sign1 = [ protected (bstr), unprotected (map), payload (bstr), signature (bstr) ]
private enum COSESign1Index {
    static let protected = 0
    static let unprotected = 1
    static let payload = 2
    static let signature = 3
}

// MARK: - MSO payload keys (ISO 18013-5)

private enum MSOPayloadKey {
    static let docType = "docType"
    static let validityInfo = "validityInfo"
    static let deviceKeyInfo = "deviceKeyInfo"
    static let valueDigests = "valueDigests"
    static let validFrom = "validFrom"
    static let validUntil = "validUntil"
    static let deviceKey = "deviceKey"
}

// MARK: - Limits

private enum MSOLimits {
    static let maxDataSize = 1024 * 1024
}

// MARK: - Date-time format (ISO 8601)

private func makeDateTimeFormatter() -> DateFormatter {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.locale = Locale(identifier: "en_GB_POSIX")
    return formatter
}

// MARK: - Errors

/// Errors when decoding an MSO from CBOR.
public enum MSOCBORDecodeError: Error, Sendable {
    case invalidFormat
}

/// Result of successfully decoding an MSO (COSE_Sign1).
public struct MSODecodeResult: Sendable {
    public let mso: MobileSecurityObject
    public let protectedHeader: Data
    public let payloadBytes: Data
    public let signature: Data

    public init(mso: MobileSecurityObject, protectedHeader: Data, payloadBytes: Data, signature: Data) {
        self.mso = mso
        self.protectedHeader = protectedHeader
        self.payloadBytes = payloadBytes
        self.signature = signature
    }
}

// MARK: - MSOCBORCoding

public enum MSOCBORCoding {

    /// Decodes a full MSO from CBOR (COSE_Sign1 structure).
    /// Returns the payload as a `MobileSecurityObject` and the raw protected header, payload bytes, and signature for later verification.
    public static func decode(_ data: Data) throws -> MSODecodeResult {
        guard data.count <= MSOLimits.maxDataSize else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let array: [CBOR]
        switch cbor {
        case .tagged(_, .array(let arr)) where arr.count >= 4:
            array = arr
        case .array(let arr) where arr.count >= 4:
            array = arr
        default:
            throw MSOCBORDecodeError.invalidFormat
        }
        guard array.count >= 4,
              case .byteString(let protectedBytes) = array[COSESign1Index.protected],
              case .byteString(let payloadBytes) = array[COSESign1Index.payload],
              case .byteString(let signatureBytes) = array[COSESign1Index.signature] else {
            throw MSOCBORDecodeError.invalidFormat
        }
        guard let payloadCBOR = try? CBOR.decode(payloadBytes),
              case .map(let payloadMap) = payloadCBOR else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let dateTimeFormatter = makeDateTimeFormatter()
        let mso = try parseMSOPayload(payloadMap, dateTimeFormatter: dateTimeFormatter)
        return MSODecodeResult(
            mso: mso,
            protectedHeader: Data(protectedBytes),
            payloadBytes: Data(payloadBytes),
            signature: Data(signatureBytes)
        )
    }

    /// Decodes only the MSO payload from CBOR (convenience when you already have the payload bytes).
    public static func decodePayload(_ payloadData: Data) throws -> MobileSecurityObject {
        guard payloadData.count <= MSOLimits.maxDataSize,
              let cbor = try? CBOR.decode([UInt8](payloadData)),
              case .map(let payloadMap) = cbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        return try parseMSOPayload(payloadMap, dateTimeFormatter: makeDateTimeFormatter())
    }

    // MARK: - Private

    private static func parseMSOPayload(_ map: [CBOR: CBOR], dateTimeFormatter: DateFormatter) throws -> MobileSecurityObject {
        func requiredString(_ key: String) throws -> String {
            guard let cborValue = map[.utf8String(key)], case let .utf8String(string) = cborValue else {
                throw MSOCBORDecodeError.invalidFormat
            }
            return string
        }
        let docType = try requiredString(MSOPayloadKey.docType)
        let validityInfo = try parseValidityInfo(from: map, dateTimeFormatter: dateTimeFormatter)
        let deviceKeyInfo = try parseDeviceKeyInfo(from: map)
        let valueDigests = try parseValueDigests(from: map)
        return MobileSecurityObject(
            docType: docType,
            validityInfo: validityInfo,
            deviceKeyInfo: deviceKeyInfo,
            valueDigests: valueDigests
        )
    }

    private static func parseValidityInfo(from map: [CBOR: CBOR], dateTimeFormatter: DateFormatter) throws -> MSOValidityInfo {
        guard let validityCbor = map[.utf8String(MSOPayloadKey.validityInfo)], case .map(let validityMap) = validityCbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        func dateString(_ key: String) throws -> String {
            guard let cborValue = validityMap[.utf8String(key)], case let .utf8String(string) = cborValue else {
                throw MSOCBORDecodeError.invalidFormat
            }
            return string
        }
        let validFromStr = try dateString(MSOPayloadKey.validFrom)
        let validUntilStr = try dateString(MSOPayloadKey.validUntil)
        guard let validFrom = dateTimeFormatter.date(from: validFromStr),
              let validUntil = dateTimeFormatter.date(from: validUntilStr) else {
            throw MSOCBORDecodeError.invalidFormat
        }
        return MSOValidityInfo(validFrom: validFrom, validUntil: validUntil)
    }

    private static func parseDeviceKeyInfo(from map: [CBOR: CBOR]) throws -> MSODeviceKeyInfo {
        guard let dkiCbor = map[.utf8String(MSOPayloadKey.deviceKeyInfo)], case .map(let dkiMap) = dkiCbor,
              let keyCbor = dkiMap[.utf8String(MSOPayloadKey.deviceKey)] else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let keyData: Data
        switch keyCbor {
        case .map:
            keyData = Data(keyCbor.encode())
        case .byteString(let bytes):
            keyData = Data(bytes)
        default:
            throw MSOCBORDecodeError.invalidFormat
        }
        return MSODeviceKeyInfo(deviceKey: keyData)
    }

    private static func parseValueDigests(from map: [CBOR: CBOR]) throws -> [String: [String: Data]] {
        guard let digestsCbor = map[.utf8String(MSOPayloadKey.valueDigests)], case .map(let digestsMap) = digestsCbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        var result: [String: [String: Data]] = [:]
        for (nsKey, nsValue) in digestsMap {
            guard case .utf8String(let namespace) = nsKey, case .map(let labelToDigest) = nsValue else {
                throw MSOCBORDecodeError.invalidFormat
            }
            var inner: [String: Data] = [:]
            for (labelKey, digestCbor) in labelToDigest {
                let labelStr: String
                switch labelKey {
                case .utf8String(let string): labelStr = string
                case .unsignedInt(let unsigned): labelStr = String(unsigned)
                case .negativeInt(let neg): labelStr = String(-Int(neg) - 1)
                default: throw MSOCBORDecodeError.invalidFormat
                }
                guard case .byteString(let digestBytes) = digestCbor else { throw MSOCBORDecodeError.invalidFormat }
                inner[labelStr] = Data(digestBytes)
            }
            result[namespace] = inner
        }
        return result
    }
}

