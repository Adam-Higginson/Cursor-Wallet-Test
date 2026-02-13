// MSOCBORCoding.swift
// Encodes and decodes an ISO 18013-5 Mobile Security Object (MSO) to/from CBOR.
//
// The MSO is transmitted inside a COSE_Sign1 structure (RFC 9052):
//   COSE_Sign1 = [protected (bstr), unprotected (map), payload (bstr), signature (bstr)]
// The payload is a CBOR map with docType, validityInfo, deviceKeyInfo, and valueDigests.
//
// This module handles encoding and decoding of the MSO payload and the
// COSE_Sign1 wrapper. It does NOT sign or verify signatures — callers
// should handle that using the Document Signer Certificate (DSC) and
// IACA chain.

import Foundation
import SwiftCBOR

// MARK: - COSE_Sign1 layout (RFC 9052)

private enum COSESign1Index {
    static let protected = 0
    static let unprotected = 1
    static let payload = 2
    static let signature = 3
    static let requiredCount = 4
}

// MARK: - MSO payload keys (ISO 18013-5 §9.1.2.4)

private enum MSOKey {
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
    /// Maximum CBOR payload size (1 MiB).
    static let maxDataSize = 1024 * 1024
    /// Maximum encoded device key size (16 KiB).
    static let maxDeviceKeySize = 16 * 1024
    /// Allowed digest byte lengths: SHA-256 (32), SHA-384 (48), SHA-512 (64).
    static let allowedDigestLengths: Set<Int> = [32, 48, 64]
    /// Maximum namespaces in valueDigests.
    static let maxNamespaces = 128
    /// Maximum digest entries per namespace.
    static let maxDigestsPerNamespace = 256
    /// Validity dates must be after Unix epoch.
    static let validityDateMin = Date(timeIntervalSince1970: 0)
    /// Validity dates must be before year 2100.
    static let validityDateMax = Date(timeIntervalSince1970: 4_102_444_800) // 2100-01-01T00:00:00Z
    /// Accepted docType values for this mDL wallet.
    static let allowedDocTypes: Set<String> = ["org.iso.18013.5.1.mDL"]
}

// MARK: - Date-time format (ISO 8601 with time, UTC)

private func makeDateTimeFormatter() -> DateFormatter {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.locale = Locale(identifier: "en_US_POSIX")
    return formatter
}

// MARK: - Errors

/// Errors when decoding an MSO from CBOR.
public enum MSOCBORDecodeError: Error, Sendable {
    /// The data is not a valid MSO or COSE_Sign1 structure.
    case invalidFormat
}

// MARK: - Decode result

/// Result of decoding an MSO from a COSE_Sign1 structure.
/// Provides the parsed MSO plus raw bytes needed for signature verification.
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

    // ═══════════════════════════════════════════════════════════════
    // MARK: Decode (Data → MSODecodeResult)
    // ═══════════════════════════════════════════════════════════════

    /// Decodes a full MSO from CBOR data containing a COSE_Sign1 structure.
    /// Returns the MSO and raw COSE_Sign1 components for signature verification.
    public static func decode(_ data: Data) throws -> MSODecodeResult {
        guard data.count <= MSOLimits.maxDataSize else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MSOCBORDecodeError.invalidFormat
        }

        // COSE_Sign1 is a 4-element array, optionally tagged (tag 18)
        let array: [CBOR]
        switch cbor {
        case .tagged(_, .array(let arr)) where arr.count >= COSESign1Index.requiredCount:
            array = arr
        case .array(let arr) where arr.count >= COSESign1Index.requiredCount:
            array = arr
        default:
            throw MSOCBORDecodeError.invalidFormat
        }

        guard case .byteString(let protectedBytes) = array[COSESign1Index.protected],
              case .byteString(let payloadBytes) = array[COSESign1Index.payload],
              case .byteString(let signatureBytes) = array[COSESign1Index.signature] else {
            throw MSOCBORDecodeError.invalidFormat
        }

        guard let payloadCBOR = try? CBOR.decode(payloadBytes),
              case .map(let payloadMap) = payloadCBOR else {
            throw MSOCBORDecodeError.invalidFormat
        }

        let mso = try parseMSOPayload(payloadMap)

        return MSODecodeResult(
            mso: mso,
            protectedHeader: Data(protectedBytes),
            payloadBytes: Data(payloadBytes),
            signature: Data(signatureBytes)
        )
    }

    /// Decodes only the MSO payload from raw CBOR bytes (when you already have the payload).
    public static func decodePayload(_ payloadData: Data) throws -> MobileSecurityObject {
        guard payloadData.count <= MSOLimits.maxDataSize,
              let cbor = try? CBOR.decode([UInt8](payloadData)),
              case .map(let payloadMap) = cbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        return try parseMSOPayload(payloadMap)
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Encode (MobileSecurityObject → Data)
    // ═══════════════════════════════════════════════════════════════

    /// Encodes an MSO payload to CBOR bytes.
    /// Returns the raw CBOR-encoded payload (not wrapped in COSE_Sign1).
    /// Callers wrap this in COSE_Sign1 with their own signing logic.
    public static func encodePayload(_ mso: MobileSecurityObject) -> Data {
        let dateTimeFormatter = makeDateTimeFormatter()
        let payloadMap = buildPayloadMap(from: mso, dateTimeFormatter: dateTimeFormatter)
        let cbor = CBOR.map(payloadMap)
        return Data(cbor.encode())
    }

    /// Wraps an MSO into a COSE_Sign1 structure (untagged).
    /// - Parameters:
    ///   - mso: The MSO to encode.
    ///   - protectedHeader: Protected header bytes (empty for no header).
    ///   - signature: Signature bytes (caller is responsible for signing).
    /// - Returns: CBOR-encoded COSE_Sign1 bytes.
    public static func encodeCOSESign1(
        mso: MobileSecurityObject,
        protectedHeader: Data = Data(),
        signature: Data
    ) -> Data {
        let payloadBytes = encodePayload(mso)
        let coseSign1: CBOR = .array([
            .byteString([UInt8](protectedHeader)),
            .map([:]),
            .byteString([UInt8](payloadBytes)),
            .byteString([UInt8](signature))
        ])
        return Data(coseSign1.encode())
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Decode helpers
    // ═══════════════════════════════════════════════════════════════

    private static func parseMSOPayload(_ map: [CBOR: CBOR]) throws -> MobileSecurityObject {
        // docType
        guard let docTypeCbor = map[.utf8String(MSOKey.docType)],
              case .utf8String(let docType) = docTypeCbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        guard MSOLimits.allowedDocTypes.contains(docType) else {
            throw MSOCBORDecodeError.invalidFormat
        }

        let validityInfo = try parseValidityInfo(from: map)
        let deviceKeyInfo = try parseDeviceKeyInfo(from: map)
        let valueDigests = try parseValueDigests(from: map)

        return MobileSecurityObject(
            docType: docType,
            validityInfo: validityInfo,
            deviceKeyInfo: deviceKeyInfo,
            valueDigests: valueDigests
        )
    }

    private static func parseValidityInfo(from map: [CBOR: CBOR]) throws -> MSOValidityInfo {
        guard let validityCbor = map[.utf8String(MSOKey.validityInfo)],
              case .map(let validityMap) = validityCbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        let dateTimeFormatter = makeDateTimeFormatter()

        guard let fromCbor = validityMap[.utf8String(MSOKey.validFrom)],
              case .utf8String(let fromStr) = fromCbor,
              let validFrom = dateTimeFormatter.date(from: fromStr) else {
            throw MSOCBORDecodeError.invalidFormat
        }
        guard let untilCbor = validityMap[.utf8String(MSOKey.validUntil)],
              case .utf8String(let untilStr) = untilCbor,
              let validUntil = dateTimeFormatter.date(from: untilStr) else {
            throw MSOCBORDecodeError.invalidFormat
        }

        // Date range validation
        guard validFrom > MSOLimits.validityDateMin,
              validUntil < MSOLimits.validityDateMax else {
            throw MSOCBORDecodeError.invalidFormat
        }

        return MSOValidityInfo(validFrom: validFrom, validUntil: validUntil)
    }

    private static func parseDeviceKeyInfo(from map: [CBOR: CBOR]) throws -> MSODeviceKeyInfo {
        guard let dkiCbor = map[.utf8String(MSOKey.deviceKeyInfo)],
              case .map(let dkiMap) = dkiCbor,
              let keyCbor = dkiMap[.utf8String(MSOKey.deviceKey)] else {
            throw MSOCBORDecodeError.invalidFormat
        }

        let keyData: Data
        switch keyCbor {
        case .map:
            let encoded = keyCbor.encode()
            guard encoded.count <= MSOLimits.maxDeviceKeySize else {
                throw MSOCBORDecodeError.invalidFormat
            }
            keyData = Data(encoded)
        case .byteString(let bytes):
            guard bytes.count <= MSOLimits.maxDeviceKeySize else {
                throw MSOCBORDecodeError.invalidFormat
            }
            keyData = Data(bytes)
        default:
            throw MSOCBORDecodeError.invalidFormat
        }

        return MSODeviceKeyInfo(deviceKey: keyData)
    }

    private static func parseValueDigests(from map: [CBOR: CBOR]) throws -> [String: [String: Data]] {
        guard let digestsCbor = map[.utf8String(MSOKey.valueDigests)],
              case .map(let digestsMap) = digestsCbor else {
            throw MSOCBORDecodeError.invalidFormat
        }
        guard digestsMap.count <= MSOLimits.maxNamespaces else {
            throw MSOCBORDecodeError.invalidFormat
        }

        var result: [String: [String: Data]] = [:]
        for (nsKey, nsValue) in digestsMap {
            guard case .utf8String(let namespace) = nsKey,
                  case .map(let labelToDigest) = nsValue else {
                throw MSOCBORDecodeError.invalidFormat
            }
            guard labelToDigest.count <= MSOLimits.maxDigestsPerNamespace else {
                throw MSOCBORDecodeError.invalidFormat
            }

            var inner: [String: Data] = [:]
            for (labelKey, digestCbor) in labelToDigest {
                let labelStr: String
                switch labelKey {
                case .utf8String(let s): labelStr = s
                case .unsignedInt(let u): labelStr = String(u)
                default: throw MSOCBORDecodeError.invalidFormat
                }
                guard case .byteString(let digestBytes) = digestCbor,
                      MSOLimits.allowedDigestLengths.contains(digestBytes.count) else {
                    throw MSOCBORDecodeError.invalidFormat
                }
                inner[labelStr] = Data(digestBytes)
            }
            result[namespace] = inner
        }
        return result
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Encode helpers
    // ═══════════════════════════════════════════════════════════════

    private static func buildPayloadMap(
        from mso: MobileSecurityObject,
        dateTimeFormatter: DateFormatter
    ) -> [CBOR: CBOR] {
        var map: [CBOR: CBOR] = [:]

        // docType
        map[.utf8String(MSOKey.docType)] = .utf8String(mso.docType)

        // validityInfo
        map[.utf8String(MSOKey.validityInfo)] = .map([
            .utf8String(MSOKey.validFrom): .utf8String(dateTimeFormatter.string(from: mso.validityInfo.validFrom)),
            .utf8String(MSOKey.validUntil): .utf8String(dateTimeFormatter.string(from: mso.validityInfo.validUntil))
        ])

        // deviceKeyInfo — re-encode the raw COSE_Key bytes as-is
        let deviceKeyCbor: CBOR
        if let decoded = try? CBOR.decode([UInt8](mso.deviceKeyInfo.deviceKey)),
           case .map = decoded {
            deviceKeyCbor = decoded
        } else {
            deviceKeyCbor = .byteString([UInt8](mso.deviceKeyInfo.deviceKey))
        }
        map[.utf8String(MSOKey.deviceKeyInfo)] = .map([
            .utf8String(MSOKey.deviceKey): deviceKeyCbor
        ])

        // valueDigests
        var digestsMap: [CBOR: CBOR] = [:]
        for (namespace, digests) in mso.valueDigests {
            var innerMap: [CBOR: CBOR] = [:]
            for (label, digestData) in digests {
                if let intLabel = UInt64(label) {
                    innerMap[.unsignedInt(intLabel)] = .byteString([UInt8](digestData))
                } else {
                    innerMap[.utf8String(label)] = .byteString([UInt8](digestData))
                }
            }
            digestsMap[.utf8String(namespace)] = .map(innerMap)
        }
        map[.utf8String(MSOKey.valueDigests)] = .map(digestsMap)

        return map
    }
}
