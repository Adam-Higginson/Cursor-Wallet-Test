// MSOCBORCoding.swift
// Encodes and decodes an ISO 18013-5 Mobile Security Object (MSO) to/from CBOR.
//
// The MSO is transmitted inside a COSE_Sign1 structure (RFC 9052):
//   COSE_Sign1 = [protected (bstr), unprotected (map), payload (bstr), signature (bstr)]
// The payload is a CBOR map with version, digestAlgorithm, docType, validityInfo,
// deviceKeyInfo, and valueDigests.
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

/// CBOR tag for COSE_Sign1 (RFC 9052 §4.2).
private let coseSign1Tag: UInt64 = 18

// MARK: - MSO payload keys (ISO 18013-5 §9.1.2.4)

private enum MSOKey {
    static let version = "version"
    static let digestAlgorithm = "digestAlgorithm"
    static let docType = "docType"
    static let validityInfo = "validityInfo"
    static let deviceKeyInfo = "deviceKeyInfo"
    static let valueDigests = "valueDigests"
    static let signed = "signed"
    static let validFrom = "validFrom"
    static let validUntil = "validUntil"
    static let expectedUpdate = "expectedUpdate"
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
    /// Allowed digest algorithm identifiers per ISO 18013-5.
    static let allowedDigestAlgorithms: Set<String> = ["SHA-256", "SHA-384", "SHA-512"]
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
// Static formatter avoids the cost of constructing DateFormatter on each call.

private let dateTimeFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.locale = Locale(identifier: "en_US_POSIX")
    return formatter
}()

// MARK: - Errors

/// Errors when decoding an MSO from CBOR.
/// Each case targets a specific failure mode for debuggability.
public enum MSOCBORDecodeError: Error, Sendable, Equatable {
    /// Raw CBOR bytes could not be parsed. Includes a description of the underlying error.
    case cborParseError(String)
    /// The outer structure is not a valid COSE_Sign1 (wrong tag, not an array, too few elements, etc.).
    case invalidCOSESign1Structure(String)
    /// The payload CBOR is not a valid MSO map. Includes a description of what went wrong.
    case invalidPayload(String)
    /// The docType is present and well-typed, but not in the allowed set.
    case unsupportedDocType(String)
    /// A date string could not be parsed as ISO 8601.
    case invalidDateFormat(String)
    /// A parsed date is outside the allowed absolute range, or validFrom >= validUntil.
    case validityOutOfRange(String)
    /// The device key exceeds the maximum allowed size.
    case deviceKeyTooLarge(Int)
    /// A value digest has an invalid length or is the wrong CBOR type.
    case invalidDigest(String)
    /// The number of namespaces in valueDigests exceeds the limit.
    case tooManyNamespaces(Int)
    /// A single namespace has more digest entries than allowed.
    case tooManyDigestsPerNamespace(Int)
    /// The input data exceeds the maximum allowed size.
    case dataTooLarge(Int)
}

/// Errors when encoding an MSO.
public enum MSOCBOREncodeError: Error, Sendable, Equatable {
    /// An MSO field is invalid for encoding (e.g. empty docType, dates out of order).
    case invalidField(String)
}

// MARK: - Decode result

/// Result of decoding an MSO from a COSE_Sign1 structure.
/// Provides the parsed MSO plus raw bytes needed for signature verification.
///
/// **Signature verification (RFC 9052 §4.4):**
/// To verify, construct a COSE `Sig_structure`:
/// ```
/// Sig_structure = ["Signature1", protectedHeader, externalAAD, payloadBytes]
/// ```
/// where `externalAAD` is typically empty (`Data()`).
/// CBOR-encode the `Sig_structure` array, then verify `signature` over the
/// resulting bytes using the issuer's public key from the DSC / IACA chain.
public struct MSODecodeResult: Sendable, Equatable {
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
            throw MSOCBORDecodeError.dataTooLarge(data.count)
        }

        let bytes = [UInt8](data)
        let cbor: CBOR
        do {
            guard let decoded = try CBOR.decode(bytes) else {
                throw MSOCBORDecodeError.cborParseError("CBOR decode returned nil")
            }
            cbor = decoded
        } catch let error as MSOCBORDecodeError {
            throw error
        } catch {
            throw MSOCBORDecodeError.cborParseError(error.localizedDescription)
        }

        // COSE_Sign1 is a 4-element array, optionally tagged with tag 18 (RFC 9052 §4.2)
        let array: [CBOR]
        switch cbor {
        case .tagged(let tag, .array(let arr))
            where tag.rawValue == coseSign1Tag && arr.count >= COSESign1Index.requiredCount:
            array = arr
        case .tagged(let tag, _):
            throw MSOCBORDecodeError.invalidCOSESign1Structure(
                "Expected CBOR tag 18 (COSE_Sign1), got tag \(tag.rawValue)"
            )
        case .array(let arr) where arr.count >= COSESign1Index.requiredCount:
            array = arr
        case .array(let arr):
            throw MSOCBORDecodeError.invalidCOSESign1Structure(
                "COSE_Sign1 array has \(arr.count) elements, need at least \(COSESign1Index.requiredCount)"
            )
        default:
            throw MSOCBORDecodeError.invalidCOSESign1Structure(
                "Expected CBOR array or tagged array, got \(cbor)"
            )
        }

        guard case .byteString(let protectedBytes) = array[COSESign1Index.protected] else {
            throw MSOCBORDecodeError.invalidCOSESign1Structure("protected header is not a byte string")
        }
        guard case .byteString(let payloadBytes) = array[COSESign1Index.payload] else {
            throw MSOCBORDecodeError.invalidCOSESign1Structure("payload is not a byte string")
        }
        guard case .byteString(let signatureBytes) = array[COSESign1Index.signature] else {
            throw MSOCBORDecodeError.invalidCOSESign1Structure("signature is not a byte string")
        }

        let payloadCBOR: CBOR
        do {
            guard let decoded = try CBOR.decode(payloadBytes) else {
                throw MSOCBORDecodeError.invalidPayload("payload CBOR decode returned nil")
            }
            payloadCBOR = decoded
        } catch let error as MSOCBORDecodeError {
            throw error
        } catch {
            throw MSOCBORDecodeError.invalidPayload("payload CBOR parse failed: \(error.localizedDescription)")
        }

        guard case .map(let payloadMap) = payloadCBOR else {
            throw MSOCBORDecodeError.invalidPayload("payload is not a CBOR map")
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
        guard payloadData.count <= MSOLimits.maxDataSize else {
            throw MSOCBORDecodeError.dataTooLarge(payloadData.count)
        }

        let cbor: CBOR
        do {
            guard let decoded = try CBOR.decode([UInt8](payloadData)) else {
                throw MSOCBORDecodeError.cborParseError("CBOR decode returned nil")
            }
            cbor = decoded
        } catch let error as MSOCBORDecodeError {
            throw error
        } catch {
            throw MSOCBORDecodeError.cborParseError(error.localizedDescription)
        }

        guard case .map(let payloadMap) = cbor else {
            throw MSOCBORDecodeError.invalidPayload("payload is not a CBOR map")
        }
        return try parseMSOPayload(payloadMap)
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Encode (MobileSecurityObject → Data)
    // ═══════════════════════════════════════════════════════════════

    /// Encodes an MSO payload to CBOR bytes.
    /// Returns the raw CBOR-encoded payload (not wrapped in COSE_Sign1).
    /// Callers wrap this in COSE_Sign1 with their own signing logic.
    /// - Throws: `MSOCBOREncodeError.invalidField` if the MSO has invalid data.
    public static func encodePayload(_ mso: MobileSecurityObject) throws -> Data {
        try validateForEncoding(mso)
        let payloadMap = buildPayloadMap(from: mso)
        let cbor = CBOR.map(payloadMap)
        return Data(cbor.encode())
    }

    /// Wraps an MSO into a COSE_Sign1 structure.
    /// - Parameters:
    ///   - mso: The MSO to encode.
    ///   - protectedHeader: Protected header bytes (empty for no header).
    ///   - unprotectedHeader: Unprotected header map (empty by default; use for x5chain etc.).
    ///   - signature: Signature bytes (caller is responsible for signing).
    ///   - tagged: Whether to wrap in CBOR tag 18 (default true, per RFC 9052).
    /// - Returns: CBOR-encoded COSE_Sign1 bytes.
    /// - Throws: `MSOCBOREncodeError.invalidField` if the MSO has invalid data.
    public static func encodeCOSESign1(
        mso: MobileSecurityObject,
        protectedHeader: Data = Data(),
        unprotectedHeader: [CBOR: CBOR] = [:],
        signature: Data,
        tagged: Bool = true
    ) throws -> Data {
        let payloadBytes = try encodePayload(mso)
        let coseArray: CBOR = .array([
            .byteString([UInt8](protectedHeader)),
            .map(unprotectedHeader),
            .byteString([UInt8](payloadBytes)),
            .byteString([UInt8](signature))
        ])
        let output: CBOR = tagged
            ? .tagged(CBOR.Tag(rawValue: coseSign1Tag), coseArray)
            : coseArray
        return Data(output.encode())
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Encode validation
    // ═══════════════════════════════════════════════════════════════

    private static func validateForEncoding(_ mso: MobileSecurityObject) throws {
        guard !mso.version.isEmpty else {
            throw MSOCBOREncodeError.invalidField("version must not be empty")
        }
        guard !mso.digestAlgorithm.isEmpty else {
            throw MSOCBOREncodeError.invalidField("digestAlgorithm must not be empty")
        }
        guard !mso.docType.isEmpty else {
            throw MSOCBOREncodeError.invalidField("docType must not be empty")
        }
        guard mso.validityInfo.validFrom < mso.validityInfo.validUntil else {
            throw MSOCBOREncodeError.invalidField("validFrom must be before validUntil")
        }
        guard mso.deviceKeyInfo.deviceKey.count > 0 else {
            throw MSOCBOREncodeError.invalidField("deviceKey must not be empty")
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Decode helpers
    // ═══════════════════════════════════════════════════════════════

    private static func parseMSOPayload(_ map: [CBOR: CBOR]) throws -> MobileSecurityObject {
        // version
        guard let versionCbor = map[.utf8String(MSOKey.version)],
              case .utf8String(let version) = versionCbor else {
            throw MSOCBORDecodeError.invalidPayload("version missing or not a string")
        }

        // digestAlgorithm
        guard let algCbor = map[.utf8String(MSOKey.digestAlgorithm)],
              case .utf8String(let digestAlgorithm) = algCbor else {
            throw MSOCBORDecodeError.invalidPayload("digestAlgorithm missing or not a string")
        }

        // docType
        guard let docTypeCbor = map[.utf8String(MSOKey.docType)],
              case .utf8String(let docType) = docTypeCbor else {
            throw MSOCBORDecodeError.invalidPayload("docType missing or not a string")
        }
        guard MSOLimits.allowedDocTypes.contains(docType) else {
            throw MSOCBORDecodeError.unsupportedDocType(docType)
        }

        let validityInfo = try parseValidityInfo(from: map)
        let deviceKeyInfo = try parseDeviceKeyInfo(from: map)
        let valueDigests = try parseValueDigests(from: map)

        return MobileSecurityObject(
            version: version,
            digestAlgorithm: digestAlgorithm,
            docType: docType,
            validityInfo: validityInfo,
            deviceKeyInfo: deviceKeyInfo,
            valueDigests: valueDigests
        )
    }

    private static func parseValidityInfo(from map: [CBOR: CBOR]) throws -> MSOValidityInfo {
        guard let validityCbor = map[.utf8String(MSOKey.validityInfo)],
              case .map(let validityMap) = validityCbor else {
            throw MSOCBORDecodeError.invalidPayload("validityInfo missing or not a map")
        }

        // signed (mandatory)
        guard let signedCbor = validityMap[.utf8String(MSOKey.signed)],
              case .utf8String(let signedStr) = signedCbor else {
            throw MSOCBORDecodeError.invalidPayload("signed missing or not a string")
        }
        guard let signed = dateTimeFormatter.date(from: signedStr) else {
            throw MSOCBORDecodeError.invalidDateFormat("signed: \(signedStr)")
        }

        // validFrom
        guard let fromCbor = validityMap[.utf8String(MSOKey.validFrom)],
              case .utf8String(let fromStr) = fromCbor else {
            throw MSOCBORDecodeError.invalidPayload("validFrom missing or not a string")
        }
        guard let validFrom = dateTimeFormatter.date(from: fromStr) else {
            throw MSOCBORDecodeError.invalidDateFormat("validFrom: \(fromStr)")
        }

        // validUntil
        guard let untilCbor = validityMap[.utf8String(MSOKey.validUntil)],
              case .utf8String(let untilStr) = untilCbor else {
            throw MSOCBORDecodeError.invalidPayload("validUntil missing or not a string")
        }
        guard let validUntil = dateTimeFormatter.date(from: untilStr) else {
            throw MSOCBORDecodeError.invalidDateFormat("validUntil: \(untilStr)")
        }

        // expectedUpdate (optional)
        var expectedUpdate: Date?
        if let euCbor = validityMap[.utf8String(MSOKey.expectedUpdate)],
           case .utf8String(let euStr) = euCbor {
            guard let euDate = dateTimeFormatter.date(from: euStr) else {
                throw MSOCBORDecodeError.invalidDateFormat("expectedUpdate: \(euStr)")
            }
            expectedUpdate = euDate
        }

        // Absolute date range validation
        guard signed > MSOLimits.validityDateMin,
              validFrom > MSOLimits.validityDateMin,
              validUntil > MSOLimits.validityDateMin else {
            throw MSOCBORDecodeError.validityOutOfRange("dates must be after Unix epoch")
        }
        guard signed < MSOLimits.validityDateMax,
              validFrom < MSOLimits.validityDateMax,
              validUntil < MSOLimits.validityDateMax else {
            throw MSOCBORDecodeError.validityOutOfRange("dates must be before year 2100")
        }

        // Ordering validation
        guard validFrom < validUntil else {
            throw MSOCBORDecodeError.validityOutOfRange("validFrom (\(fromStr)) must be before validUntil (\(untilStr))")
        }

        return MSOValidityInfo(signed: signed, validFrom: validFrom, validUntil: validUntil, expectedUpdate: expectedUpdate)
    }

    private static func parseDeviceKeyInfo(from map: [CBOR: CBOR]) throws -> MSODeviceKeyInfo {
        guard let dkiCbor = map[.utf8String(MSOKey.deviceKeyInfo)],
              case .map(let dkiMap) = dkiCbor,
              let keyCbor = dkiMap[.utf8String(MSOKey.deviceKey)] else {
            throw MSOCBORDecodeError.invalidPayload("deviceKeyInfo or deviceKey missing")
        }

        let keyData: Data
        switch keyCbor {
        case .map:
            let encoded = keyCbor.encode()
            guard encoded.count <= MSOLimits.maxDeviceKeySize else {
                throw MSOCBORDecodeError.deviceKeyTooLarge(encoded.count)
            }
            keyData = Data(encoded)
        case .byteString(let bytes):
            guard bytes.count <= MSOLimits.maxDeviceKeySize else {
                throw MSOCBORDecodeError.deviceKeyTooLarge(bytes.count)
            }
            keyData = Data(bytes)
        default:
            throw MSOCBORDecodeError.invalidPayload("deviceKey is neither a map nor a byte string")
        }

        return MSODeviceKeyInfo(deviceKey: keyData)
    }

    private static func parseValueDigests(from map: [CBOR: CBOR]) throws -> [String: [UInt64: Data]] {
        guard let digestsCbor = map[.utf8String(MSOKey.valueDigests)],
              case .map(let digestsMap) = digestsCbor else {
            throw MSOCBORDecodeError.invalidPayload("valueDigests missing or not a map")
        }
        guard digestsMap.count <= MSOLimits.maxNamespaces else {
            throw MSOCBORDecodeError.tooManyNamespaces(digestsMap.count)
        }

        var result: [String: [UInt64: Data]] = [:]
        for (nsKey, nsValue) in digestsMap {
            guard case .utf8String(let namespace) = nsKey else {
                throw MSOCBORDecodeError.invalidPayload("namespace key is not a string")
            }
            guard case .map(let labelToDigest) = nsValue else {
                throw MSOCBORDecodeError.invalidPayload("namespace '\(namespace)' value is not a map")
            }
            guard labelToDigest.count <= MSOLimits.maxDigestsPerNamespace else {
                throw MSOCBORDecodeError.tooManyDigestsPerNamespace(labelToDigest.count)
            }

            var inner: [UInt64: Data] = [:]
            for (labelKey, digestCbor) in labelToDigest {
                guard case .unsignedInt(let digestID) = labelKey else {
                    throw MSOCBORDecodeError.invalidDigest("digest ID must be an unsigned integer, got \(labelKey)")
                }
                guard case .byteString(let digestBytes) = digestCbor else {
                    throw MSOCBORDecodeError.invalidDigest("digest value for ID \(digestID) is not a byte string")
                }
                guard MSOLimits.allowedDigestLengths.contains(digestBytes.count) else {
                    throw MSOCBORDecodeError.invalidDigest(
                        "digest ID \(digestID) has length \(digestBytes.count), expected one of \(MSOLimits.allowedDigestLengths.sorted())"
                    )
                }
                inner[digestID] = Data(digestBytes)
            }
            result[namespace] = inner
        }
        return result
    }

    // ═══════════════════════════════════════════════════════════════
    // MARK: Private — Encode helpers
    // ═══════════════════════════════════════════════════════════════

    private static func buildPayloadMap(from mso: MobileSecurityObject) -> [CBOR: CBOR] {
        var map: [CBOR: CBOR] = [:]

        // version
        map[.utf8String(MSOKey.version)] = .utf8String(mso.version)

        // digestAlgorithm
        map[.utf8String(MSOKey.digestAlgorithm)] = .utf8String(mso.digestAlgorithm)

        // docType
        map[.utf8String(MSOKey.docType)] = .utf8String(mso.docType)

        // validityInfo
        var validityMap: [CBOR: CBOR] = [
            .utf8String(MSOKey.signed): .utf8String(dateTimeFormatter.string(from: mso.validityInfo.signed)),
            .utf8String(MSOKey.validFrom): .utf8String(dateTimeFormatter.string(from: mso.validityInfo.validFrom)),
            .utf8String(MSOKey.validUntil): .utf8String(dateTimeFormatter.string(from: mso.validityInfo.validUntil))
        ]
        if let expectedUpdate = mso.validityInfo.expectedUpdate {
            validityMap[.utf8String(MSOKey.expectedUpdate)] = .utf8String(dateTimeFormatter.string(from: expectedUpdate))
        }
        map[.utf8String(MSOKey.validityInfo)] = .map(validityMap)

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

        // valueDigests — digest IDs are unsigned integers
        var digestsMap: [CBOR: CBOR] = [:]
        for (namespace, digests) in mso.valueDigests {
            var innerMap: [CBOR: CBOR] = [:]
            for (digestID, digestData) in digests {
                innerMap[.unsignedInt(digestID)] = .byteString([UInt8](digestData))
            }
            digestsMap[.utf8String(namespace)] = .map(innerMap)
        }
        map[.utf8String(MSOKey.valueDigests)] = .map(digestsMap)

        return map
    }
}
