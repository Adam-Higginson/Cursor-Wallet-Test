// MDLDocumentCBORCoding.swift
// Encodes and decodes MDLDocument to/from CBOR per ISO/IEC 18013-5.
//
// ISO 18013-5 §7 defines the data model: data elements live in a namespace
// (e.g. "org.iso.18013.5.1" for mDL). We encode the document as a single
// namespace map: { "org.iso.18013.5.1": { "family_name": "...", ... } }.

import Foundation
import SwiftCBOR

// MARK: - Namespace and element names (ISO 18013-5 §7.2.1)

private enum ISO180135 {
    /// Namespace for mDL data elements (ISO 18013-5 §7).
    static let namespace = "org.iso.18013.5.1"

    /// Data element identifiers (ISO 18013-5 §7.2.1).
    /// Driving privilege entries use the same key names "issue_date" and "expiry_date"
    /// as the document-level dates (ISO 18013-5 §7.2.4); they are disambiguated by context (inside each privilege map).
    enum Key {
        static let familyName = "family_name"
        static let givenName = "given_name"
        static let birthDate = "birth_date"
        static let issueDate = "issue_date"
        static let expiryDate = "expiry_date"
        static let issuingCountry = "issuing_country"
        static let issuingAuthority = "issuing_authority"
        static let documentNumber = "document_number"
        static let drivingPrivileges = "driving_privileges"
        static let portrait = "portrait"
        static let nationality = "nationality"
        static let ageOver18 = "age_over_18"
        static let residentAddress = "resident_address"
        static let vehicleCategoryCode = "vehicle_category_code"
        static let privilegeIssueDate = "issue_date"
        static let privilegeExpiryDate = "expiry_date"
    }
}

// MARK: - Limits (security: prevent memory exhaustion)

private enum CBORLimits {
    /// Maximum size of incoming CBOR payload (1 MiB).
    static let maxDataSize = 1024 * 1024
}

// MARK: - Date format
// ISO 18013-5 §7.2.1 uses calendar date only (no time or timezone). We use YYYY-MM-DD in UTC
// so that encoding is unambiguous and round-trips correctly.

private func makeDateFormatter() -> DateFormatter {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.locale = Locale(identifier: "en_US_POSIX")
    return formatter
}

// MARK: - CBOR decode errors

/// Errors when decoding an MDLDocument from CBOR.
/// Use the `reason` for debugging; avoid showing raw details to end users.
public enum MDLCBORDecodeError: Error, Sendable, Equatable {
    /// Decoded data is not valid mDL CBOR. Associated string describes what failed (for logs/debugging).
    case invalidFormat(reason: String)

    public var reason: String {
        switch self {
        case .invalidFormat(let reason): return reason
        }
    }
}

extension MDLCBORDecodeError: LocalizedError {
    public var errorDescription: String? {
        "MDL CBOR decode failed: \(reason)"
    }
}

// MARK: - MDLDocumentCBORCoding

public enum MDLDocumentCBORCoding {

    // MARK: Encode (MDLDocument → Data)

    /// Encodes an `MDLDocument` to CBOR as specified in ISO 18013-5 §7.
    /// Structure: one top-level map with namespace key and a nested map of data elements.
    public static func encode(_ document: MDLDocument) -> Data {
        let dateFormatter = makeDateFormatter()
        let itemsPairs = buildItemsMap(from: document, dateFormatter: dateFormatter)
        let itemsDict = Dictionary(uniqueKeysWithValues: itemsPairs)
        let innerMap = CBOR.map(itemsDict)
        let topLevel = CBOR.map([.utf8String(ISO180135.namespace): innerMap])
        let bytes = topLevel.encode()
        return Data(bytes)
    }

    private static func buildItemsMap(from document: MDLDocument, dateFormatter: DateFormatter) -> [(CBOR, CBOR)] {
        var pairs: [(CBOR, CBOR)] = []

        pairs.append((.utf8String(ISO180135.Key.familyName), .utf8String(document.familyName)))
        pairs.append((.utf8String(ISO180135.Key.givenName), .utf8String(document.givenName)))
        pairs.append((.utf8String(ISO180135.Key.birthDate), .utf8String(dateFormatter.string(from: document.birthDate))))
        pairs.append((.utf8String(ISO180135.Key.issueDate), .utf8String(dateFormatter.string(from: document.issueDate))))
        pairs.append((.utf8String(ISO180135.Key.expiryDate), .utf8String(dateFormatter.string(from: document.expiryDate))))
        pairs.append((.utf8String(ISO180135.Key.issuingCountry), .utf8String(document.issuingCountry)))
        pairs.append((.utf8String(ISO180135.Key.issuingAuthority), .utf8String(document.issuingAuthority)))
        pairs.append((.utf8String(ISO180135.Key.documentNumber), .utf8String(document.documentNumber)))

        let privilegesArray: [CBOR] = document.drivingPrivileges.map { privilege in
            var entries: [(CBOR, CBOR)] = [
                (.utf8String(ISO180135.Key.vehicleCategoryCode), .utf8String(privilege.vehicleCategoryCode))
            ]
            if let issueDate = privilege.issueDate {
                entries.append((.utf8String(ISO180135.Key.privilegeIssueDate), .utf8String(dateFormatter.string(from: issueDate))))
            }
            if let expiryDate = privilege.expiryDate {
                entries.append((.utf8String(ISO180135.Key.privilegeExpiryDate), .utf8String(dateFormatter.string(from: expiryDate))))
            }
            return .map(Dictionary(uniqueKeysWithValues: entries))
        }
        pairs.append((.utf8String(ISO180135.Key.drivingPrivileges), .array(privilegesArray)))

        if let portrait = document.portrait {
            pairs.append((.utf8String(ISO180135.Key.portrait), .byteString(Array(portrait))))
        }
        if let nationality = document.nationality {
            pairs.append((.utf8String(ISO180135.Key.nationality), .utf8String(nationality)))
        }
        if let ageOver18 = document.ageOver18 {
            pairs.append((.utf8String(ISO180135.Key.ageOver18), .boolean(ageOver18)))
        }
        if let address = document.residentAddress {
            pairs.append((.utf8String(ISO180135.Key.residentAddress), .utf8String(address)))
        }

        return pairs
    }

    // MARK: Decode (Data → MDLDocument)

    /// Decodes credential bytes into a stored credential (document + optional MSO).
    /// Tries simple form first, then IssuerSigned nameSpaces; MSO is parsed if issuerAuth is present.
    public static func decodeStoredCredential(_ data: Data) throws -> StoredCredential {
        let document = try decodeFromCredential(data)
        let mso = Self.decodeMSOFromCredentialIfPresent(data)
        return StoredCredential(document: document, mso: mso)
    }

    /// Attempts to extract and decode MSO from credential CBOR (issuerAuth is a COSE_Sign1 array). Returns nil if not present or parse fails.
    private static func decodeMSOFromCredentialIfPresent(_ data: Data) -> MobileSecurityObject? {
        guard data.count <= CBORLimits.maxDataSize,
              let cbor = try? CBOR.decode([UInt8](data)),
              case let .map(topMap) = cbor else { return nil }
        guard let issuerAuthCbor = topMap[.utf8String("issuerAuth")] else { return nil }
        // issuerAuth is a COSE_Sign1: CBOR array [protected, unprotected, payload, signature]; re-encode and decode.
        let coseBytes = Data(issuerAuthCbor.encode())
        guard let msoResult = try? MSOCBORCoding.decode(coseBytes) else { return nil }
        return msoResult.mso
    }

    /// Decodes credential bytes (simple namespace map or IssuerSigned) into an `MDLDocument`.
    /// Tries simple form first: { "org.iso.18013.5.1": { "family_name": "...", ... } }.
    /// If that fails, tries IssuerSigned: { "nameSpaces": { "org.iso.18013.5.1": [ { "elementIdentifier", "elementValue" }, ... ] } }.
    public static func decodeFromCredential(_ data: Data) throws -> MDLDocument {
        guard data.count <= CBORLimits.maxDataSize else {
            throw MDLCBORDecodeError.invalidFormat(reason: "payload too large (\(data.count) bytes, max \(CBORLimits.maxDataSize))")
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MDLCBORDecodeError.invalidFormat(reason: "CBOR parse failed (not valid CBOR)")
        }
        guard case let .map(topMap) = cbor else {
            throw MDLCBORDecodeError.invalidFormat(reason: "top-level is not a CBOR map")
        }
        let namespaceKey = CBOR.utf8String(ISO180135.namespace)
        let dateFormatter = makeDateFormatter()

        // Try simple form: top-level key is namespace, value is items map.
        if let itemsCbor = topMap[namespaceKey], case let .map(itemsMap) = itemsCbor {
            return try parseDocument(from: itemsMap, dateFormatter: dateFormatter)
        }

        // Try IssuerSigned: "nameSpaces" -> map -> "org.iso.18013.5.1" -> array of IssuerSignedItem.
        guard let nameSpacesCbor = topMap[.utf8String("nameSpaces")], case let .map(nameSpacesMap) = nameSpacesCbor,
              let itemsArrayCbor = nameSpacesMap[.utf8String(ISO180135.namespace)], case let .array(itemsArray) = itemsArrayCbor else {
            let topKeys = describeTopLevelKeys(topMap)
            throw MDLCBORDecodeError.invalidFormat(reason: "expected simple namespace map or IssuerSigned nameSpaces with '\(ISO180135.namespace)'; top-level keys: \(topKeys)")
        }
        var itemsMap: [CBOR: CBOR] = [:]
        for itemCbor in itemsArray {
            // CRI encodes each IssuerSignedItem as CBOR tag 24 (embedded CBOR) + byte string; unwrap to get the map.
            let itemMap: [CBOR: CBOR]
            switch itemCbor {
            case .map(let map):
                itemMap = map
            case .tagged(CBOR.Tag(rawValue: 24), .byteString(let embeddedBytes)):
                guard let inner = try? CBOR.decode(embeddedBytes), case .map(let map) = inner else { continue }
                itemMap = map
            default:
                continue
            }
            guard case let .utf8String(elementIdentifier) = itemMap[.utf8String("elementIdentifier")],
                  let elementValue = itemMap[.utf8String("elementValue")] else {
                continue
            }
            itemsMap[.utf8String(elementIdentifier)] = elementValue
        }
        return try parseDocument(from: itemsMap, dateFormatter: dateFormatter)
    }

    /// Returns a short description of top-level CBOR map keys for debug logging (no values).
    public static func describeCredentialStructure(_ data: Data) -> String {
        guard data.count <= CBORLimits.maxDataSize,
              let cbor = try? CBOR.decode([UInt8](data)),
              case let .map(topMap) = cbor else {
            return "not a map or CBOR parse failed"
        }
        return describeTopLevelKeys(topMap)
    }

    private static func describeTopLevelKeys(_ map: [CBOR: CBOR]) -> String {
        let keys = map.keys.compactMap { cbor -> String? in
            if case .utf8String(let string) = cbor { return string }
            return nil
        }
        return keys.sorted().joined(separator: ", ")
    }

    /// Decodes CBOR data into an `MDLDocument` per ISO 18013-5 §7.
    /// Expects structure: { "org.iso.18013.5.1": { "family_name": "...", ... } }.
    /// Rejects payloads exceeding size or structural limits.
    public static func decode(_ data: Data) throws -> MDLDocument {
        guard data.count <= CBORLimits.maxDataSize else {
            throw MDLCBORDecodeError.invalidFormat(reason: "payload too large")
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MDLCBORDecodeError.invalidFormat(reason: "CBOR parse failed")
        }
        guard case let .map(topMap) = cbor else {
            throw MDLCBORDecodeError.invalidFormat(reason: "top-level is not a map")
        }
        let namespaceKey = CBOR.utf8String(ISO180135.namespace)
        guard let itemsCbor = topMap[namespaceKey] else {
            throw MDLCBORDecodeError.invalidFormat(reason: "namespace '\(ISO180135.namespace)' missing")
        }
        guard case let .map(itemsMap) = itemsCbor else {
            throw MDLCBORDecodeError.invalidFormat(reason: "namespace value is not a map")
        }
        let dateFormatter = makeDateFormatter()
        return try parseDocument(from: itemsMap, dateFormatter: dateFormatter)
    }

    /// CRI encodes LocalDate as tag 1004 (RFC 8943 full-date) + text string; accept plain string or tagged.
    private static func stringFromCBOR(_ cbor: CBOR?) -> String? {
        guard let cbor else { return nil }
        switch cbor {
        case .utf8String(let string):
            return string
        case .tagged(CBOR.Tag(rawValue: 1004), .utf8String(let string)),  // CRI LocalDate: tag 1004 + "YYYY-MM-DD"
             .tagged(CBOR.Tag(rawValue: 0), .utf8String(let string)):     // date-time (e.g. Instant)
            return string
        default:
            return nil
        }
    }

    private static func parseDocument(from itemsMap: [CBOR: CBOR], dateFormatter: DateFormatter) throws -> MDLDocument {
        func requiredString(_ key: String) throws -> String {
            guard let string = stringFromCBOR(itemsMap[.utf8String(key)]) else {
                throw MDLCBORDecodeError.invalidFormat(reason: "missing or non-string required field '\(key)'")
            }
            return string
        }
        func optionalString(_ key: String) -> String? {
            stringFromCBOR(itemsMap[.utf8String(key)])
        }
        func parseDate(key: String, value: String) throws -> Date {
            guard let date = dateFormatter.date(from: value) else {
                throw MDLCBORDecodeError.invalidFormat(reason: "invalid date format for '\(key)' (expected YYYY-MM-DD): '\(value)'")
            }
            return date
        }

        let familyName = try requiredString(ISO180135.Key.familyName)
        let givenName = try requiredString(ISO180135.Key.givenName)
        let birthDate = try parseDate(key: ISO180135.Key.birthDate, value: try requiredString(ISO180135.Key.birthDate))
        let issueDate = try parseDate(key: ISO180135.Key.issueDate, value: try requiredString(ISO180135.Key.issueDate))
        let expiryDate = try parseDate(key: ISO180135.Key.expiryDate, value: try requiredString(ISO180135.Key.expiryDate))
        let issuingCountry = try requiredString(ISO180135.Key.issuingCountry)
        let issuingAuthority = try requiredString(ISO180135.Key.issuingAuthority)
        let documentNumber = try requiredString(ISO180135.Key.documentNumber)

        let drivingPrivileges = try parseDrivingPrivileges(from: itemsMap, dateFormatter: dateFormatter)

        var portrait: Data?
        if let cborValue = itemsMap[.utf8String(ISO180135.Key.portrait)], case let .byteString(byteArray) = cborValue {
            portrait = Data(byteArray)
        }

        var ageOver18: Bool?
        if let cborValue = itemsMap[.utf8String(ISO180135.Key.ageOver18)], case let .boolean(boolValue) = cborValue {
            ageOver18 = boolValue
        }

        return MDLDocument(
            familyName: familyName,
            givenName: givenName,
            birthDate: birthDate,
            issueDate: issueDate,
            expiryDate: expiryDate,
            issuingCountry: issuingCountry,
            issuingAuthority: issuingAuthority,
            documentNumber: documentNumber,
            drivingPrivileges: drivingPrivileges,
            portrait: portrait,
            nationality: optionalString(ISO180135.Key.nationality),
            ageOver18: ageOver18,
            residentAddress: optionalString(ISO180135.Key.residentAddress)
        )
    }

    private static func parseDrivingPrivileges(from itemsMap: [CBOR: CBOR], dateFormatter: DateFormatter) throws -> [DrivingPrivilege] {
        guard let privCbor = itemsMap[.utf8String(ISO180135.Key.drivingPrivileges)], case let .array(privArray) = privCbor else {
            throw MDLCBORDecodeError.invalidFormat(reason: "missing or non-array 'driving_privileges'")
        }
        var result: [DrivingPrivilege] = []
        for item in privArray {
            guard case let .map(entry) = item else {
                throw MDLCBORDecodeError.invalidFormat(reason: "driving_privileges entry is not a map")
            }
            guard let vehicleCategoryCode = stringFromCBOR(entry[.utf8String(ISO180135.Key.vehicleCategoryCode)]) else {
                throw MDLCBORDecodeError.invalidFormat(reason: "driving_privileges entry missing 'vehicle_category_code'")
            }
            let issueDate = parseOptionalDate(from: entry, key: ISO180135.Key.privilegeIssueDate, dateFormatter: dateFormatter)
            let expiryDate = parseOptionalDate(from: entry, key: ISO180135.Key.privilegeExpiryDate, dateFormatter: dateFormatter)
            result.append(DrivingPrivilege(vehicleCategoryCode: vehicleCategoryCode, issueDate: issueDate, expiryDate: expiryDate))
        }
        guard !result.isEmpty else {
            throw MDLCBORDecodeError.invalidFormat(reason: "driving_privileges array is empty")
        }
        return result
    }

    private static func parseOptionalDate(from entry: [CBOR: CBOR], key: String, dateFormatter: DateFormatter) -> Date? {
        guard let string = stringFromCBOR(entry[.utf8String(key)]) else { return nil }
        return dateFormatter.date(from: string)
    }
}
