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
    formatter.locale = Locale(identifier: "en_GB_POSIX")
    return formatter
}

// MARK: - CBOR decode errors

/// Errors when decoding an MDLDocument from CBOR.
/// We expose only a generic invalidFormat to avoid leaking document structure to callers.
public enum MDLCBORDecodeError: Error, Sendable {
    /// Decoded data is not valid mDL CBOR (structure, size, or content).
    case invalidFormat
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

    /// Decodes CBOR data into an `MDLDocument` per ISO 18013-5 §7.
    /// Expects structure: { "org.iso.18013.5.1": { "family_name": "...", ... } }.
    /// Rejects payloads exceeding size or structural limits.
    public static func decode(_ data: Data) throws -> MDLDocument {
        guard data.count <= CBORLimits.maxDataSize else {
            throw MDLCBORDecodeError.invalidFormat
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MDLCBORDecodeError.invalidFormat
        }
        guard case let .map(topMap) = cbor else {
            throw MDLCBORDecodeError.invalidFormat
        }
        let namespaceKey = CBOR.utf8String(ISO180135.namespace)
        guard let itemsCbor = topMap[namespaceKey] else {
            throw MDLCBORDecodeError.invalidFormat
        }
        guard case let .map(itemsMap) = itemsCbor else {
            throw MDLCBORDecodeError.invalidFormat
        }
        let dateFormatter = makeDateFormatter()
        return try parseDocument(from: itemsMap, dateFormatter: dateFormatter)
    }

    private static func parseDocument(from itemsMap: [CBOR: CBOR], dateFormatter: DateFormatter) throws -> MDLDocument {
        func requiredString(_ key: String) throws -> String {
            guard let cborValue = itemsMap[.utf8String(key)], case let .utf8String(string) = cborValue else {
                throw MDLCBORDecodeError.invalidFormat
            }
            return string
        }
        func optionalString(_ key: String) -> String? {
            guard let cborValue = itemsMap[.utf8String(key)], case let .utf8String(string) = cborValue else {
                return nil
            }
            return string
        }
        func parseDate(key: String, value: String) throws -> Date {
            guard let date = dateFormatter.date(from: value) else {
                throw MDLCBORDecodeError.invalidFormat
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
            throw MDLCBORDecodeError.invalidFormat
        }
        var result: [DrivingPrivilege] = []
        for item in privArray {
            guard case let .map(entry) = item else { throw MDLCBORDecodeError.invalidFormat }
            guard case let .utf8String(vehicleCategoryCode) = entry[.utf8String(ISO180135.Key.vehicleCategoryCode)] else {
                throw MDLCBORDecodeError.invalidFormat
            }
            let issueDate = parseOptionalDate(from: entry, key: ISO180135.Key.privilegeIssueDate, dateFormatter: dateFormatter)
            let expiryDate = parseOptionalDate(from: entry, key: ISO180135.Key.privilegeExpiryDate, dateFormatter: dateFormatter)
            result.append(DrivingPrivilege(vehicleCategoryCode: vehicleCategoryCode, issueDate: issueDate, expiryDate: expiryDate))
        }
        guard !result.isEmpty else {
            throw MDLCBORDecodeError.invalidFormat
        }
        return result
    }

    private static func parseOptionalDate(from entry: [CBOR: CBOR], key: String, dateFormatter: DateFormatter) -> Date? {
        guard let cborValue = entry[.utf8String(key)], case let .utf8String(string) = cborValue else {
            return nil
        }
        return dateFormatter.date(from: string)
    }
}
