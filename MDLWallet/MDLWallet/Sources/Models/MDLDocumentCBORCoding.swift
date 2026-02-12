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
        // Driving privilege sub-keys (§7.2.4)
        static let vehicleCategoryCode = "vehicle_category_code"
        static let privilegeIssueDate = "issue_date"
        static let privilegeExpiryDate = "expiry_date"
    }
}

// MARK: - Date format

/// ISO 8601 date only (YYYY-MM-DD) for encoding/decoding per ISO 18013-5.
private let iso8601DateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd"
    f.timeZone = TimeZone(identifier: "UTC")
    f.locale = Locale(identifier: "en_GB_POSIX")
    return f
}()

// MARK: - CBOR decode errors

/// Errors when decoding an MDLDocument from CBOR.
public enum MDLCBORDecodeError: Error, Sendable {
    case notAMap
    case missingNamespace(String)
    case missingRequiredKey(String)
    case invalidStringValue(key: String)
    case invalidDateValue(key: String, value: String)
    case invalidDrivingPrivileges
    case invalidPrivilegeEntry
    case invalidByteString(key: String)
    case invalidBool(key: String)
}

// MARK: - MDLDocumentCBORCoding

public enum MDLDocumentCBORCoding {

    // MARK: Encode (MDLDocument → Data)

    /// Encodes an `MDLDocument` to CBOR as specified in ISO 18013-5 §7.
    /// Structure: one top-level map with namespace key and a nested map of data elements.
    public static func encode(_ document: MDLDocument) -> Data {
        let itemsPairs = buildItemsMap(from: document)
        let itemsDict = Dictionary(uniqueKeysWithValues: itemsPairs)
        let innerMap = CBOR.map(itemsDict)
        let topLevel = CBOR.map([.utf8String(ISO180135.namespace): innerMap])
        let bytes = topLevel.encode()
        return Data(bytes)
    }

    private static func buildItemsMap(from document: MDLDocument) -> [(CBOR, CBOR)] {
        var pairs: [(CBOR, CBOR)] = []

        // Required string fields
        pairs.append((.utf8String(ISO180135.Key.familyName), .utf8String(document.familyName)))
        pairs.append((.utf8String(ISO180135.Key.givenName), .utf8String(document.givenName)))
        pairs.append((.utf8String(ISO180135.Key.birthDate), .utf8String(iso8601DateFormatter.string(from: document.birthDate))))
        pairs.append((.utf8String(ISO180135.Key.issueDate), .utf8String(iso8601DateFormatter.string(from: document.issueDate))))
        pairs.append((.utf8String(ISO180135.Key.expiryDate), .utf8String(iso8601DateFormatter.string(from: document.expiryDate))))
        pairs.append((.utf8String(ISO180135.Key.issuingCountry), .utf8String(document.issuingCountry)))
        pairs.append((.utf8String(ISO180135.Key.issuingAuthority), .utf8String(document.issuingAuthority)))
        pairs.append((.utf8String(ISO180135.Key.documentNumber), .utf8String(document.documentNumber)))

        // Driving privileges (array of maps)
        let privilegesArray: [CBOR] = document.drivingPrivileges.map { privilege in
            var entries: [(CBOR, CBOR)] = [
                (.utf8String(ISO180135.Key.vehicleCategoryCode), .utf8String(privilege.vehicleCategoryCode))
            ]
            if let d = privilege.issueDate {
                entries.append((.utf8String(ISO180135.Key.privilegeIssueDate), .utf8String(iso8601DateFormatter.string(from: d))))
            }
            if let d = privilege.expiryDate {
                entries.append((.utf8String(ISO180135.Key.privilegeExpiryDate), .utf8String(iso8601DateFormatter.string(from: d))))
            }
            return .map(Dictionary(uniqueKeysWithValues: entries))
        }
        pairs.append((.utf8String(ISO180135.Key.drivingPrivileges), .array(privilegesArray)))

        // Optional fields (omit if nil)
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
    public static func decode(_ data: Data) throws -> MDLDocument {
        let bytes = [UInt8](data)
        let cbor = try CBOR.decode(bytes)
        guard case let .map(topMap) = cbor else {
            throw MDLCBORDecodeError.notAMap
        }

        let namespaceKey = CBOR.utf8String(ISO180135.namespace)
        guard let itemsCbor = topMap[namespaceKey] else {
            throw MDLCBORDecodeError.missingNamespace(ISO180135.namespace)
        }
        guard case let .map(itemsMap) = itemsCbor else {
            throw MDLCBORDecodeError.notAMap
        }

        let getString = { (key: String) throws -> String in
            guard let c = itemsMap[.utf8String(key)], case let .utf8String(s) = c else {
                throw MDLCBORDecodeError.missingRequiredKey(key)
            }
            return s
        }
        let getOptionalString = { (key: String) -> String? in
            guard let c = itemsMap[.utf8String(key)], case let .utf8String(s) = c else { return nil }
            return s
        }

        func parseDate(key: String, value: String) throws -> Date {
            guard let date = iso8601DateFormatter.date(from: value) else {
                throw MDLCBORDecodeError.invalidDateValue(key: key, value: value)
            }
            return date
        }

        let familyName = try getString(ISO180135.Key.familyName)
        let givenName = try getString(ISO180135.Key.givenName)
        let birthDate = try parseDate(key: ISO180135.Key.birthDate, value: try getString(ISO180135.Key.birthDate))
        let issueDate = try parseDate(key: ISO180135.Key.issueDate, value: try getString(ISO180135.Key.issueDate))
        let expiryDate = try parseDate(key: ISO180135.Key.expiryDate, value: try getString(ISO180135.Key.expiryDate))
        let issuingCountry = try getString(ISO180135.Key.issuingCountry)
        let issuingAuthority = try getString(ISO180135.Key.issuingAuthority)
        let documentNumber = try getString(ISO180135.Key.documentNumber)

        // Driving privileges
        guard let privCbor = itemsMap[.utf8String(ISO180135.Key.drivingPrivileges)], case let .array(privArray) = privCbor else {
            throw MDLCBORDecodeError.missingRequiredKey(ISO180135.Key.drivingPrivileges)
        }
        var drivingPrivileges: [DrivingPrivilege] = []
        for item in privArray {
            guard case let .map(entry) = item else { throw MDLCBORDecodeError.invalidPrivilegeEntry }
            guard case let .utf8String(vehicleCategoryCode) = entry[.utf8String(ISO180135.Key.vehicleCategoryCode)] else {
                throw MDLCBORDecodeError.invalidPrivilegeEntry
            }
            let issueDateStr = (entry[.utf8String(ISO180135.Key.privilegeIssueDate)]).flatMap { c in if case .utf8String(let s) = c { return s }; return nil }
            let expiryDateStr = (entry[.utf8String(ISO180135.Key.privilegeExpiryDate)]).flatMap { c in if case .utf8String(let s) = c { return s }; return nil }
            let privIssueDate = issueDateStr.flatMap { iso8601DateFormatter.date(from: $0) }
            let privExpiryDate = expiryDateStr.flatMap { iso8601DateFormatter.date(from: $0) }
            drivingPrivileges.append(DrivingPrivilege(vehicleCategoryCode: vehicleCategoryCode, issueDate: privIssueDate, expiryDate: privExpiryDate))
        }
        if drivingPrivileges.isEmpty {
            throw MDLCBORDecodeError.invalidDrivingPrivileges
        }

        // Optionals
        var portrait: Data?
        if let c = itemsMap[.utf8String(ISO180135.Key.portrait)], case let .byteString(bytes) = c {
            portrait = Data(bytes)
        }

        let nationality = getOptionalString(ISO180135.Key.nationality)

        var ageOver18: Bool?
        if let c = itemsMap[.utf8String(ISO180135.Key.ageOver18)], case let .boolean(b) = c {
            ageOver18 = b
        }

        let residentAddress = getOptionalString(ISO180135.Key.residentAddress)

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
            nationality: nationality,
            ageOver18: ageOver18,
            residentAddress: residentAddress
        )
    }
}
