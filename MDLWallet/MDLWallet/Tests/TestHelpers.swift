import Foundation
@testable import MDLWallet

enum TestHelpers {
    static func makeMinimalDocument(givenName: String = "Alice") -> MDLDocument {
        MDLDocument(
            familyName: "Smith",
            givenName: givenName,
            birthDate: makeDate(year: 1990, month: 6, day: 15),
            issueDate: makeDate(year: 2024, month: 1, day: 1),
            expiryDate: makeDate(year: 2029, month: 1, day: 1),
            issuingCountry: "UK",
            issuingAuthority: "DVLA",
            documentNumber: "DL123456789",
            drivingPrivileges: [
                DrivingPrivilege(vehicleCategoryCode: "B")
            ]
        )
    }

    static func makeDate(year: Int, month: Int, day: Int) -> Date {
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day

        return Calendar.current.date(from: components)!
    }

    /// Date at midnight UTC for the given day. Use in CBOR round-trip tests so
    /// encode (UTC YYYY-MM-DD) and decode produce the same Date.
    static func makeDateUTC(year: Int, month: Int, day: Int) -> Date {
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = 0
        components.minute = 0
        components.second = 0
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: components)!
    }

    /// Minimal document with UTC dates for CBOR encoding tests.
    static func makeMinimalDocumentForCBOR() -> MDLDocument {
        MDLDocument(
            familyName: "Smith",
            givenName: "Alice",
            birthDate: makeDateUTC(year: 1990, month: 6, day: 15),
            issueDate: makeDateUTC(year: 2024, month: 1, day: 1),
            expiryDate: makeDateUTC(year: 2029, month: 1, day: 1),
            issuingCountry: "UK",
            issuingAuthority: "DVLA",
            documentNumber: "DL123456789",
            drivingPrivileges: [
                DrivingPrivilege(vehicleCategoryCode: "B")
            ]
        )
    }
}


