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
            issuingCountry: "US",
            issuingAuthority: "State of California",
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
}


