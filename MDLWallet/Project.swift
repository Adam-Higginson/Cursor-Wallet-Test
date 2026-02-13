import ProjectDescription

let project = Project(
    name: "MDLWallet",
    targets: [
        .target(
            name: "MDLWallet",
            destinations: .iOS,
            product: .app,
            bundleId: "dev.tuist.MDLWallet",
            infoPlist: .extendingDefault(
                with: [
                    "UILaunchScreen": [
                        "UIColorName": "",
                        "UIImageName": ""
                    ],
                    "NSCameraUsageDescription": "We need camera access to scan QR codes for credential issuance.",
                    "CFBundleURLTypes": [
                        [
                            "CFBundleURLSchemes": ["openid-credential-offer"],
                            "CFBundleTypeRole": "Editor",
                            "CFBundleURLName": "OID4VCI Credential Offer"
                        ]
                    ]
                ]
            ),
            buildableFolders: [
                "MDLWallet/Sources",
                "MDLWallet/Resources"
            ],
            dependencies: [.external(name: "SwiftCBOR")]
        ),
        .target(
            name: "MDLWalletTests",
            destinations: .iOS,
            product: .unitTests,
            bundleId: "dev.tuist.MDLWalletTests",
            infoPlist: .default,
            buildableFolders: [
                "MDLWallet/Tests"
            ],
            dependencies: [.target(name: "MDLWallet"), .external(name: "SwiftCBOR")]
        )
    ]
)
