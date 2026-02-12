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
                        "UIImageName": "",
                    ],
                ]
            ),
            buildableFolders: [
                "MDLWallet/Sources",
                "MDLWallet/Resources",
            ],
            dependencies: []
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
            dependencies: [.target(name: "MDLWallet")]
        ),
    ]
)
