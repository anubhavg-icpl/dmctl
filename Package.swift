// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DManagement",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "dmctl", targets: ["DManagement"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0")
    ],
    targets: [
        .executableTarget(
            name: "DManagement",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        ),
        .testTarget(
            name: "DManagementTests",
            dependencies: ["DManagement"]
        )
    ]
)
