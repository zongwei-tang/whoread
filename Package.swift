// swift-tools-version:5.9
//
// WhoRead — who read my sensitive files?
//
// The SwiftPM package holds everything that is not an app bundle:
//   WhoReadCore    pure logic (no EndpointSecurity, no IO besides what callers inject)
//   WhoReadStore   SQLite-backed EventStore
//   WhoReadIPC     daemon <-> app/CLI message protocol + transports
//   WhoReadEngine  daemon runtime: event sources, pipeline, kill switch, service handler
//   whoreadd       root daemon executable (dev LaunchDaemon form)
//   whoread        command line client
// The SwiftUI app and the system extension are Xcode targets generated from project.yml
// and link these products.
import PackageDescription

let package = Package(
    name: "WhoRead",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "WhoReadCore", targets: ["WhoReadCore"]),
        .library(name: "WhoReadStore", targets: ["WhoReadStore"]),
        .library(name: "WhoReadIPC", targets: ["WhoReadIPC"]),
        .library(name: "WhoReadEngine", targets: ["WhoReadEngine"]),
        .executable(name: "whoreadd", targets: ["whoreadd"]),
        .executable(name: "whoread", targets: ["whoread"]),
    ],
    targets: [
        .target(name: "WhoReadCore"),
        // macOS ships SQLite3 as an SDK module; Linux (development host) needs a system library shim.
        .systemLibrary(
            name: "CSQLite",
            path: "Sources/CSQLite",
            providers: [.apt(["libsqlite3-dev"])]
        ),
        .target(
            name: "WhoReadStore",
            dependencies: [
                "WhoReadCore",
                .target(name: "CSQLite", condition: .when(platforms: [.linux])),
            ]
        ),
        .target(name: "WhoReadIPC", dependencies: ["WhoReadCore"]),
        .target(
            name: "WhoReadEngine",
            dependencies: ["WhoReadCore", "WhoReadStore", "WhoReadIPC"],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity", .when(platforms: [.macOS])),
                .linkedLibrary("bsm", .when(platforms: [.macOS])),
            ]
        ),
        .executableTarget(name: "whoreadd", dependencies: ["WhoReadEngine"]),
        .executableTarget(name: "whoread", dependencies: ["WhoReadEngine"]),
        .testTarget(name: "WhoReadCoreTests", dependencies: ["WhoReadCore"]),
        .testTarget(name: "WhoReadStoreTests", dependencies: ["WhoReadStore"]),
        .testTarget(name: "WhoReadEngineTests", dependencies: ["WhoReadEngine"]),
    ]
)
