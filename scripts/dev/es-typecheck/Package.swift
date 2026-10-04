// swift-tools-version:5.9
// Type-checks Sources/WhoReadEngine/Sources/NativeESSource.swift on a non-Mac host against a stub
// EndpointSecurity module whose declarations copy the Swift signatures Apple's DocC shows (see
// docs/research/endpoint-security-api.md). It proves the Swift usage is type-correct against the
// documented API shapes; it does NOT replace compiling against the real SDK.
// Run: cd scripts/dev/es-typecheck && swift build
import PackageDescription

let package = Package(
    name: "ESTypecheck",
    targets: [
        .target(name: "WhoReadCore"),
        .systemLibrary(name: "CSQLite"),
        .target(name: "WhoReadStore", dependencies: ["WhoReadCore", "CSQLite"]),
        .target(name: "WhoReadIPC", dependencies: ["WhoReadCore"]),
        .target(name: "EndpointSecurity"),
        .target(name: "WhoReadEngine", dependencies: ["WhoReadCore", "WhoReadStore", "WhoReadIPC", "EndpointSecurity"]),
    ]
)
