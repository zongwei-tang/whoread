// swift-tools-version:5.9
// Type-checks Sources/WhoReadEngine/Sources/NativeESSource.swift on a non-Mac host against a stub
// EndpointSecurity module whose declarations copy the macOS 27 SDK headers as Swift imports them.
// check-stub.sh (on a Mac) checks every stub declaration and raw value against the real SDK. This
// proves the Swift usage is type-correct against the SDK's shapes; it does NOT replace compiling
// against the real SDK.
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
