import Foundation

/// Describes a set of processes by location and code identity. Used for category owners,
/// benign system services and AI agents' bundle constraints.
///
/// Semantics: every *provided* constraint must hold (AND); inside one list any entry may match (OR).
/// - Location: `executables` (path globs), `bundles` (bundle path globs, matched against every
///   `.app` on the executable's path) and `names` (executable basename) are alternatives — if any
///   of the three is provided, at least one must match.
/// - Identity: `signingIDs` (exact, or prefix when ending in `*`), `teamIDs`, `cdhashes`,
///   `platformBinary`.
/// - Interpreted tools: `argvGlobs` must match some argv element (e.g. the script path of
///   `python3 /opt/homebrew/bin/aws`). argv is caller-controlled, so such owners are weak.
public struct IdentitySpec: Codable, Hashable, Sendable {
    public var label: String?
    public var executables: [Glob]?
    public var bundles: [Glob]?
    public var names: [String]?
    public var signingIDs: [String]?
    public var teamIDs: [String]?
    public var cdhashes: [String]?
    public var platformBinary: Bool?
    public var argvGlobs: [Glob]?

    public init(
        label: String? = nil,
        executables: [String]? = nil,
        bundles: [String]? = nil,
        names: [String]? = nil,
        signingIDs: [String]? = nil,
        teamIDs: [String]? = nil,
        cdhashes: [String]? = nil,
        platformBinary: Bool? = nil,
        argvGlobs: [String]? = nil
    ) {
        self.label = label
        self.executables = executables?.map(Glob.init)
        self.bundles = bundles?.map(Glob.init)
        self.names = names
        self.signingIDs = signingIDs
        self.teamIDs = teamIDs
        self.cdhashes = cdhashes
        self.platformBinary = platformBinary
        self.argvGlobs = argvGlobs?.map(Glob.init)
    }

    /// True when the spec pins code identity, not just a location the user may be able to write to.
    public var isVerified: Bool {
        !(signingIDs ?? []).isEmpty || !(teamIDs ?? []).isEmpty || !(cdhashes ?? []).isEmpty || platformBinary == true
    }

    public func matches(_ p: ProcessRecord) -> Bool {
        let hasLocation = !(executables ?? []).isEmpty || !(bundles ?? []).isEmpty || !(names ?? []).isEmpty
        if hasLocation {
            var located = false
            if let executables, executables.contains(where: { $0.matches(p.executablePath) }) {
                located = true
            }
            if !located, let bundles, !bundles.isEmpty {
                let appBundles = BundlePath.appBundles(in: p.executablePath)
                located = appBundles.contains { app in bundles.contains { $0.matches(app) } }
            }
            if !located, let names, !names.isEmpty {
                let n = PathNormalizer.fold(p.name)
                located = names.contains { PathNormalizer.fold($0) == n }
            }
            if !located { return false }
        }
        if let signingIDs, !signingIDs.isEmpty {
            guard let sid = p.signingID else { return false }
            let ok = signingIDs.contains { pattern in
                pattern.hasSuffix("*") ? sid.hasPrefix(String(pattern.dropLast())) : sid == pattern
            }
            if !ok { return false }
        }
        if let teamIDs, !teamIDs.isEmpty {
            guard let team = p.teamID, teamIDs.contains(team) else { return false }
        }
        if let cdhashes, !cdhashes.isEmpty {
            guard let cd = p.cdhash?.lowercased(), cdhashes.contains(where: { $0.lowercased() == cd }) else { return false }
        }
        if let platformBinary, platformBinary != p.isPlatformBinary {
            return false
        }
        if let argvGlobs, !argvGlobs.isEmpty {
            guard let argv = p.argv, argv.contains(where: { arg in argvGlobs.contains { $0.matches(arg) } }) else {
                return false
            }
        }
        // A spec with no constraints at all matches nothing: an empty owner must not bless everyone.
        return hasLocation || !(signingIDs ?? []).isEmpty || !(teamIDs ?? []).isEmpty
            || !(cdhashes ?? []).isEmpty || !(argvGlobs ?? []).isEmpty
    }
}
