import Foundation

/// Describes a set of processes by location and code identity. Used for category owners,
/// benign system services and AI agents' bundle constraints.
///
/// Semantics: every *provided* constraint must hold (AND); inside one list any entry may match (OR).
/// - Location: `executables` (path globs) and `bundles` (bundle path globs, matched against every
///   `.app` on the executable's path) are alternatives — if either is provided, one must match.
/// - Identity: `signingIDs` (exact, or prefix when ending in `*`), `teamIDs`, `cdhashes`,
///   `platformBinary` (only honoured in root-owned system locations unless signing IDs are pinned).
/// - Narrowing only: `names` (executable basename) and `argvGlobs` (the script an interpreter runs,
///   e.g. `python3 /opt/homebrew/bin/aws`). They never make a spec match on their own.
/// - A spec must pin a location or a code identity; third-party bundles need a team ID.
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

    /// Root-owned system locations. A copied Apple binary keeps its platform flag (it follows the
    /// signature, not the path), so "platform binary" only means "system tool" in these places.
    static let systemLocations = ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/",
                                  "/Library/Apple/", "/Library/Developer/CommandLineTools/"]

    /// True for an executable in a root-owned system location. `/System/Volumes/Data/…` is the
    /// writable data volume (`/Users`, `/private/tmp`…) under another spelling, not a system location.
    static func isSystemLocation(_ path: String) -> Bool {
        systemLocations.contains { path.hasPrefix($0) } && !PathNormalizer.fold(path).hasPrefix("/system/volumes/data/")
    }

    public func matches(_ p: ProcessRecord) -> Bool {
        let executables = self.executables ?? [], bundles = self.bundles ?? []
        let signingIDs = self.signingIDs ?? [], teamIDs = self.teamIDs ?? [], cdhashes = self.cdhashes ?? []
        // Names and argv are caller-controlled: they only narrow a spec that also pins a location or
        // code identity. A spec that pins nothing matches nothing.
        guard !executables.isEmpty || !bundles.isEmpty || !signingIDs.isEmpty || !teamIDs.isEmpty || !cdhashes.isEmpty else {
            return false
        }
        if !executables.isEmpty || !bundles.isEmpty {
            var located = executables.contains { $0.matches(p.executablePath) }
            if !located && !bundles.isEmpty {
                let appBundles = BundlePath.appBundles(in: p.executablePath)
                located = appBundles.contains { app in bundles.contains { $0.matches(app) } }
            }
            if !located { return false }
        }
        if let names, !names.isEmpty {
            let n = PathNormalizer.fold(p.name)
            guard names.contains(where: { PathNormalizer.fold($0) == n }) else { return false }
        }
        if !signingIDs.isEmpty {
            guard let sid = p.signingID else { return false }
            let ok = signingIDs.contains { pattern in
                pattern.hasSuffix("*") ? sid.hasPrefix(String(pattern.dropLast())) : sid == pattern
            }
            if !ok { return false }
        }
        if !teamIDs.isEmpty {
            guard let team = p.teamID, teamIDs.contains(team) else { return false }
        }
        if !cdhashes.isEmpty {
            guard let cd = p.cdhash?.lowercased(), cdhashes.contains(where: { $0.lowercased() == cd }) else { return false }
        }
        if let platformBinary {
            if platformBinary != p.isPlatformBinary { return false }
            if platformBinary && signingIDs.isEmpty && !IdentitySpec.isSystemLocation(p.executablePath) {
                return false
            }
        }
        // A third-party bundle owner is only trusted once its team ID is known (resolved from
        // `codesign -dv` on this Mac): /Applications is writable by admin users.
        if !bundles.isEmpty && teamIDs.isEmpty && signingIDs.isEmpty && cdhashes.isEmpty && platformBinary != true
            && !bundles.allSatisfy({ $0.pattern.hasPrefix("/System/") }) {
            return false
        }
        if let argvGlobs, !argvGlobs.isEmpty {
            guard let script = IdentitySpec.scriptArgument(p.argv), argvGlobs.contains(where: { $0.matches(script) }) else {
                return false
            }
        }
        return true
    }

    /// Interpreter (python, node) options before the script. Short options can be clustered (`-Im`).
    /// An option that takes a value must not let that value pose as the script
    /// (`python3 -X /opt/homebrew/bin/aws -c '…'` runs the `-c` code, not aws).
    static let shortFlags = Set("bBdEhiIOPqRsSuvVx")
    /// Code given on the command line: there is no script.
    static let shortCode = Set("cep")
    /// Options whose value is the next element (or the rest of the cluster).
    static let shortValued = Set("WXrC")
    static let longFlags: Set<String> = [
        "--no-warnings", "--no-deprecation", "--enable-source-maps", "--trace-warnings", "--trace-deprecation",
        "--throw-deprecation", "--pending-deprecation", "--expose-gc", "--inspect", "--inspect-brk", "--preserve-symlinks",
        "--preserve-symlinks-main", "--experimental-vm-modules", "--use-openssl-ca", "--use-system-ca", "--jitless",
        "--no-experimental-fetch", "--experimental-require-module", "--no-experimental-require-module",
        "--experimental-strip-types", "--experimental-detect-module", "--frozen-intrinsics", "--abort-on-uncaught-exception",
        "--harmony", "--no-addons", "--bun", "--smol", "--hot", "--watch",
    ]
    static let longValued: Set<String> = [
        "--require", "--import", "--loader", "--experimental-loader", "--conditions", "--title", "--input-type",
        "--env-file", "--disable-warning", "--check-hash-based-pycs", "--preload",
    ]

    /// The script (or `-m` module) an interpreter runs: the first argv[1...] element that is not an
    /// option. Matching anywhere in argv would let `cat ~/.aws/credentials /x/bin/aws` pose as aws.
    /// An option this parser does not know (it might take a value) means "no script": such a process
    /// is not an owner (fail closed: its access is alerted on like anyone else's).
    static func scriptArgument(_ argv: [String]?) -> String? {
        guard let argv, argv.count > 1 else { return nil }
        var i = 1
        while i < argv.count {
            let a = argv[i]
            if a == "--" { return i + 1 < argv.count ? argv[i + 1] : nil }
            if !a.hasPrefix("-") || a == "-" { return a == "-" ? nil : a }
            if a.hasPrefix("--") {
                if a.contains("=") {
                    let name = String(a[..<a.firstIndex(of: "=")!])
                    guard longFlags.contains(name) || longValued.contains(name) || name.hasPrefix("--max-old-space-size")
                            || name.hasPrefix("--stack-size") else { return nil }
                    i += 1
                } else if longFlags.contains(a) {
                    i += 1
                } else if longValued.contains(a) {
                    i += 2
                } else {
                    return nil  // --eval / --print / --check (code, no script), or unknown
                }
                continue
            }
            // A cluster of short options: `-I`, `-Im`, `-Wignore`, `-SE`.
            let letters = Array(a.dropFirst())
            var consumedNext = false
            for (k, ch) in letters.enumerated() {
                if shortFlags.contains(ch) { continue }
                let rest = String(letters[(k + 1)...])
                if ch == "m" {
                    // Module: the rest of the cluster, or the next element.
                    if !rest.isEmpty { return rest }
                    return i + 1 < argv.count ? argv[i + 1] : nil
                }
                if shortCode.contains(ch) { return nil }
                if shortValued.contains(ch) {
                    if rest.isEmpty { consumedNext = true }
                    break
                }
                return nil  // unknown option letter
            }
            i += consumedNext ? 2 : 1
        }
        return nil
    }
}
