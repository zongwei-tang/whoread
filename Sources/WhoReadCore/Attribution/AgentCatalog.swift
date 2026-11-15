import Foundation

/// AI agent recognition rules (`Data/agents.json`).
public struct AgentCatalog: Codable, Hashable, Sendable {
    public var version: Int
    public var agents: [AgentSpec]

    public init(version: Int = 1, agents: [AgentSpec]) {
        self.version = version
        self.agents = agents
    }

    public static func load(from data: Data) throws -> AgentCatalog {
        try JSONDecoder().decode(AgentCatalog.self, from: data)
    }

    public func agent(_ id: String) -> AgentSpec? { agents.first { $0.id == id } }
}

public struct AgentSpec: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable { case cli, app }
    public var id: String
    public var name: LocalizedText
    public var kind: Kind
    /// Any clause matching makes a process image this agent.
    public var match: [AgentMatchClause]

    public init(id: String, name: LocalizedText, kind: Kind, match: [AgentMatchClause]) {
        self.id = id
        self.name = name
        self.kind = kind
        self.match = match
    }
}

/// All provided fields must match.
public struct AgentMatchClause: Codable, Hashable, Sendable {
    /// Executable basename, case-insensitive (e.g. "codex").
    public var executableNames: [String]?
    /// Full executable path globs (e.g. "**/.local/share/claude/versions/*").
    public var executableGlobs: [Glob]?
    /// Name of any `.app` bundle on the executable path (e.g. "Cursor.app").
    public var bundleNames: [String]?
    /// basename(argv[0]).
    public var argv0Names: [String]?
    /// basename of the script or module an interpreter runs (`node /opt/homebrew/bin/claude`,
    /// `python -m aider`; see `operands`).
    public var argvBasenames: [String]?
    /// Substring of the script or module an interpreter runs (e.g. "@anthropic-ai/claude-code"; see
    /// `operands`).
    public var argvContains: [String]?
    /// Optional code identity pin, filled from `codesign -dv` on the user's machine.
    public var teamIDs: [String]?

    public init(
        executableNames: [String]? = nil,
        executableGlobs: [String]? = nil,
        bundleNames: [String]? = nil,
        argv0Names: [String]? = nil,
        argvBasenames: [String]? = nil,
        argvContains: [String]? = nil,
        teamIDs: [String]? = nil
    ) {
        self.executableNames = executableNames
        self.executableGlobs = executableGlobs?.map(Glob.init)
        self.bundleNames = bundleNames
        self.argv0Names = argv0Names
        self.argvBasenames = argvBasenames
        self.argvContains = argvContains
        self.teamIDs = teamIDs
    }

    var isEmpty: Bool {
        (executableNames ?? []).isEmpty && (executableGlobs ?? []).isEmpty && (bundleNames ?? []).isEmpty
            && (argv0Names ?? []).isEmpty && (argvBasenames ?? []).isEmpty && (argvContains ?? []).isEmpty
    }

    func matches(_ p: ProcessRecord) -> Bool {
        if isEmpty { return false }
        if let names = executableNames, !names.isEmpty {
            let n = PathNormalizer.fold(p.name)
            guard names.contains(where: { PathNormalizer.fold($0) == n }) else { return false }
        }
        if let globs = executableGlobs, !globs.isEmpty {
            guard globs.contains(where: { $0.matches(p.executablePath) }) else { return false }
        }
        if let bundles = bundleNames, !bundles.isEmpty {
            let wanted = Set(bundles.map(PathNormalizer.fold))
            let present = BundlePath.appBundles(in: p.executablePath).map {
                PathNormalizer.fold(String($0.split(separator: "/").last ?? ""))
            }
            guard present.contains(where: wanted.contains) else { return false }
        }
        let argv = p.argv ?? []
        if let names = argv0Names, !names.isEmpty {
            guard let first = argv.first else { return false }
            let n = PathNormalizer.fold(AgentMatchClause.basename(first))
            guard names.contains(where: { PathNormalizer.fold($0) == n }) else { return false }
        }
        if let names = argvBasenames, !names.isEmpty {
            let wanted = Set(names.map(PathNormalizer.fold))
            guard AgentMatchClause.operands(p).contains(where: { wanted.contains(PathNormalizer.fold(AgentMatchClause.basename($0))) })
            else { return false }
        }
        if let needles = argvContains, !needles.isEmpty {
            guard AgentMatchClause.operands(p).contains(where: { arg in needles.contains { arg.contains($0) } }) else { return false }
        }
        if let teams = teamIDs, !teams.isEmpty {
            guard let t = p.teamID, teams.contains(t) else { return false }
        }
        return true
    }

    /// What `argvBasenames` and `argvContains` are matched against: the script or module the interpreter
    /// runs (`scriptPosition`), not any argument. `npm install -g @anthropic-ai/claude-code` runs npm,
    /// `npx tsc -p ~/code/codex` npx, `node build.js --out dist/claude` build.js and
    /// `deno run -A scripts/build.ts --out dist/claude` build.ts: none of them is the agent they name.
    /// Code given on the command line (`python3 -c`, `node -e`, `bun -e`) and a runtime's other
    /// subcommands (a test runner, a package manager) run no script. Only where the position cannot be
    /// told (an option the parser cannot place) every argument after argv[0] counts, as before: missing an
    /// agent is the fail-open direction.
    static func operands(_ p: ProcessRecord) -> ArraySlice<String> {
        guard let argv = p.argv, argv.count > 1 else { return [] }
        switch scriptPosition(p) {
        case .script(let s, _): return [s]
        case .none: return []
        case .unknown: return argv.dropFirst()
        }
    }

    /// Where the script or module an interpreter runs is in its argv.
    enum ScriptPosition: Equatable {
        /// The script (or `-m` module): its element's index, and the script itself (a module may be the rest
        /// of a cluster, `-maider`).
        case script(String, at: Int)
        /// None by construction: code on the command line, a REPL, a runtime's subcommand that runs no script.
        case none
        /// An option the parser cannot place (it might take a value).
        case unknown
    }

    static func scriptPosition(_ p: ProcessRecord) -> ScriptPosition {
        guard let argv = p.argv else { return .none }
        return scriptPosition(executableName: p.name, argv: argv)
    }

    static func scriptPosition(executableName: String, argv: [String]) -> ScriptPosition {
        guard argv.count > 1 else { return .none }
        switch PathNormalizer.fold(executableName) {
        case "deno": return denoScript(argv)
        case "bun": return bunScript(argv, bunx: PathNormalizer.fold(basename(argv[0])) == "bunx")
        case "node", "nodejs": return interpreterScript(argv, node: true)
        default: return interpreterScript(argv, node: false)
        }
    }

    /// Long options of node and python whose code is on the command line, or that run no script.
    static let noScriptLong: Set<String> = ["--eval", "--print", "--check", "--test", "--run", "--interactive", "--help", "--version",
                                            "--v8-options"]
    /// node options whose value may be the next element (`--inspect-port 9229`). Any other node option
    /// without "=" is a switch: node's switches are many and change with each release.
    static let nodeLongValued: Set<String> = [
        "--require", "--import", "--loader", "--experimental-loader", "--conditions", "--title", "--input-type", "--env-file",
        "--env-file-if-exists", "--disable-warning", "--inspect-port", "--debug-port", "--max-http-header-size",
        "--redirect-warnings", "--report-dir", "--report-directory", "--report-filename", "--report-signal",
        "--heapsnapshot-signal", "--heapsnapshot-near-heap-limit", "--diagnostic-dir", "--cpu-prof-dir", "--cpu-prof-name",
        "--cpu-prof-interval", "--heap-prof-dir", "--heap-prof-name", "--heap-prof-interval", "--secure-heap",
        "--secure-heap-min", "--tls-keylog", "--tls-cipher-list", "--use-largepages", "--icu-data-dir", "--openssl-config",
        "--policy-integrity", "--experimental-policy", "--experimental-config-file", "--es-module-specifier-resolution",
        "--unhandled-rejections", "--watch-path", "--test-reporter", "--test-reporter-destination", "--test-name-pattern",
        "--test-skip-pattern", "--test-concurrency", "--test-timeout", "--test-shard", "--localstorage-file",
        "--experimental-sea-config", "--dns-result-order", "--trace-event-categories", "--trace-event-file-pattern",
        "--stack-trace-limit", "--max-old-space-size", "--max-semi-space-size", "--snapshot-blob", "--allow-fs-read",
        "--allow-fs-write", "--experimental-default-type", "--watch-kill-signal", "--disable-proto",
    ]

    /// node and python (and other interpreters the agent catalog names), with the options of the shared
    /// parser (`IdentitySpec`).
    static func interpreterScript(_ argv: [String], node: Bool) -> ScriptPosition {
        var i = 1
        while i < argv.count {
            let a = argv[i]
            if a == "--" { return i + 1 < argv.count ? .script(argv[i + 1], at: i + 1) : .none }
            if a == "-" { return .none }  // the script on standard input
            if !a.hasPrefix("-") { return .script(a, at: i) }
            if a.hasPrefix("--") {
                let name = a.firstIndex(of: "=").map { String(a[..<$0]) } ?? a
                if noScriptLong.contains(name) { return .none }
                if a.contains("=") {
                    i += 1
                } else if IdentitySpec.longValued.contains(a) || (node && nodeLongValued.contains(a)) {
                    i += 2
                } else if IdentitySpec.longFlags.contains(a) || node {
                    i += 1
                } else {
                    return .unknown
                }
                continue
            }
            // A cluster of short options: `-I`, `-Im`, `-Wignore`, `-SE`.
            let letters = Array(a.dropFirst())
            var consumedNext = false
            for (k, ch) in letters.enumerated() {
                if IdentitySpec.shortFlags.contains(ch) { continue }
                let rest = String(letters[(k + 1)...])
                if ch == "m" && !node {
                    if !rest.isEmpty { return .script(rest, at: i) }
                    return i + 1 < argv.count ? .script(argv[i + 1], at: i + 1) : .none
                }
                if IdentitySpec.shortCode.contains(ch) { return .none }
                if IdentitySpec.shortValued.contains(ch) {
                    if rest.isEmpty { consumedNext = true }
                    break
                }
                return .unknown
            }
            i += consumedNext ? 2 : 1
        }
        return .none
    }

    /// deno subcommands that run a script (the next operand), and those that run none. `deno <file>` runs it.
    static let denoScriptCommands: Set<String> = ["run", "serve", "x"]
    static let denoOtherCommands: Set<String> = [
        "add", "approve-scripts", "audit", "bench", "cache", "check", "clean", "compile", "completions", "coverage", "deploy",
        "doc", "eval", "fmt", "help", "info", "init", "install", "jupyter", "lint", "lsp", "outdated", "publish", "remove",
        "repl", "task", "test", "types", "uninstall", "update", "upgrade", "vendor",
    ]
    /// deno options whose value is the next element; every other option is a switch, or carries its
    /// value after "=" (`--allow-read=/tmp`, `--inspect=…`).
    static let denoValued: Set<String> = ["-c", "--config", "--import-map", "-L", "--log-level", "--cert", "--location", "--seed",
                                          "--ext", "--preload", "--port", "--host", "--env"]

    static func denoScript(_ argv: [String]) -> ScriptPosition {
        var i = 1
        var command = false
        while i < argv.count {
            let a = argv[i]
            if a == "--" { return i + 1 < argv.count ? .script(argv[i + 1], at: i + 1) : .none }
            if a.hasPrefix("-") && a != "-" {
                let name = a.firstIndex(of: "=").map { String(a[..<$0]) } ?? a
                // A short cluster ending in a valued letter (`-Ac deno.json`) takes the next element too.
                let valued = !a.contains("=") && (denoValued.contains(name)
                    || (!a.hasPrefix("--") && a.count > 2 && "cL".contains(a.last!)))
                i += valued ? 2 : 1
                continue
            }
            if !command {
                if denoScriptCommands.contains(a) {
                    command = true
                    i += 1
                    continue
                }
                if denoOtherCommands.contains(a) { return .none }
            }
            return a == "-" ? .none : .script(a, at: i)
        }
        return .none
    }

    /// bun subcommands that run a script or package (the next operand), and those that run none.
    /// `bun <file>` runs it; `bunx <package>` is `bun x`.
    static let bunScriptCommands: Set<String> = ["run", "x"]
    static let bunOtherCommands: Set<String> = [
        "a", "add", "audit", "build", "c", "completions", "create", "discord", "exec", "feedback", "help", "i", "info", "init",
        "install", "link", "outdated", "patch", "patch-commit", "pm", "publish", "remove", "repl", "rm", "test", "uninstall",
        "unlink", "update", "upgrade", "why",
    ]
    static let bunValued: Set<String> = [
        "-r", "--preload", "-d", "--define", "-l", "--loader", "--main-fields", "--tsconfig-override", "--env-file", "--cwd", "-c",
        "--config", "--port", "--conditions", "--elide-lines", "-F", "--filter", "--shell", "--jsx-factory", "--jsx-fragment",
        "--jsx-import-source", "--jsx-runtime", "--extension-order", "--origin", "--target", "--external", "--console-depth",
        "--fetch-preconnect", "--max-http-header-size", "--dns-result-order", "--title", "--unhandled-rejections",
        "--user-agent", "--registry", "--backend", "--cache-dir",
    ]
    /// Code on the command line.
    static let bunCode: Set<String> = ["-e", "--eval", "-p", "--print", "-h", "--help", "-v", "--version", "--revision"]

    static func bunScript(_ argv: [String], bunx: Bool) -> ScriptPosition {
        var i = 1
        var command = bunx
        while i < argv.count {
            let a = argv[i]
            if a == "--" { return i + 1 < argv.count ? .script(argv[i + 1], at: i + 1) : .none }
            if a.hasPrefix("-") && a != "-" {
                let name = a.firstIndex(of: "=").map { String(a[..<$0]) } ?? a
                if bunCode.contains(name) { return .none }
                i += !a.contains("=") && bunValued.contains(name) ? 2 : 1
                continue
            }
            if !command {
                if bunScriptCommands.contains(a) {
                    command = true
                    i += 1
                    continue
                }
                if bunOtherCommands.contains(a) { return .none }
            }
            return a == "-" ? .none : .script(a, at: i)
        }
        return .none
    }

    static func basename(_ s: String) -> String {
        var t = Substring(s)
        while t.count > 1 && t.hasSuffix("/") { t = t.dropLast() }
        if let slash = t.lastIndex(of: "/") { return String(t[t.index(after: slash)...]) }
        return String(t)
    }
}

/// Decides whether a process image is a known AI agent.
public struct AgentDetector: Sendable {
    public let catalog: AgentCatalog

    public init(catalog: AgentCatalog) {
        self.catalog = catalog
    }

    /// Agent ID for this image, if any. First agent in catalog order wins.
    public func detect(_ p: ProcessRecord) -> String? {
        for agent in catalog.agents where agent.match.contains(where: { $0.matches(p) }) {
            return agent.id
        }
        return nil
    }

    public func displayName(_ agentID: String, language: Language = .en) -> String {
        catalog.agent(agentID)?.name.resolve(language) ?? agentID
    }
}
