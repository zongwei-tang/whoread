import XCTest
@testable import WhoReadCore

// Regression tests for review round 2. Each test names the finding it covers and
// replays the finding's scenario against the current code.

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let awsCreds = "/Users/alice/.aws/credentials"

/// What the AUTH path decides (Enforcer.decide without the enforcement switch).
private func authDecision(_ h: Harness, _ p: ProcessRecord, _ path: String, t: TimeInterval = 10) -> RuleDecision {
    let activity = FileActivity(time: at(t), operation: .open, process: p, targets: OperationSemantics.open(path: path, fflag: 1))
    let targets = h.analyzer.classify(activity).filter(\.isSensitive).map(\.evaluationTarget)
    let chain = h.tree.chain(for: activity.process, at: activity.time)
    return h.rules.evaluate(process: chain.first?.image ?? p, chain: chain, targets: targets, enforcementActive: true,
                            now: activity.time)
}

/// zsh → node running Claude Code (an agent) → leaf. Returns the leaf.
private func claudeShell(_ h: Harness, _ leaf: ProcessRecord) -> ProcessRecord {
    let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
    let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]))
    return h.spawn(claude, leaf)
}

private func terminalShell(_ h: Harness, _ leaf: ProcessRecord) -> ProcessRecord {
    h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), leaf)
}

private func enforced(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

private func unsignedTool(_ pid: Int32, _ path: String, cdhash: String?, ppid: Int32 = 1) -> ProcessRecord {
    var p = proc(pid, path, ppid: ppid)
    p.cdhash = cdhash
    return p
}

// MARK: - Rules (core-semantics-*, docs-consistency-*)

final class RulesRound2Tests: XCTestCase {
    // core-semantics-2 / docs-consistency-1: a copied Apple binary keeps its platform flag, so the
    // never-block list also needs a root-owned location.
    func testNeverBlockNeedsARootOwnedLocation() throws {
        let h = try Harness(rules: [enforced(RuleTemplates.blockAgentsFromCritical())])
        let cat = claudeShell(h, P.cat(700, parent: 600))
        XCTAssertEqual(authDecision(h, cat, sshKey).reason, .explicitDeny)
        for (pid, path) in [(701, "/private/tmp/mds_x"), (702, "/private/tmp/launchd"), (703, "/Users/alice/tccd"),
                            (704, "/Users/alice/tmp/mdscat")] {
            let copy = claudeShell(h, proc(Int32(pid), path, ppid: 600, platform: true, signingID: "com.apple.cat"))
            let d = authDecision(h, copy, sshKey)
            XCTAssertEqual(d.verdict, .deny, path)
            XCTAssertEqual(d.reason, .explicitDeny, path)
        }
        let list = NeverBlockList()
        XCTAssertTrue(list.contains(proc(90, "/usr/sbin/securityd", platform: true)))
        XCTAssertTrue(list.contains(proc(91, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds",
                                         platform: true)))
        XCTAssertTrue(list.contains(proc(92, "/usr/libexec/trustd", platform: true)))
        XCTAssertFalse(list.contains(proc(93, "/private/tmp/mds_x", platform: true)))
        // The data volume under its firmlink spelling is not a system location.
        XCTAssertFalse(list.contains(proc(94, "/System/Volumes/Data/Users/alice/tmp/launchd", platform: true)))
        XCTAssertFalse(list.contains(proc(95, "/System/Volumes/data/private/tmp/mds", platform: true)))
        XCTAssertTrue(list.contains(proc(1, "/Users/alice/whatever", platform: false)), "launchd's pid is always exempt")
        // Owner specs use the same location test.
        let spec = IdentitySpec(executables: ["/System/**/mds"], platformBinary: true)
        XCTAssertTrue(spec.matches(proc(96, "/System/Library/Support/mds", platform: true)))
        XCTAssertFalse(spec.matches(proc(97, "/System/Volumes/Data/Users/alice/mds", platform: true)))
    }

    // core-semantics-1 / docs-consistency-3: "block from now on" for an unsigned binary follows its
    // cdhash, not only its path.
    func testBlockFromNowOnFollowsTheUnsignedBinarysCode() throws {
        let block = enforced(Rule(id: "block", target: .category("ssh"),
                                  subject: .responsible(key: "bin:/users/alice/bin/tool", teamID: nil, cdhash: "ABCD", exceptOwners: true),
                                  action: .deny, includePlatformBinaries: true))
        let h = try Harness(rules: [block])
        XCTAssertEqual(authDecision(h, unsignedTool(800, "/Users/alice/bin/tool", cdhash: "abcd"), sshKey).verdict, .deny)
        let copy = authDecision(h, unsignedTool(801, "/Users/alice/bin/tool2", cdhash: "abcd"), sshKey)
        XCTAssertEqual(copy.verdict, .deny, "same code at another path")
        XCTAssertFalse(copy.cacheable)
        XCTAssertEqual(authDecision(h, unsignedTool(802, "/Users/alice/bin/tool", cdhash: "ffff"), sshKey).verdict, .allow,
                       "different code at the pinned path")
        XCTAssertEqual(authDecision(h, unsignedTool(803, "/Users/alice/bin/tool2", cdhash: "ffff"), sshKey).verdict, .allow)
        // Run from a terminal, the copy is the leaf of a chain charged to Terminal: still the same code.
        let leaf = terminalShell(h, unsignedTool(804, "/Users/alice/tmp/x", cdhash: "abcd", ppid: 500))
        XCTAssertEqual(h.attributor.attribute(chain: h.tree.chain(for: leaf, at: at(10))).kind, .app)
        XCTAssertEqual(authDecision(h, leaf, sshKey).verdict, .deny)

        // Exceptions are not widened: an "always allow" for the tool does not cover a copy.
        var broad = enforced(Rule(id: "broad", target: .category("ssh"), subject: .anyNonOwner, action: .deny,
                                  includePlatformBinaries: true))
        broad.exceptions = [RuleException(subject: .responsible(key: "bin:/users/alice/bin/tool", teamID: nil, cdhash: "abcd"))]
        let ex = try Harness(rules: [broad])
        XCTAssertEqual(authDecision(ex, unsignedTool(810, "/Users/alice/bin/tool", cdhash: "abcd"), sshKey).verdict, .allow)
        XCTAssertEqual(authDecision(ex, unsignedTool(811, "/Users/alice/bin/tool2", cdhash: "abcd"), sshKey).verdict, .deny)
    }

    // core-semantics-4: a "block from now on" rule for an agent applies wherever the agent is in the
    // chain, not only when attribution picks it (the nearest .app wins attribution).
    func testBlockFromNowOnForAnAgentSurvivesAnAppBundleLeaf() throws {
        let block = enforced(Rule(id: "block-agent", target: .category("aws"),
                                  subject: .responsible(key: "agent:claude-code", teamID: nil, cdhash: nil, exceptOwners: true),
                                  action: .deny, includePlatformBinaries: true))
        let h = try Harness(rules: [block])
        XCTAssertEqual(authDecision(h, claudeShell(h, P.cat(700, parent: 600)), awsCreds).verdict, .deny)
        let bundled = claudeShell(h, proc(701, "/Users/alice/tmp/X.app/cat", ppid: 600, platform: true, signingID: "com.apple.cat"))
        XCTAssertEqual(h.attributor.attribute(chain: h.tree.chain(for: bundled, at: at(10))).key, "app:/users/alice/tmp/x.app",
                       "attribution alone charges the bundle")
        let d = authDecision(h, bundled, awsCreds)
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "block-agent")
        // No agent in the chain: not covered.
        let plain = try Harness(rules: [block])
        let noAgent = terminalShell(plain, proc(702, "/Users/alice/tmp/X.app/cat", ppid: 500, platform: true))
        XCTAssertEqual(authDecision(plain, noAgent, awsCreds).verdict, .allow)

        // A team pin still has to hold for the agent's chain node.
        let pinned = enforced(Rule(id: "block-pinned", target: .category("aws"),
                                   subject: .responsible(key: "agent:claude-code", teamID: "OTHERTEAM", cdhash: nil, exceptOwners: true),
                                   action: .deny, includePlatformBinaries: true))
        let p = try Harness(rules: [pinned])
        XCTAssertEqual(authDecision(p, claudeShell(p, proc(703, "/Users/alice/tmp/X.app/cat", ppid: 600, platform: true)), awsCreds).verdict,
                       .allow)

        // Exceptions keep exact attribution: an approval for Claude Code is no tunnel through a bundle.
        var broad = enforced(Rule(id: "broad", target: .category("aws"), subject: .anyNonOwner, action: .deny,
                                  includePlatformBinaries: true))
        broad.exceptions = [RuleException(subject: .responsible(key: "agent:claude-code", teamID: nil))]
        let ex = try Harness(rules: [broad])
        XCTAssertEqual(authDecision(ex, claudeShell(ex, P.cat(700, parent: 600)), awsCreds).verdict, .allow)
        let tunnel = claudeShell(ex, proc(704, "/Users/alice/tmp/X.app/cat", ppid: 600, platform: true))
        XCTAssertEqual(authDecision(ex, tunnel, awsCreds).verdict, .deny)
    }
}

// MARK: - Links (engine-runtime-1, engine-runtime-5)

final class LinksRound2Tests: XCTestCase {
    private func classifier(custom: [String] = [], _ resolver: SymlinkResolver) throws -> PathClassifier {
        var catalog = try defaultData().catalog
        if let i = catalog.categories.firstIndex(where: { $0.kind == .custom }) {
            catalog.categories[i].paths = custom
            catalog.categories[i].enabled = true
        }
        return PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: [home]), symlinks: resolver)
    }

    // engine-runtime-1 (classifier half): a prefix in a user's own files never leads outside them.
    func testLinksFromUserFilesNeverReachSystemPaths() throws {
        let resolver = MapSymlinkResolver([
            "/Users/alice/link": "/usr/lib",
            "/Volumes/Macintosh HD/usr/lib": "/usr/lib",
            "/Users/alice/secret": "/Users/alice/Dropbox/secret",
            "/Volumes/NAS/keys": "/Users/alice/keys",
            "/Users/alice/tmpkeys": "/private/tmp/keys",
        ], links: [
            "/Users/alice/.ssh": [(link: "/Users/alice/.ssh/x", target: "/usr/lib"),
                                  (link: "/Users/alice/.ssh/config", target: "/Users/alice/dotfiles/ssh/config"),
                                  (link: "/Users/alice/.ssh/ext", target: "/Volumes/USB/ssh/id_rsa")],
        ])
        let c = try classifier(custom: ["~/link", "/Volumes/Macintosh HD/usr/lib", "~/secret", "/Volumes/NAS/keys", "~/tmpkeys"], resolver)
        XCTAssertFalse(c.prefixes.contains { $0.path.hasPrefix("/usr/lib") || $0.path.hasPrefix("/private/tmp") }, "\(c.prefixes)")
        XCTAssertNil(c.classify("/usr/lib/libc.dylib"))
        XCTAssertNil(c.classify("/usr/lib/os-release"), "the dotfile walk is held to the same limit")
        XCTAssertFalse(c.mutePaths.contains("/usr/lib"))
        // Links that stay in a home or on an external volume still count.
        XCTAssertEqual(c.classify("/Users/alice/Dropbox/secret/a.txt")?.categoryID, "custom")
        XCTAssertEqual(c.classify("/Users/alice/keys/id")?.categoryID, "custom")
        XCTAssertEqual(c.classify("/Users/alice/dotfiles/ssh/config")?.categoryID, "ssh")
        XCTAssertEqual(c.classify("/Volumes/USB/ssh/id_rsa")?.categoryID, "ssh")
        // The literal spellings stay monitored (nothing above changes what an unresolved path means).
        XCTAssertEqual(c.classify("/Users/alice/link/x")?.categoryID, "custom")

        // A prefix outside users' files (only a privileged catalog edit can add one) may still follow links.
        let system = try classifier(custom: ["/opt/secrets"], MapSymlinkResolver(["/opt/secrets": "/srv/secrets"]))
        XCTAssertEqual(system.classify("/srv/secrets/token")?.categoryID, "custom")

        let homes = [home]
        XCTAssertTrue(PathClassifier.isUserLocation("/Users/alice/x", homes: homes))
        XCTAssertTrue(PathClassifier.isUserLocation("/Volumes/USB", homes: homes))
        XCTAssertTrue(PathClassifier.isUserLocation("/volumes/usb/x", homes: homes))
        XCTAssertFalse(PathClassifier.isUserLocation("/Users/alice", homes: homes), "the home itself is not inside it")
        XCTAssertFalse(PathClassifier.isUserLocation("/Users/alicex/y", homes: homes))
        XCTAssertFalse(PathClassifier.isUserLocation("/Volumes", homes: homes))
        XCTAssertFalse(PathClassifier.isUserLocation("/usr/lib", homes: homes))
        XCTAssertFalse(PathClassifier.isUsableLinkTarget("/usr/lib", inside: "/Users/alice/.ssh", homes: homes))
        XCTAssertTrue(PathClassifier.isUsableLinkTarget("/srv/x", inside: "/opt/secrets", homes: homes))
    }

    // engine-runtime-5: a path rule on a spelling reached through a link matches the path ES reports.
    func testPathRulesMatchTheResolvedPath() throws {
        let resolver = MapSymlinkResolver(["/Users/alice/secret": "/Users/alice/Dropbox/secret"], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/credentials", target: "/Users/alice/dotfiles/aws/credentials")],
        ])
        let c = try classifier(custom: ["~/secret"], resolver)
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/secret"), ["/Users/alice/Dropbox/secret"])
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/Secret/Sub/F.txt"), ["/Users/alice/Dropbox/secret/Sub/F.txt"],
                       "below a link: same tail, case kept")
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.aws"), ["/Users/alice/dotfiles/aws/credentials"])
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.aws", includingLinksBelow: false), [])
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.aws/credentials"), ["/Users/alice/dotfiles/aws/credentials"])
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/secretive"), [], "component boundaries")
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.ssh"), [])

        func decide(_ rules: [Rule], _ path: String, _ p: ProcessRecord = proc(900, "/Users/alice/bin/zoomish")) -> RuleDecision {
            let engine = RuleEngine(rules: rules, classifier: c)
            guard let hit = c.classify(path) else { return RuleDecision(verdict: .allow, reason: .notSensitive) }
            let target = EvaluationTarget(path: c.normalizer.normalize(path), access: .read,
                                          categories: [TargetCategory(id: hit.categoryID, severity: hit.severity)])
            return engine.evaluate(process: p, chain: [], targets: [target], enforcementActive: true, now: at(1))
        }
        let rule = enforced(Rule(id: "secret", target: .pathPrefix("~/secret"), subject: .anyNonOwner, action: .deny))
        XCTAssertEqual(decide([rule], "/Users/alice/Dropbox/secret/a.txt").verdict, .deny, "the path ES reports")
        XCTAssertEqual(decide([rule], "/Users/alice/secret/a.txt").verdict, .deny)
        XCTAssertEqual(decide([rule], "/Users/alice/Dropbox/secret2/a.txt").reason, .notSensitive)
        let dotfile = enforced(Rule(id: "aws-dir", target: .pathPrefix("~/.aws"), subject: .anyNonOwner, action: .deny,
                                    includePlatformBinaries: true))
        XCTAssertEqual(decide([dotfile], "/Users/alice/dotfiles/aws/credentials").verdict, .deny, "a link found inside the folder")

        // An exception's path is not widened to links found below it.
        var withException = enforced(Rule(id: "broad", target: .category("aws"), subject: .anyNonOwner, action: .deny,
                                          includePlatformBinaries: true))
        withException.exceptions = [RuleException(subject: .anyNonOwner, pathPrefix: "~/.aws")]
        XCTAssertEqual(decide([withException], "/Users/alice/dotfiles/aws/credentials").verdict, .deny)
        XCTAssertEqual(decide([withException], "/Users/alice/.aws/config").verdict, .allow)

        // Rediscovery: replacing the classifier recompiles the keys against the new links.
        let engine = RuleEngine(rules: [rule], classifier: try classifier(custom: ["~/secret"], NoSymlinkResolver()))
        let target = EvaluationTarget(path: "/Users/alice/Dropbox/secret/a.txt", access: .read,
                                      categories: [TargetCategory(id: "custom", severity: .high)])
        let zoomish = proc(900, "/Users/alice/bin/zoomish")
        XCTAssertEqual(engine.evaluate(process: zoomish, chain: [], targets: [target], enforcementActive: true, now: at(1)).verdict, .allow)
        engine.replace(classifier: c)
        XCTAssertEqual(engine.evaluate(process: zoomish, chain: [], targets: [target], enforcementActive: true, now: at(1)).verdict, .deny)
    }

    // Rule evaluation is linear in the keys: a folder full of links cannot blow up one rule.
    func testLinkAliasesAreBounded() throws {
        let many = (0..<500).map { (link: "/Users/alice/.ssh/l\($0)", target: "/Users/alice/stash/k\($0)") }
        let c = try classifier(MapSymlinkResolver([:], links: ["/Users/alice/.ssh": many]))
        XCTAssertEqual(c.classify("/Users/alice/stash/k499")?.categoryID, "ssh", "the classifier still monitors every target")
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.ssh").count, 8)
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.ssh", limit: 3).count, 3)
        XCTAssertEqual(c.linkAliases(of: "/Users/alice/.ssh/l42"), ["/Users/alice/stash/k42"])
        let rule = Rule(target: .pathPrefix("~/.ssh"), subject: .anyNonOwner, action: .deny)
        XCTAssertEqual(RuleEngine.compile(rule, c).prefixKeys.count, 9, "the folder and at most 8 link targets")
    }
}

// MARK: - Catalog data (core-semantics-3)

final class CatalogDataRound2Tests: XCTestCase {
    // A platform spec outside the system locations only matches with pinned signing IDs, and only a
    // spec of literal paths can be pinned. Anything else is dead data.
    func testEveryPlatformSpecCanMatch() throws {
        let data = try defaultData()
        func inSystem(_ g: Glob) -> Bool { IdentitySpec.systemLocations.contains { g.pattern.hasPrefix($0) } }
        var specs: [(String, IdentitySpec)] = data.catalog.categories.flatMap { c in c.owners.map { (c.id, $0) } }
        specs += data.benign.services.map { ($0.id, $0.identity) }
        for (owner, spec) in specs where spec.platformBinary == true && (spec.signingIDs ?? []).isEmpty {
            let paths = (spec.executables ?? []) + (spec.bundles ?? [])
            XCTAssertTrue(paths.allSatisfy(inSystem) || paths.allSatisfy { !$0.hasWildcards },
                          "\(owner): \(spec.label ?? "?") can never match")
        }
    }

    func testXcodeGitTransportIsANetrcOwnerOncePinned() throws {
        let data = try defaultData()
        let netrc = try XCTUnwrap(data.catalog.categories.first { $0.id == "netrc" })
        var xcode = try XCTUnwrap(netrc.owners.first { $0.label == "git HTTP transport (Xcode)" })
        XCTAssertFalse((xcode.executables ?? []).contains(where: \.hasWildcards), "literal paths: resolve-owners can pin them")
        let helper = "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-remote-https"
        let process = proc(700, helper, platform: true, signingID: "com.apple.git-remote-https")
        XCTAssertFalse(xcode.matches(process), "unpinned: Xcode is admin-writable")
        xcode.signingIDs = ["com.apple.git-remote-http", "com.apple.git-remote-https"]  // what resolve-owners fills in
        XCTAssertTrue(xcode.matches(process))
        XCTAssertFalse(xcode.matches(proc(701, helper, platform: true, signingID: "com.apple.cat")))
    }
}

// MARK: - Latency (docs-consistency-4)

final class LatencyRound2Tests: XCTestCase {
    private func slow(_ m: LatencyMonitor, _ n: Int = 60) { for _ in 0..<n { m.record(micros: 80_000, missedDeadline: false) } }
    private func fast(_ m: LatencyMonitor, _ n: Int = 60) { for _ in 0..<n { m.record(micros: 100, missedDeadline: false) } }

    func testP99TripNeedsABreachThatPersists() {
        let m = LatencyMonitor(p99ThresholdMicros: 50_000, minimumSamples: 50, breachesToTrip: 3)
        // One burst: it stays in the window, but nothing slow happens afterwards.
        slow(m)
        m.evaluate()
        for _ in 0..<5 {
            fast(m)
            m.evaluate()
        }
        m.evaluate()
        XCTAssertFalse(m.isTripped, "a burst that ended does not trip")
        XCTAssertGreaterThan(m.evaluateWithoutTripping().p99Micros, 50_000, "although the window's p99 is still over")
        // Slow in two evaluations, then a quiet one: the streak starts over.
        slow(m); m.evaluate()
        slow(m); m.evaluate()
        fast(m, 500); m.evaluate()
        slow(m); m.evaluate()
        XCTAssertFalse(m.isTripped)
        // Three in a row.
        slow(m); m.evaluate()
        XCTAssertFalse(m.isTripped)
        slow(m); m.evaluate()
        XCTAssertTrue(m.trippedReason?.contains("p99") == true)
        m.reset()
        XCTAssertFalse(m.isTripped)
        slow(m); m.evaluate()
        XCTAssertFalse(m.isTripped, "reset clears the streak")
    }

    func testStatusReadsDoNotCountAndDeadlineMissesStillTripAtOnce() {
        let m = LatencyMonitor(p99ThresholdMicros: 50_000, minimumSamples: 50, breachesToTrip: 2)
        slow(m)
        for _ in 0..<5 { _ = m.evaluateWithoutTripping() }
        XCTAssertFalse(m.isTripped)
        m.evaluate()
        XCTAssertFalse(m.isTripped)
        slow(m)
        m.evaluate()
        XCTAssertTrue(m.isTripped)

        let d = LatencyMonitor(breachesToTrip: 5)
        d.record(micros: 10, missedDeadline: true)
        XCTAssertEqual(d.trippedReason, "deadline missed")
        // After a burst, a handful of slow responses among many fast ones is under p99 for the interval
        // (the window, still holding the burst, is not).
        let tail = LatencyMonitor(p99ThresholdMicros: 50_000, minimumSamples: 50, breachesToTrip: 2)
        slow(tail)
        tail.evaluate()
        slow(tail, 5)
        fast(tail, 1000)
        XCTAssertGreaterThan(tail.evaluate().p99Micros, 50_000)
        XCTAssertFalse(tail.isTripped)
        slow(tail)
        tail.evaluate()
        XCTAssertFalse(tail.isTripped, "the streak started over")
        XCTAssertEqual(LatencyMonitor(breachesToTrip: 0).breachesToTrip, 1)
    }
}

// MARK: - Date coding (store-ipc-cli-2, Core half)

final class DateCodingRound2Tests: XCTestCase {
    private struct Box: Codable { var d: Date }

    func testDatesTheStoreCannotReadBackAreRefusedOnBothSides() throws {
        let dec = Exporter.decoder()
        for json in [#"{"d":1e12}"#, #"{"d":1e300}"#, #"{"d":-1e300}"#, #"{"d":-62167219201}"#, #"{"d":253402300800}"#,
                     #"{"d":"9999-12-31T23:30:00-01:00"}"#, #"{"d":"0000-01-01T00:30:00+01:00"}"#] {
            XCTAssertThrowsError(try dec.decode(Box.self, from: Data(json.utf8)), json)
        }
        let enc = Exporter.encoder(pretty: false)
        for t in [1e12, 1e300, -1e300, 253_402_300_800] {
            XCTAssertThrowsError(try enc.encode(Box(d: Date(timeIntervalSince1970: t))), "\(t)")
        }
        // The edges round-trip.
        for t in [-62_167_219_200, 0, 1_760_000_000.123456, 253_402_300_799.999_9] as [TimeInterval] {
            let data = try enc.encode(Box(d: Date(timeIntervalSince1970: t)))
            let back = try dec.decode(Box.self, from: data)
            XCTAssertEqual(back.d.timeIntervalSince1970, t, accuracy: 1e-3, String(decoding: data, as: UTF8.self))
            XCTAssertNoThrow(try enc.encode(back))
        }
        XCTAssertEqual(try dec.decode(Box.self, from: Data(#"{"d":1760000000}"#.utf8)).d, Date(timeIntervalSince1970: 1_760_000_000))
        // A rule with such a date is not decodable, so it can never be stored or replied with.
        let rule = #"{"id":"x1","target":{"category":"ssh"},"subject":{"type":"anyNonOwner"},"action":"alert","createdAt":CREATED}"#
        XCTAssertThrowsError(try dec.decode(Rule.self, from: Data(rule.replacingOccurrences(of: "CREATED", with: "1e12").utf8)))
        XCTAssertNoThrow(try dec.decode(Rule.self, from: Data(rule.replacingOccurrences(of: "CREATED", with: "1760000000").utf8)))
    }
}

// MARK: - Second review (links an agent can create in its own files)

final class Round2FollowUpTests: XCTestCase {
    private func classifier(custom: [String] = [], projectRoots: [String] = [], _ resolver: SymlinkResolver) throws -> PathClassifier {
        var catalog = try defaultData().catalog
        if let i = catalog.categories.firstIndex(where: { $0.kind == .custom }) {
            catalog.categories[i].paths = custom
            catalog.categories[i].enabled = true
        }
        return PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: [home]), projectRoots: projectRoots,
                              symlinks: resolver)
    }

    // A link into another category's files must not reclassify them: an unprivileged path rule on
    // `~/x -> ~/.ssh/id_ed25519` made the key Custom/high, out of reach of critical-file and ssh rules.
    func testALinkNeverDisplacesWhatAFileIsAtItsRealLocation() throws {
        let viaRule = try classifier(custom: ["~/x"], MapSymlinkResolver(["/Users/alice/x": "/Users/alice/.ssh/id_ed25519"]))
        XCTAssertEqual(viaRule.classify(sshKey)?.categoryID, "ssh")
        XCTAssertEqual(viaRule.classify(sshKey)?.severity, .critical)
        let viaWalk = try classifier(MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/x", target: "/Users/alice/.ssh/id_ed25519")],
        ]))
        XCTAssertEqual(viaWalk.classify(sshKey)?.categoryID, "ssh", "same severity: the real location wins")

        // A link still adds severity where the real location has less (or none).
        let up = try classifier(projectRoots: ["~/code"], MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/credentials", target: "/Users/alice/code/dotfiles/aws/credentials")],
            "/Users/alice/.ssh": [(link: "/Users/alice/.ssh/id_rsa", target: "/Volumes/USB/ssh/id_rsa")],
        ]))
        XCTAssertEqual(up.classify("/Users/alice/code/dotfiles/aws/credentials")?.categoryID, "aws", "inside a project root")
        XCTAssertEqual(up.classify("/Volumes/USB/ssh/id_rsa")?.categoryID, "ssh", "critical over the volume's high")
        XCTAssertEqual(up.classify("/Volumes/USB/other")?.categoryID, "volumes")

        // Dropbox on File Provider: the rule's folder is Cloud drives at its real location, and the path
        // rule still matches there (rule keys follow the link, whatever the category).
        let cloud = try classifier(custom: ["~/Dropbox/secret"],
                                   MapSymlinkResolver(["/Users/alice/Dropbox": "/Users/alice/Library/CloudStorage/Dropbox"]))
        let synced = "/Users/alice/Library/CloudStorage/Dropbox/secret/a.txt"
        let hit = try XCTUnwrap(cloud.classify(synced))
        XCTAssertEqual(hit.categoryID, "cloud-storage")
        let rule = enforced(Rule(id: "secret", target: .pathPrefix("~/Dropbox/secret"), subject: .anyNonOwner, action: .deny))
        func decide(_ path: String) -> Verdict {
            let c = cloud.classify(path)!
            let t = EvaluationTarget(path: path, access: .read, categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
            return RuleEngine(rules: [rule], classifier: cloud)
                .evaluate(process: proc(900, "/Users/alice/bin/zoomish"), chain: [], targets: [t], enforcementActive: true, now: at(1)).verdict
        }
        XCTAssertEqual(decide(synced), .deny)
        XCTAssertEqual(decide("/Users/alice/Library/CloudStorage/Dropbox/other.txt"), .allow)

        // A spelling that is both a catalog path and a link target is not "only via a link".
        let both = try classifier(custom: ["~/a", "~/b"], MapSymlinkResolver(["/Users/alice/a": "/Users/alice/b"]))
        XCTAssertEqual(both.prefixes.filter { $0.path == "/Users/alice/b" }.map(\.viaSymlink), [false])

        // End to end: a "block from now on" rule for the agent on ssh still applies after the agent
        // links the key from ~/.aws (the dotfile walk picks the link up on the next rediscovery).
        let block = enforced(Rule(id: "block-ssh", target: .category("ssh"),
                                  subject: .responsible(key: "agent:claude-code", teamID: nil, cdhash: nil, exceptOwners: true),
                                  action: .deny, includePlatformBinaries: true))
        let h = try Harness(rules: [block], symlinks: MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/x", target: "/Users/alice/.ssh/id_ed25519")],
        ]))
        let d = authDecision(h, claudeShell(h, P.cat(700, parent: 600)), sshKey)
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "block-ssh")
    }

    // Allow rules take no link targets: whoever owns the files can re-point a link, and an allow
    // rule on ~/.aws/credentials must not start silencing reads of the ssh key it now points to.
    func testAllowRulesDoNotFollowLinks() throws {
        let c = try classifier(MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/credentials", target: "/Users/alice/.ssh/id_ed25519")],
        ]))
        let zoomish = proc(900, "/Users/alice/bin/zoomish")
        let allow = Rule(id: "allow", enabled: true, target: .pathPrefix("~/.aws/credentials"),
                         subject: .unsigned(path: "/Users/alice/bin/zoomish", cdhash: nil), action: .allow)
        let deny = enforced(Rule(id: "deny", target: .pathPrefix("~/.aws/credentials"), subject: .anyNonOwner, action: .deny))
        XCTAssertEqual(RuleEngine.compile(allow, c).prefixKeys, ["/users/alice/.aws/credentials"])
        XCTAssertEqual(RuleEngine.compile(deny, c).prefixKeys, ["/users/alice/.aws/credentials", "/users/alice/.ssh/id_ed25519"])
        let key = EvaluationTarget(path: sshKey, access: .read, categories: [TargetCategory(id: "ssh", severity: .critical)])
        let engine = RuleEngine(rules: [allow], classifier: c)
        let d = engine.evaluate(process: zoomish, chain: [], targets: [key], enforcementActive: true, now: at(1))
        XCTAssertNotEqual(d.reason, .explicitAllow)
        XCTAssertFalse(d.suppressAlert)
        // At its own spelling the allow rule still works.
        let creds = EvaluationTarget(path: awsCreds, access: .read, categories: [TargetCategory(id: "aws", severity: .critical)])
        XCTAssertEqual(engine.evaluate(process: zoomish, chain: [], targets: [creds], enforcementActive: true, now: at(1)).reason,
                       .explicitAllow)
    }

    func testLatencyThresholdChangesApplyToTheBreachCount() {
        let m = LatencyMonitor(p99ThresholdMicros: 50_000, minimumSamples: 50)
        for _ in 0..<60 { m.record(micros: 20_000, missedDeadline: false) }
        m.evaluate()
        XCTAssertFalse(m.isTripped)
        m.p99ThresholdMicros = 10_000
        XCTAssertEqual(m.p99ThresholdMicros, 10_000)
        for _ in 0..<60 { m.record(micros: 20_000, missedDeadline: false) }
        m.evaluate()
        XCTAssertEqual(m.trippedReason, "p99 latency 20.0 ms over 10.0 ms")
    }
}
