import XCTest
@testable import WhoReadCore

// Regression tests for the path findings (files-1, files-2,
// files-3, files-6, files-7). Each test names the finding it covers and replays its scenario.

private func activity(_ op: FileOperation, _ p: ProcessRecord, _ targets: [FileTarget], _ t: TimeInterval = 10) -> FileActivity {
    FileActivity(time: at(t), operation: op, process: p, targets: targets)
}

/// What the AUTH path decides (Enforcer.decide without the enforcement switch).
private func authDecision(_ h: Harness, _ a: FileActivity, ask: AskPolicy = .off) -> RuleDecision {
    let targets = h.analyzer.classify(a).filter(\.isSensitive).map(\.evaluationTarget)
    let chain = h.tree.chain(for: a.process, at: a.time)
    return h.rules.evaluate(process: chain.first?.image ?? a.process, chain: chain, targets: targets, enforcementActive: true,
                            now: a.time, ask: ask)
}

/// Every category the AUTH path sees for an activity, at its worst severity.
private func categories(_ h: Harness, _ a: FileActivity) -> [String: Severity] {
    var out: [String: Severity] = [:]
    for t in h.analyzer.classify(a) {
        for c in t.categories { out[c.id] = max(out[c.id] ?? c.severity, c.severity) }
    }
    return out
}

private func enforced(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

/// Terminal → zsh → node running Claude Code (an agent) → leaf.
private func claudeShell(_ h: Harness, _ leaf: ProcessRecord) -> ProcessRecord {
    let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
    let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]))
    return h.spawn(claude, leaf)
}

/// `mv src dst` (or `cp -c`) of a directory, as both sources report it.
private func move(_ p: ProcessRecord, _ src: String, _ dst: String, dir: Bool? = true, clone: Bool = false) -> FileActivity {
    let s = ReportedPath(src, isDirectory: dir)
    let d = ReportedPath(dst)
    return clone ? activity(.clone, p, OperationSemantics.clone(s, d)) : activity(.rename, p, OperationSemantics.rename(s, d))
}

/// The default catalog with paths on the Custom category, plus extra categories.
private func catalog(custom: [String] = [], extra: [CategorySpec] = []) throws -> Catalog {
    var catalog = try defaultData().catalog
    if let i = catalog.categories.firstIndex(where: { $0.id == "custom" }) {
        catalog.categories[i].paths = custom
        catalog.categories[i].enabled = true
    }
    catalog.categories += extra
    return catalog
}

/// A harness whose analyzer (and rules) use a classifier over `catalog`, these homes and project roots.
private func harness(rules: [Rule] = [], catalog: Catalog? = nil, homes: [String] = [home], projectRoots: [String] = [],
                     symlinks: SymlinkResolver = NoSymlinkResolver()) throws -> Harness {
    let h = try Harness(rules: rules)
    h.analyzer.replace(classifier: PathClassifier(catalog: catalog ?? h.data.catalog, normalizer: PathNormalizer(homeDirectories: homes),
                                                  projectRoots: projectRoots, symlinks: symlinks))
    return h
}

private let blockCritical = enforced(RuleTemplates.blockAgentsFromCritical())

// MARK: - files-1: a moved directory carries every prefix inside it, wherever it is

final class CarriedPrefixesTests: XCTestCase {
    // files-1 (a): a home on an external volume.
    func testMovingFromAHomeOnAVolumeCarriesTheCategoriesBelow() throws {
        let bob = "/Volumes/Ext/bob"
        let h = try harness(rules: [blockCritical], homes: [home, bob])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        // Control: the same move in a home under /Users.
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/.config", "/Users/alice/x"))["gh"], .critical)

        let config = move(mv, bob + "/.config", "/Volumes/Ext/x")
        let c = categories(h, config)
        for id in ["gh", "gcloud", "git-credentials"] { XCTAssertEqual(c[id], .critical, id) }
        XCTAssertEqual(c["volumes"], .high, "still recorded as a volume access too")
        XCTAssertEqual(authDecision(h, config).verdict, .deny, "the critical-file template covers it")
        XCTAssertEqual(authDecision(h, config).ruleID, blockCritical.id)

        let out = h.analyzer.handle(.file(config))
        XCTAssertEqual(out.events.first { $0.categoryID == "gh" }?.viaAncestor, true)
        XCTAssertEqual(out.events.first { $0.categoryID == "volumes" }?.viaAncestor, false)

        for src in [bob + "/Library", bob] {
            let carried = categories(h, move(mv, src, "/Volumes/Ext/y"))
            XCTAssertEqual(carried["keychain"], .critical, src)
            XCTAssertEqual(carried["chrome"], .critical, src)
            XCTAssertEqual(carried["1password"], .critical, src)
        }
        XCTAssertEqual(categories(h, move(mv, bob, "/Volumes/Ext/y"))["ssh"], .critical)
        // A plain folder of the volume carries nothing more.
        XCTAssertEqual(categories(h, move(mv, bob + "/Movies/trip", "/Volumes/Ext/z")), ["volumes": .high])
    }

    // files-1 (b): a project root in a cloud folder.
    func testMovingAProjectRootInACloudFolderCarriesItsKeys() throws {
        let root = "/Users/alice/Library/CloudStorage/Dropbox/work"
        let h = try harness(rules: [blockCritical], projectRoots: [root])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        XCTAssertEqual(h.analyzer.classifier.classify(root + "/app/certs/server.key")?.severity, .critical)
        for src in [root, root + "/app", root + "/app/certs"] {
            let a = move(mv, src, "/private/tmp/c")
            XCTAssertEqual(categories(h, a)["project-secrets"], .critical, src)
            XCTAssertEqual(categories(h, a)["cloud-storage"], .high, src)
            XCTAssertEqual(authDecision(h, a).verdict, .deny, src)
        }
        // Same volume, still leaving the project.
        XCTAssertEqual(categories(h, move(mv, root + "/app/certs", "/Users/alice/Library/CloudStorage/Dropbox/c"))["project-secrets"],
                       .critical)
        // A refactor inside the project keeps base severity.
        let refactor = move(mv, root + "/app/certs", root + "/app/tls")
        XCTAssertEqual(categories(h, refactor), ["project-secrets": .high, "cloud-storage": .high])
        XCTAssertEqual(authDecision(h, refactor).verdict, .allow)
    }

    // files-1 (c): a link target inside a cloud folder.
    func testMovingACloudFolderHoldingALinkTargetCarriesTheLinkedCategory() throws {
        let target = "/Users/alice/Library/CloudStorage/Dropbox/private/ssh"
        let h = try harness(rules: [blockCritical], symlinks: MapSymlinkResolver(["/Users/alice/.ssh": target]))
        XCTAssertEqual(h.analyzer.classifier.classify(target + "/id_ed25519")?.categoryID, "ssh")
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        let a = move(mv, "/Users/alice/Library/CloudStorage/Dropbox/private", "/Users/alice/Library/CloudStorage/Dropbox/p")
        XCTAssertEqual(categories(h, a)["ssh"], .critical)
        XCTAssertEqual(authDecision(h, a).verdict, .deny)
    }

    // files-1 variant: a dotfiles repository inside a project root (no other category above it).
    func testMovingADotfilesRepoInsideAProjectRootCarriesTheLinkedCredentials() throws {
        let links = MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/credentials", target: "/Users/alice/code/dotfiles/aws/credentials")],
        ])
        let h = try harness(rules: [blockCritical], projectRoots: ["~/code"], symlinks: links)
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        let a = move(mv, "/Users/alice/code/dotfiles", "/private/tmp/d")
        XCTAssertEqual(categories(h, a)["aws"], .critical)
        XCTAssertEqual(categories(h, a)["project-secrets"], .critical)
        XCTAssertEqual(authDecision(h, a).verdict, .deny)
    }
}

// MARK: - files-2: a folder leaving a project root is judged by the keys it can carry

final class ProjectFolderMoveTests: XCTestCase {
    func testAFolderLeavingTheProjectIsCriticalAndARefactorIsNot() throws {
        let h = try harness(rules: [blockCritical], projectRoots: ["~/work"])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        XCTAssertEqual(authDecision(h, activity(.open, mv, OperationSemantics.open(path: "/Users/alice/work/app/certs/server.key", fflag: 1)))
            .verdict, .deny, "control: reading the key is denied")
        for (src, dst) in [("/Users/alice/work/app/certs", "/private/tmp/c"), ("/Users/alice/work/app", "/private/tmp/a"),
                           ("/Users/alice/work/app/certs", "/Users/alice/c")] {
            let a = move(mv, src, dst)
            XCTAssertEqual(categories(h, a), ["project-secrets": .critical], src + " -> " + dst)
            XCTAssertEqual(authDecision(h, a).verdict, .deny, src + " -> " + dst)
            XCTAssertEqual(categories(h, move(mv, src, dst, clone: true)), ["project-secrets": .critical], "clone " + src)
        }
        // Into a part of the project that is not monitored (exclusions): the keys leave monitoring.
        for dst in ["/Users/alice/work/app/node_modules/x", "/Users/alice/work/app/.git/x"] {
            XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/certs", dst)), ["project-secrets": .critical], dst)
        }
        // Refactors inside the project (or into another project root) keep base severity.
        let h2 = try harness(rules: [blockCritical], projectRoots: ["~/work", "~/code"])
        let mv2 = claudeShell(h2, proc(700, "/bin/mv", ppid: 600, platform: true))
        for dst in ["/Users/alice/work/app/tls", "/Users/alice/work/lib/certs", "/Users/alice/code/app/certs"] {
            let a = move(mv2, "/Users/alice/work/app/certs", dst)
            XCTAssertEqual(categories(h2, a), ["project-secrets": .high], dst)
            XCTAssertEqual(authDecision(h2, a).verdict, .allow, dst)
        }
        // A folder a pattern names (`.env.d`) follows the same rule.
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/.env.d", "/Users/alice/work/app/.env.old")),
                       ["project-secrets": .high])
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/.env.d", "/private/tmp/e")), ["project-secrets": .critical])
        // The root itself is critical wherever it goes.
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work", "/Users/alice/work2")), ["project-secrets": .critical])
    }

    // files-2 (review): the destination is itself the excluded folder (`node_modules`, `.git`) and does
    // not exist yet. The exclusions only match below such a folder, so the destination looked covered,
    // but every key the folder brings lands below it, out of the category.
    func testAFolderRenamedToAnExcludedNameLeavesTheProject() throws {
        let h = try harness(rules: [blockCritical], projectRoots: ["~/work"])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        XCTAssertNil(h.analyzer.classifier.classify("/Users/alice/work/app/node_modules/server.key"), "control: not monitored there")
        for dst in ["/Users/alice/work/app/node_modules", "/Users/alice/work/lib/.git", "/Users/alice/work/node_modules"] {
            for clone in [false, true] {
                let a = move(mv, "/Users/alice/work/app/certs", dst, clone: clone)
                XCTAssertEqual(categories(h, a), ["project-secrets": .critical], "\(dst) clone \(clone)")
                XCTAssertEqual(authDecision(h, a).verdict, .deny, "\(dst) clone \(clone)")
            }
        }
        // A folder a pattern names (`.env.d`) as well.
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/.env.d", "/Users/alice/work/app/node_modules")),
                       ["project-secrets": .critical])
        // Names that only resemble them stay inside the project.
        for dst in ["/Users/alice/work/app/node_modules_old", "/Users/alice/work/app/.github", "/Users/alice/work/app/git"] {
            XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/certs", dst)), ["project-secrets": .high], dst)
        }
    }

    // files-2 variant: a source that does not say whether it is a directory may be one.
    func testAMoveOfUnknownTypeInsideAProjectIsRecorded() throws {
        let h = try harness(projectRoots: ["~/work"])
        let mv = proc(700, "/bin/mv", platform: true)
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/certs", "/private/tmp/c", dir: nil))["project-secrets"], .critical)
        XCTAssertEqual(categories(h, move(mv, "/Users/alice/work/app/main.swift", "/private/tmp/m", dir: false)), [:],
                       "a plain file is not a carrier")
    }
}

// MARK: - files-3: destinations that plant a parent of monitored prefixes

final class CarriedInTests: XCTestCase {
    private let deny = enforced(Rule(id: "deny-gh", target: .category("gh"), subject: .anyNonOwner, action: .deny,
                                     includePlatformBinaries: true))
    private let ask = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)

    func testPlantingAParentOfMonitoredPrefixesIsDecided() throws {
        let h = try harness(rules: [deny], projectRoots: ["~/code"])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        // Control: planting the prefix itself.
        XCTAssertEqual(categories(h, move(mv, "/private/tmp/p/gh", "/Users/alice/.config/gh"))["gh"], .critical)
        for clone in [false, true] {
            let plant = move(mv, "/private/tmp/p", "/Users/alice/.config", clone: clone)
            let classified = h.analyzer.classify(plant).filter(\.isSensitive)
            XCTAssertEqual(classified.map(\.target.role), [.destination])
            let planted = try XCTUnwrap(classified.first)
            XCTAssertEqual(Set(planted.categories.map(\.id)), ["gh", "gcloud", "git-credentials"])
            XCTAssertTrue(planted.categories.allSatisfy { $0.severity == .critical })
            XCTAssertTrue(planted.viaAncestor)
            XCTAssertEqual(planted.target.access, .write)
            XCTAssertEqual(authDecision(h, plant).verdict, .deny, "clone \(clone)")
            let out = h.analyzer.handle(.file(plant))
            XCTAssertEqual(Set(out.events.map(\.categoryID)), ["gh", "gcloud", "git-credentials"])
        }
        // A symlink made elsewhere and renamed onto the parent redirects it just the same: what the
        // destination carries does not depend on the source being a directory.
        let linkMoved = move(mv, "/private/tmp/l", "/Users/alice/.config", dir: false)
        XCTAssertEqual(categories(h, linkMoved), ["gh": .critical, "gcloud": .critical, "git-credentials": .critical])
        XCTAssertEqual(authDecision(h, linkMoved).verdict, .deny)
        // A folder moved into a project root carries its .env in.
        let intoProject = move(mv, "/private/tmp/x", "/Users/alice/code/app/config")
        XCTAssertEqual(categories(h, intoProject), ["project-secrets": .high])
        XCTAssertEqual(authDecision(h, intoProject, ask: ask).verdict, .ask)
        // A file moved there carries nothing that is not its own.
        XCTAssertEqual(categories(h, move(mv, "/private/tmp/notes", "/Users/alice/code/app/notes", dir: false)), [:])
        XCTAssertEqual(categories(h, move(mv, "/private/tmp/x", "/Users/alice/code/app/.env", dir: false)), ["project-secrets": .high])
    }

    func testASymlinkCreatedAtAParentIsDecidedButAFolderIsNot() throws {
        let h = try harness(rules: [deny], projectRoots: ["~/code"])
        let ln = claudeShell(h, proc(700, "/bin/ln", ppid: 600, platform: true))
        // NOTIFY_CREATE (eslogger, native): the stat says what was created.
        let link = activity(.create, ln, OperationSemantics.create(ReportedPath("/Users/alice/.config", isDirectory: false)))
        XCTAssertEqual(categories(h, link), ["gh": .critical, "gcloud": .critical, "git-credentials": .critical])
        XCTAssertEqual(authDecision(h, link).verdict, .deny)
        XCTAssertEqual(Set(h.analyzer.handle(.file(link)).events.map(\.categoryID)), ["gh", "gcloud", "git-credentials"])
        XCTAssertEqual(categories(h, activity(.create, ln, OperationSemantics.create(ReportedPath("/Users/alice/code", isDirectory: false)))),
                       ["project-secrets": .critical], "a link in place of a project root")
        // A new directory carries nothing.
        let mkdir = activity(.create, ln, OperationSemantics.create(ReportedPath("/Users/alice/.config", isDirectory: true)))
        XCTAssertEqual(categories(h, mkdir), [:])
        XCTAssertEqual(authDecision(h, mkdir, ask: ask).verdict, .allow)
        // AUTH_CREATE does not say what it creates: not decided (recorded by NOTIFY_CREATE once it exists).
        XCTAssertEqual(categories(h, activity(.create, ln, OperationSemantics.create(ReportedPath("/Users/alice/.config")))), [:])
        // Links inside a project are not carriers (virtualenvs are full of them).
        XCTAssertEqual(categories(h, activity(.create, ln, OperationSemantics.create(
            ReportedPath("/Users/alice/code/app/.venv/bin/python", isDirectory: false)))), [:])
        // Inside a prefix a create is classified as before.
        XCTAssertEqual(categories(h, activity(.create, ln, OperationSemantics.create(
            ReportedPath("/Users/alice/.ssh/authorized_keys", isDirectory: false))))["ssh"], .medium)
    }

    func testThroughTheEsloggerParser() throws {
        let h = try harness(rules: [deny])
        func createLine(_ path: String, mode: Int) -> String {
            #"{"schema_version":1,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/bin\/ln"}},"event":{"create":{"destination_type":0,"destination":{"existing_file":{"path":"\#(path)","stat":{"st_mode":\#(mode)}}}}}}"#
        }
        func parsed(_ line: String) -> FileActivity? {
            if case .event(.file(let f)) = EsloggerParser().parse(line: line) { return f }
            return nil
        }
        let link = try XCTUnwrap(parsed(createLine(#"\/Users\/alice\/.config"#, mode: 0o120755)))
        XCTAssertEqual(categories(h, link)["gh"], .critical)
        let dir = try XCTUnwrap(parsed(createLine(#"\/Users\/alice\/.config"#, mode: 0o40755)))
        XCTAssertEqual(categories(h, dir), [:])
    }

    // files-3 variant (with files-1): planting a parent inside another prefix (a home on a volume).
    func testPlantingInsideAVolumeHomeCarriesTheCategoriesBelow() throws {
        let bob = "/Volumes/Ext/bob"
        let h = try harness(rules: [deny], homes: [home, bob])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        let plant = move(mv, "/Volumes/Ext/p", bob + "/.config")
        XCTAssertEqual(categories(h, plant)["gh"], .critical)
        XCTAssertEqual(authDecision(h, plant).verdict, .deny)
    }
}

// MARK: - files-6: a custom prefix nested in another category never demotes its files

final class NestedCustomPrefixTests: XCTestCase {
    func testACustomPathInsideSSHKeepsTheKeysSSHCritical() throws {
        let c = PathClassifier(catalog: try catalog(custom: ["~/.ssh/work", "~/vault"]), normalizer: PathNormalizer(homeDirectories: [home]))
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/id_ed25519")?.categoryID, "ssh")
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/id_ed25519")?.severity, .critical)
        XCTAssertEqual(c.classify("/Users/alice/.ssh/id_ed25519")?.severity, .critical)
        // More severe than what ssh says (its config is medium): the custom path wins.
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/config")?.categoryID, "custom")
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/config")?.severity, .high)
        // Not nested in anything: as before.
        XCTAssertEqual(c.classify("/Users/alice/vault/x")?.categoryID, "custom")

        // The ssh template and critical rules keep covering the key.
        let h = try harness(rules: [enforced(RuleTemplates.denyNonOwnersSSH())], catalog: try catalog(custom: ["~/.ssh/work"]))
        let cat = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), proc(501, "/opt/homebrew/bin/gcat", ppid: 500))
        let read = activity(.open, cat, OperationSemantics.open(path: "/Users/alice/.ssh/work/id_ed25519", fflag: 1))
        XCTAssertEqual(authDecision(h, read).verdict, .deny)
    }

    func testAUserCategoryOfTheSameSeverityKeepsItsFiles() throws {
        let keys = CategorySpec(id: "work-keys", name: LocalizedText(en: "Work keys", zhHans: "Work keys"), kind: .custom,
                                severity: .critical, paths: ["~/.ssh/work"])
        let c = PathClassifier(catalog: try catalog(extra: [keys]), normalizer: PathNormalizer(homeDirectories: [home]))
        // A deliberate carve-out at the same severity: its own category (critical-file rules still cover it).
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/id_ed25519")?.categoryID, "work-keys")
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/id_ed25519")?.severity, .critical)
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/known_hosts")?.categoryID, "work-keys")
        XCTAssertEqual(c.classify("/Users/alice/.ssh/work/known_hosts")?.severity, .critical)
    }

    // A custom path inside a category of the same severity stays custom: an answer about the outer
    // category does not decide it.
    func testACustomCarveOutInACloudFolderIsNotAnsweredByTheCloudFolder() throws {
        let terminalKey = "app:/system/applications/utilities/terminal.app"
        let answer = Rule(id: "cloud-answer", target: .category("cloud-storage"), subject: .responsible(key: terminalKey, teamID: nil),
                          access: .read, action: .allow, template: RuleTemplates.askAnswer, chainAgents: [])
        let carveOut = "/Users/alice/Library/CloudStorage/Dropbox/secret"
        let h = try harness(rules: [answer], catalog: try catalog(custom: [carveOut]))
        XCTAssertEqual(h.analyzer.classifier.classify(carveOut + "/plan.txt")?.categoryID, "custom")
        let cat = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), P.cat(501, parent: 500))
        let ask = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)
        let elsewhere = activity(.open, cat, OperationSemantics.open(path: "/Users/alice/Library/CloudStorage/Dropbox/notes.txt", fflag: 1))
        XCTAssertEqual(authDecision(h, elsewhere, ask: ask).verdict, .allow, "control: the answer covers the cloud folder")
        let inside = activity(.open, cat, OperationSemantics.open(path: carveOut + "/plan.txt", fflag: 1))
        XCTAssertEqual(authDecision(h, inside, ask: ask).verdict, .ask)
    }

    // files-6 variant: project roots nested in other prefixes.
    func testAProjectRootNeverDemotesTheFilesOfAnOuterPrefix() throws {
        let c = PathClassifier(catalog: try catalog(custom: ["~/Sync", "~/code/secret"]), normalizer: PathNormalizer(homeDirectories: [home]),
                               projectRoots: ["~/.aws/proj", "~/Sync/work", "~/code"])
        // Inside ~/.aws: the credentials folder stays critical.
        XCTAssertEqual(c.classify("/Users/alice/.aws/proj/.env")?.categoryID, "aws")
        XCTAssertEqual(c.classify("/Users/alice/.aws/proj/.env")?.severity, .critical)
        // Inside a folder of the same severity: the project keeps its .env (ties go to the project).
        XCTAssertEqual(c.classify("/Users/alice/Sync/work/.env")?.categoryID, "project-secrets")
        XCTAssertEqual(c.classify("/Users/alice/Sync/work/server.pem")?.severity, .critical)
        XCTAssertEqual(c.classify("/Users/alice/Sync/work/README.md")?.categoryID, "custom")
        // A custom path inside a project root: its own files are custom, the keys stay project secrets.
        XCTAssertEqual(c.classify("/Users/alice/code/secret/notes.txt")?.categoryID, "custom")
        XCTAssertEqual(c.classify("/Users/alice/code/secret/server.pem")?.categoryID, "project-secrets")
        XCTAssertEqual(c.classify("/Users/alice/code/secret/server.pem")?.severity, .critical)
        // Moving that custom folder out carries the project's keys too.
        XCTAssertEqual(c.containingCategories(normalized: "/Users/alice/code/secret/certs").map(\.id), ["custom", "project-secrets"])
    }
}

// MARK: - files-3 / files-7: the eslogger prefilter

final class PrefilterFindingsTests: XCTestCase {
    private func line(_ event: String) -> String {
        #"{"schema_version":1,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/bin\/ln"}},"event":{\#(event)}}"#
    }
    private func create(_ jsonPath: String) -> String {
        line(#""create":{"destination_type":0,"destination":{"existing_file":{"path":"\#(jsonPath)","stat":{"st_mode":41453}}}}"#)
    }
    private func open(_ jsonPath: String) -> String { line(#""open":{"fflag":1,"file":{"path":"\#(jsonPath)"}}"#) }

    // files-3: a create at exactly an ancestor of a prefix is parsed, every spelling of it.
    func testACreateAtAnAncestorIsParsed() throws {
        let h = try Harness()
        let filter = LinePrefilter(prefixes: h.classifier.mutePaths, ancestors: h.classifier.ancestors)
        XCTAssertTrue(h.classifier.ancestors.contains("/Users/alice/.config"))
        for spelling in ["/Users/alice/.config", #"\/Users\/alice\/.config"#, "/System/Volumes/Data/Users/alice/.config",
                         "/USERS/alice/.CONFIG"] {
            XCTAssertEqual(filter.verdict(create(spelling)), .parse, spelling)
        }
        // Not below it, beside it or above it (a home must not let every event through).
        for path in ["/Users/alice/.config/other/x", "/Users/alice/.configx", "/Users/alice/notes.txt"] {
            XCTAssertEqual(filter.verdict(create(path)), .drop, path)
            XCTAssertEqual(filter.verdict(open(path)), .drop, path)
        }
        XCTAssertEqual(LinePrefilter(prefixes: h.classifier.mutePaths).verdict(create("/Users/alice/.config")), .drop,
                       "without ancestors (as before)")
        // Only a create at an ancestor matters: opening (listing) the home, ~/Library or ~/.config is
        // frequent and never sensitive, so those lines are not parsed for it.
        XCTAssertTrue(h.classifier.ancestors.contains("/Users/alice"))
        for path in ["/Users/alice", "/Users/alice/Library", "/Users/alice/.config", #"\/Users\/alice\/Library"#] {
            XCTAssertEqual(filter.verdict(open(path)), .drop, path)
            XCTAssertEqual(filter.verdict(line(#""unlink":{"target":{"path":"\#(path)"}}"#)), .drop, path)
        }
        XCTAssertEqual(filter.verdict(create("/Users/alice/Library")), .parse)
        // The parsed line is an event at that ancestor.
        guard case .event(.file(let f)) = EsloggerParser().parse(line: create(#"\/Users\/alice\/.config"#)) else { return XCTFail() }
        XCTAssertEqual(h.analyzer.handle(.file(f)).events.map(\.categoryID).sorted(), ["gcloud", "gh", "git-credentials"])
        // A non-ASCII ancestor cannot be matched exactly: every create is parsed then.
        let cjk = LinePrefilter(prefixes: ["/Users/alice/项目/app"], ancestors: ["/Users", "/Users/alice", "/Users/alice/项目"])
        XCTAssertEqual(cjk.verdict(create("/Users/bob/x")), .parse)
        XCTAssertEqual(cjk.verdict(open("/Users/bob/x")), .drop)
    }

    // files-7: prefixes with characters JSON escapes.
    func testPrefixesWithQuotesBackslashesAndControlCharacters() {
        let filter = LinePrefilter(prefixes: [#"/Users/bob/code/a"b"#, #"/Users/bob/code/c\d"#, "/Users/bob/Icon\r", "/Users/bob/t\tab"])
        for path in [#"/Users/bob/code/a\"b/.env"#, #"\/Users\/bob\/code\/a\"b\/.env"#,
                     #"/Users/bob/code/c\\d/.env"#, #"\/Users\/bob\/code\/c\\d\/.env"#,
                     #"/Users/bob/Icon\r/x"#, #"\/Users\/bob\/Icon\r\/x"#, #"/Users/bob/t\tab/x"#,
                     #"/System/Volumes/Data/Users/bob/code/a\"b/.env"#] {
            XCTAssertEqual(filter.verdict(open(path)), .parse, path)
        }
        XCTAssertEqual(filter.verdict(open("/Users/bob/code/ab/.env")), .drop)
        // The parser gets the real path back.
        guard case .event(.file(let f)) = EsloggerParser().parse(line: open(#"\/Users\/bob\/code\/a\"b\/.env"#)) else { return XCTFail() }
        XCTAssertEqual(f.targets.first?.path, #"/Users/bob/code/a"b/.env"#)
        // The ASCII fragment of a non-ASCII prefix is escaped too.
        let cjk = LinePrefilter(prefixes: [#"/Users/项/code"dir"#])
        XCTAssertEqual(LinePrefilter.needle(for: #"/Users/项/code"dir"#), #"/code"dir"#)
        XCTAssertEqual(cjk.verdict(open(#"\/Users\/项\/code\"dir\/x"#)), .parse)
        XCTAssertEqual(cjk.verdict(open(#"/Users/项/code\"dir/x"#)), .parse)
    }
}

// MARK: - Recompiling rules never holds up evaluation (AUTH path)

final class RuleRecompileTests: XCTestCase {
    private let sshKey = EvaluationTarget(path: "/Users/alice/.ssh/id_ed25519", access: .read,
                                          categories: [TargetCategory(id: "ssh", severity: .critical)])

    /// Many homes (a shared Mac), and `c2` adds one. Built once: building them is slow too.
    private static let classifiers: (c1: PathClassifier, c2: PathClassifier) = {
        let catalog = try! defaultData().catalog
        let homes = [home] + (0..<60).map { "/Users/u\($0)" }
        return (PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: homes)),
                PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: homes + ["/Users/new"])))
    }()

    /// 500 path rules: compiling them all (each `~` expands once per home) takes long enough to measure.
    private func manyRules() throws -> (engine: RuleEngine, c1: PathClassifier, c2: PathClassifier) {
        let (c1, c2) = RuleRecompileTests.classifiers
        var rules = (0..<500).map { Rule(id: "r\($0)", target: .pathPrefix("~/vault/\($0)"), subject: .anyNonOwner, action: .alert) }
        var deny = Rule(id: "deny-ssh", enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny,
                        includePlatformBinaries: true)
        deny.exceptions = [RuleException(subject: .signed(signingID: "com.apple.cat", teamID: nil), remainingUses: 1)]
        rules.append(deny)
        return (RuleEngine(rules: rules, classifier: c1), c1, c2)
    }

    private func seconds(_ f: () -> Void) -> TimeInterval {
        let start = Date()
        f()
        return Date().timeIntervalSince(start)
    }

    func testAnEditOrAPruneRecompilesOnlyWhatChanged() throws {
        let (engine, _, c2) = try manyRules()
        let full = seconds { engine.replace(classifier: c2) }
        let edit = seconds { engine.mutate { $0.append(Rule(id: "late", target: .pathPrefix("~/late"), subject: .anyNonOwner, action: .alert)) } }
        XCTAssertLessThan(edit, full / 4, "an edit took \(edit) s, recompiling everything \(full) s")
        let late = EvaluationTarget(path: "/Users/new/late/x", access: .read, categories: [TargetCategory(id: "custom", severity: .high)])
        XCTAssertEqual(engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [late], enforcementActive: true, now: at(1)).ruleID,
                       "late", "the new rule is compiled against the current classifier")
        // Using up the "allow once", then pruning it.
        XCTAssertEqual(engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [sshKey], enforcementActive: true, now: at(2)).verdict,
                       .allow)
        let prune = seconds { XCTAssertTrue(engine.pruneDeadExceptions(at: at(3))) }
        XCTAssertLessThan(prune, full / 4, "a prune took \(prune) s, recompiling everything \(full) s")
        XCTAssertEqual(engine.rules.first { $0.id == "deny-ssh" }?.exceptions.count, 0)
        XCTAssertEqual(engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [sshKey], enforcementActive: true, now: at(4)).verdict,
                       .deny)
    }

    func testEvaluationGoesOnWhileRulesAreRecompiledForANewClassifier() throws {
        let (engine, c1, c2) = try manyRules()
        let full = seconds { engine.replace(classifier: c2) }
        guard full > 0.1 else { throw XCTSkip("recompiling took only \(full) s here: too fast to tell") }
        let started = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        var replaceEnd = Date.distantFuture
        DispatchQueue.global().async {
            started.signal()
            engine.replace(classifier: c1)
            replaceEnd = Date()
            finished.signal()
        }
        started.wait()
        let evaluateStart = Date()
        // Uses the "allow once" while the recompile runs.
        let d = engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [sshKey], enforcementActive: true, now: at(1))
        let waited = Date().timeIntervalSince(evaluateStart)
        // A rule added meanwhile (usually while the recompile still runs).
        engine.mutate { $0.append(Rule(id: "late", target: .pathPrefix("~/late"), subject: .anyNonOwner, action: .alert)) }
        XCTAssertEqual(finished.wait(timeout: .now() + 60), .success)
        guard evaluateStart < replaceEnd else { throw XCTSkip("the recompile ended before the evaluation started: inconclusive") }
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertLessThan(waited, full / 4, "an evaluation waited \(waited) s for a recompile of \(full) s")
        // Nothing done meanwhile is lost or compiled against the old classifier.
        XCTAssertEqual(engine.rules.first { $0.id == "deny-ssh" }?.exceptions.first?.remainingUses, 0, "a used allow-once is not restored")
        let late = EvaluationTarget(path: "/Users/u3/late/x", access: .read, categories: [TargetCategory(id: "custom", severity: .high)])
        XCTAssertEqual(engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [late], enforcementActive: true, now: at(2)).ruleID,
                       "late")
        let gone = EvaluationTarget(path: "/Users/new/vault/7/x", access: .read, categories: [TargetCategory(id: "custom", severity: .high)])
        XCTAssertNil(engine.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [gone], enforcementActive: true, now: at(3)).ruleID,
                     "compiled against the classifier swapped in last")
    }
}
