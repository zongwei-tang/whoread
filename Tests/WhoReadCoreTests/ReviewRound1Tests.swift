import XCTest
@testable import WhoReadCore

// Regression tests for review round 1. Each test names the finding it covers and
// replays the finding's scenario against the current code.

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let chromeProfile = "/Users/alice/Library/Application Support/Google/Chrome/Default"
private let terminalKey = "app:/system/applications/utilities/terminal.app"

/// What the AUTH path decides (Enforcer.decide without the enforcement switch).
private func authDecision(_ h: Harness, _ activity: FileActivity, consume: Bool = true) -> RuleDecision {
    let targets = h.analyzer.classify(activity).filter(\.isSensitive).map(\.evaluationTarget)
    let chain = h.tree.chain(for: activity.process, at: activity.time)
    let process = chain.first?.image ?? activity.process
    return h.rules.evaluate(process: process, chain: chain, targets: targets, enforcementActive: true, now: activity.time,
                            consumeExceptions: consume)
}

private func activity(_ op: FileOperation, _ p: ProcessRecord, _ targets: [FileTarget], _ t: TimeInterval = 10) -> FileActivity {
    FileActivity(time: at(t), operation: op, process: p, targets: targets)
}

private func readTargets(_ path: String) -> [FileTarget] { OperationSemantics.open(path: path, fflag: 1) }

/// Terminal → zsh → leaf. Returns the leaf.
private func terminalShell(_ h: Harness, _ leaf: ProcessRecord, t: TimeInterval = 0) -> ProcessRecord {
    let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100), t)
    return h.spawn(zsh, leaf, t)
}

/// zsh → node running Claude Code (an agent) → leaf. Returns the leaf.
private func claudeShell(_ h: Harness, _ leaf: ProcessRecord, t: TimeInterval = 0) -> ProcessRecord {
    let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100), t)
    let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), t)
    return h.spawn(claude, leaf, t)
}

private func enforced(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

// MARK: - Catalog / classifier (paths-*)

final class ClassifierRound1Tests: XCTestCase {
    // paths-12
    func testComponentsSplitOnUnicodeScalars() throws {
        XCTAssertEqual("/a/\u{301}b".split(separator: "/").count, 1, "Character split merges the boundary (the bug)")
        XCTAssertEqual(PathNormalizer.components("/a/\u{301}b"), ["a", "\u{301}b"])
        let h = try Harness()
        let c = h.classifier.classify("/Users/alice/.ssh/\u{301}k")
        XCTAssertEqual(c?.categoryID, "ssh")
        XCTAssertEqual(c?.severity, .critical)
        XCTAssertEqual(c?.relativePath, "\u{301}k")
        // lexicallyClean keeps the boundary too.
        XCTAssertEqual(h.normalizer.normalize("/Users/alice//.ssh/./\u{301}k"), "/Users/alice/.ssh/\u{301}k")
        XCTAssertEqual(h.classifier.classify("/Users/alice//.ssh/../.ssh/\u{301}k")?.categoryID, "ssh")
        // A ZWJ right after "/" is a boundary as well.
        XCTAssertEqual(h.classifier.classify("/Users/alice/.aws/\u{200D}credentials")?.categoryID, "aws")
    }

    // paths-7
    func testDeepestPrefixFallsBackToShallowerOnes() throws {
        let h = try Harness(projectRoots: ["~/Library/Mobile Documents/com~apple~CloudDocs/dev", "/Volumes/Work/src"])
        let icloud = "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs"
        XCTAssertEqual(h.classifier.classify(icloud + "/notes.txt")?.categoryID, "cloud-storage")
        let code = h.classifier.classify(icloud + "/dev/app/main.swift")
        XCTAssertEqual(code?.categoryID, "cloud-storage", "project-root patterns reject main.swift; iCloud still applies")
        XCTAssertEqual(code?.severity, .high)
        XCTAssertEqual(h.classifier.classify(icloud + "/dev/app/.env")?.categoryID, "project-secrets", "deeper prefix wins when it matches")
        XCTAssertEqual(h.classifier.classify(icloud + "/dev/certs/server.pem")?.severity, .critical)
        XCTAssertEqual(h.classifier.classify("/Volumes/Work/src/app/secret.txt")?.categoryID, "volumes")
        // An exclusion on the deeper prefix also falls back.
        XCTAssertEqual(h.classifier.classify("/Volumes/Work/src/node_modules/x/.env")?.categoryID, "volumes")
    }

    // paths-13
    func testTruncatedPathsGetTheWorstCaseSeverity() throws {
        let h = try Harness(projectRoots: ["~/code"])
        let cut = chromeProfile + "/Network/Coo"
        XCTAssertEqual(h.classifier.classify(cut)?.severity, .medium)
        XCTAssertEqual(h.classifier.classify(cut, truncated: true)?.severity, .critical)
        XCTAssertNil(h.classifier.classify("/Users/alice/code/deep/ab"))
        let project = h.classifier.classify("/Users/alice/code/deep/ab", truncated: true)
        XCTAssertEqual(project?.categoryID, "project-secrets", "matchOnlyPatterns cannot reject a name it cannot see")
        XCTAssertEqual(project?.severity, .critical)
        XCTAssertEqual(h.classifier.maxSeverity("chrome"), .critical)
        XCTAssertEqual(h.classifier.maxSeverity("ssh"), .critical)
        XCTAssertEqual(h.classifier.maxSeverity("project-secrets"), .critical)
        XCTAssertEqual(h.classifier.maxSeverity("shell-history"), .high)
        XCTAssertNil(h.classifier.maxSeverity("no-such-category"))
        // The analyzer passes FileTarget.truncated through.
        let cat = terminalShell(h, P.cat(501, parent: 500))
        let out = h.file(.open, cat, [FileTarget(path: cut, role: .target, access: .read, truncated: true)], 5)
        XCTAssertEqual(out.events.first?.severity, .critical)
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
    }

    // paths-10
    func testMutePathsKeepEveryByteDistinctSpelling() throws {
        let data = try defaultData()
        let n = PathNormalizer(homeDirectories: [home])
        let c = PathClassifier(catalog: data.catalog, normalizer: n, projectRoots: ["~/Projects"],
                               symlinks: MapSymlinkResolver(["/Users/alice/Projects": "/Users/alice/projects"]))
        XCTAssertTrue(c.mutePaths.contains("/Users/alice/Projects"))
        XCTAssertTrue(c.mutePaths.contains("/Users/alice/projects"), "on-disk spelling is muted too")
        XCTAssertEqual(c.prefixes.filter { $0.categoryID == "project-secrets" }.count, 1, "the trie dedups case-only spellings")
        XCTAssertEqual(c.classify("/Users/alice/projects/web/.env")?.categoryID, "project-secrets")
        XCTAssertEqual(Set(c.mutePaths).count, c.mutePaths.count, "no byte-identical duplicates")
        XCTAssertTrue(c.ancestors.contains("/Users/alice"))
        XCTAssertFalse(c.ancestors.contains("/Users/alice/projects"), "a monitored prefix is not an ancestor")
    }

    // paths-9
    func testSymlinkTargetsInsideDirectoryPrefixesAreMonitored() throws {
        let data = try defaultData()
        let n = PathNormalizer(homeDirectories: [home])
        let resolver = MapSymlinkResolver([:], links: [
            "/Users/alice/.aws": [(link: "/Users/alice/.aws/credentials", target: "/Users/alice/dotfiles/aws/credentials")],
        ])
        let c = PathClassifier(catalog: data.catalog, normalizer: n, symlinks: resolver)
        let hit = c.classify("/Users/alice/dotfiles/aws/credentials")
        XCTAssertEqual(hit?.categoryID, "aws")
        XCTAssertEqual(hit?.severity, .critical)
        XCTAssertTrue(c.prefixes.contains(MonitoredPrefix(path: "/Users/alice/dotfiles/aws/credentials", categoryID: "aws", viaSymlink: true)))
        XCTAssertTrue(c.mutePaths.contains("/Users/alice/dotfiles/aws/credentials"), "ES muting covers the link target")
        XCTAssertNil(c.classify("/Users/alice/dotfiles/aws/README"), "only the linked file, not its siblings")
    }

    // paths-6
    func testProjectRootAndFoldersInsideItAreCoveredWhenMoved() throws {
        let h = try Harness(projectRoots: ["~/code"])
        let c = h.classifier
        XCTAssertNil(c.classify("/Users/alice/code"))
        XCTAssertNil(c.classify("/Users/alice/code/web"))
        XCTAssertEqual(c.categoriesBelow(normalized: "/Users/alice/code"), ["project-secrets"], "the root itself carries its secrets")
        XCTAssertEqual(c.categoriesBelow(normalized: "/Users/alice/code/web"), [])
        XCTAssertEqual(c.containingCategory(normalized: "/Users/alice/code/web"), TargetCategory(id: "project-secrets", severity: .high))
        XCTAssertNil(c.containingCategory(normalized: "/Users/alice/code/web/node_modules/pkg"), "exclusions still apply")
        XCTAssertNil(c.containingCategory(normalized: "/Users/alice/Documents/web"))

        let mv = terminalShell(h, proc(501, "/bin/mv", ppid: 500, platform: true))
        func rename(_ src: String, dir: Bool?) -> AnalysisOutput {
            h.file(.rename, mv, OperationSemantics.rename(ReportedPath(src, isDirectory: dir), ReportedPath("/private/tmp/w")), 5)
        }
        let sub = rename("/Users/alice/code/web", dir: true)
        XCTAssertEqual(sub.events.map(\.categoryID), ["project-secrets"])
        XCTAssertEqual(sub.events.first?.severity, .high, "base severity: renaming project folders is not critical")
        XCTAssertEqual(sub.events.first?.viaAncestor, true)
        let root = rename("/Users/alice/code", dir: true)
        XCTAssertEqual(root.events.map(\.categoryID), ["project-secrets"])
        XCTAssertTrue(rename("/Users/alice/code/web/main.swift", dir: false).events.isEmpty, "a plain file is not a carrier")
        // Clone (cp -c -R) of the folder is covered the same way.
        let clone = h.file(.clone, mv, OperationSemantics.clone(ReportedPath("/Users/alice/code/web", isDirectory: true),
                                                              ReportedPath("/private/tmp/w")), 6)
        XCTAssertEqual(clone.events.map(\.categoryID), ["project-secrets"])
    }

    // paths-14
    func testAccountWebDataIsCriticalInEveryChromiumBrowser() throws {
        let h = try Harness()
        let profiles = [
            "/Users/alice/Library/Application Support/Google/Chrome/Default",
            "/Users/alice/Library/Application Support/BraveSoftware/Brave-Browser/Default",
            "/Users/alice/Library/Application Support/Microsoft Edge/Default",
            "/Users/alice/Library/Application Support/Arc/User Data/Default",
        ]
        for p in profiles {
            XCTAssertEqual(h.classifier.classify(p + "/Account Web Data")?.severity, .critical, p)
            XCTAssertEqual(h.classifier.classify(p + "/Account Web Data-journal")?.severity, .critical, p)
            XCTAssertEqual(h.classifier.classify(p + "/Web Data")?.severity, .critical, p)
            XCTAssertEqual(h.classifier.classify(p + "/Preferences")?.severity, .medium, p)
        }
    }
}

// MARK: - Owner identities (paths-1..5, paths-11)

final class OwnerRound1Tests: XCTestCase {
    // paths-1
    func testArgvMatchesOnlyAtTheScriptPositionAndNeverAlone() throws {
        let h = try Harness()
        let creds = "/Users/alice/.aws/credentials"
        let catTrick = proc(501, "/bin/cat", platform: true, argv: ["cat", creds, "/x/bin/aws"])
        XCTAssertFalse(h.classifier.isOwner(catTrick, of: "aws"))
        XCTAssertFalse(IdentitySpec(argvGlobs: ["**/bin/aws"]).matches(catTrick), "argv alone pins nothing")
        let python = "/opt/homebrew/Cellar/python@3.12/3.12.4/bin/python3.12"
        XCTAssertTrue(h.classifier.isOwner(proc(502, python, argv: ["python3.12", "/opt/homebrew/bin/aws", "s3", "ls"]), of: "aws"))
        XCTAssertFalse(h.classifier.isOwner(proc(503, python, argv: ["python3.12", "-c", "print(1)", "/opt/homebrew/bin/aws"]), of: "aws"),
                       "argv elements after the script are not the script")
        XCTAssertFalse(h.classifier.isOwner(proc(504, "/private/tmp/python3", argv: ["/tmp/python3", "/opt/homebrew/bin/aws", creds]), of: "aws"),
                       "a copied binary named python3 is not an interpreter location")
        XCTAssertFalse(h.classifier.isOwner(proc(505, python, argv: ["python3.12", "/tmp/bin/aws"]), of: "aws"), "**/bin/aws is gone")
        // Other categories that had argv-only owners.
        let node = "/opt/homebrew/Cellar/node/22.9.0/bin/node"
        XCTAssertFalse(h.classifier.isOwner(proc(506, "/bin/cat", platform: true, argv: ["cat", "x", "/x/bin/claude"]), of: "claude-sessions"))
        XCTAssertTrue(h.classifier.isOwner(proc(507, node, argv: ["node", "/opt/homebrew/bin/claude"]), of: "claude-sessions"))

        XCTAssertEqual(IdentitySpec.scriptArgument(["python3", "-m", "awscli", "s3"]), "awscli")
        XCTAssertEqual(IdentitySpec.scriptArgument(["python3", "-Im", "awscli"]), "awscli")
        XCTAssertEqual(IdentitySpec.scriptArgument(["node", "--no-warnings", "/opt/homebrew/bin/claude", "-p"]), "/opt/homebrew/bin/claude")
        XCTAssertEqual(IdentitySpec.scriptArgument(["python3", "-u", "/opt/homebrew/bin/aws"]), "/opt/homebrew/bin/aws")
        XCTAssertNil(IdentitySpec.scriptArgument(["cat"]))
        XCTAssertNil(IdentitySpec.scriptArgument(nil))
        XCTAssertNil(IdentitySpec.scriptArgument(["python3", "-m"]))
    }

    // paths-2
    func testNamesOnlySpecsMatchNothing() throws {
        let h = try Harness()
        XCTAssertFalse(IdentitySpec(names: ["gh"]).matches(proc(1, "/private/tmp/gh")))
        let impostors: [(String, String)] = [("/private/tmp/gh", "gh"), ("/private/tmp/kubectl", "kube"), ("/private/tmp/gpg", "gnupg"),
                                            ("/private/tmp/terraform", "aws"), ("/private/tmp/aws-vault", "aws"),
                                            ("/private/tmp/docker", "docker"), ("/private/tmp/bun", "npm"), ("/private/tmp/uv", "pypi"),
                                            ("/private/tmp/codex", "codex-sessions"), ("/private/tmp/opencode", "opencode-data"),
                                            ("/private/tmp/cursor-agent", "cursor-data"),
                                            ("/Users/alice/x/.local/share/claude/versions/1.0", "claude-sessions"),
                                            ("/Users/alice/x/Caskroom/claude-code/1.0/claude", "claude-sessions")]
        for (path, category) in impostors {
            XCTAssertFalse(h.classifier.isOwner(proc(2, path), of: category), "\(path) → \(category)")
        }
        XCTAssertTrue(h.classifier.isOwner(proc(3, "/opt/homebrew/Cellar/gh/2.50.0/bin/gh"), of: "gh"))
        // Names narrow a located spec.
        let spec = IdentitySpec(executables: ["/usr/local/bin/*"], names: ["gh"])
        XCTAssertTrue(spec.matches(proc(4, "/usr/local/bin/gh")))
        XCTAssertFalse(spec.matches(proc(5, "/usr/local/bin/cat")))
        // Data-wide: no owner location is unanchored ("**/x" or "*/x" match under any directory).
        for c in h.data.catalog.categories {
            for o in c.owners {
                for g in (o.executables ?? []) + (o.bundles ?? []) {
                    XCTAssertTrue(g.pattern.hasPrefix("/"), "\(c.id): \(o.label ?? "?") has unanchored \(g.pattern)")
                }
                let pins = !(o.executables ?? []).isEmpty || !(o.bundles ?? []).isEmpty || !(o.signingIDs ?? []).isEmpty
                    || !(o.teamIDs ?? []).isEmpty || !(o.cdhashes ?? []).isEmpty
                XCTAssertTrue(pins, "\(c.id): \(o.label ?? "?") pins neither a location nor an identity")
            }
        }
    }

    // paths-3
    func testPlatformBinaryOwnersOnlyInRootOwnedLocations() throws {
        let h = try Harness()
        let fakeKeychainAccess = proc(1, "/Users/alice/x/Keychain Access.app/Contents/MacOS/cp", platform: true)
        XCTAssertFalse(h.classifier.isOwner(fakeKeychainAccess, of: "keychain"))
        let realKeychainAccess = proc(2, "/System/Applications/Utilities/Keychain Access.app/Contents/MacOS/Keychain Access", platform: true)
        XCTAssertTrue(h.classifier.isOwner(realKeychainAccess, of: "keychain"))
        XCTAssertFalse(h.classifier.isOwner(proc(3, "/usr/local/bin/ssh", platform: true), of: "ssh"), "/usr/local is user-owned on Intel")
        XCTAssertTrue(h.classifier.isOwner(proc(4, "/usr/bin/ssh", platform: true), of: "ssh"))
        XCTAssertFalse(h.classifier.isOwner(proc(5, "/Users/alice/x/Finder.app/Contents/MacOS/Finder", platform: true), of: "iphone-backup"))
        XCTAssertFalse(h.classifier.isOwner(proc(6, "/Applications/XcodeX.app/Contents/Developer/usr/bin/git", platform: true),
                                            of: "git-credentials"))
        XCTAssertTrue(h.classifier.isOwner(proc(7, "/Library/Developer/CommandLineTools/usr/bin/git", platform: true), of: "git-credentials"))
        // Spec level: outside root-owned places only a pinned signing ID makes "platform binary" mean something.
        let loose = IdentitySpec(executables: ["/Applications/Xcode.app/**/git"], platformBinary: true)
        let xcodeGit = proc(8, "/Applications/Xcode.app/Contents/Developer/usr/bin/git", platform: true, signingID: "com.apple.git")
        XCTAssertFalse(loose.matches(xcodeGit))
        let pinned = IdentitySpec(executables: ["/Applications/Xcode.app/**/git"], signingIDs: ["com.apple.git"], platformBinary: true)
        XCTAssertTrue(pinned.matches(xcodeGit))
    }

    // paths-4
    func testUnresolvedThirdPartyBundlesMatchNothing() throws {
        let h = try Harness()
        let canary = proc(1, "/Applications/Google Chrome Canary.app/Contents/MacOS/x")
        let chrome = proc(2, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", teamID: "EQHXZ8M8AV")
        XCTAssertFalse(h.classifier.isOwner(canary, of: "chrome"))
        XCTAssertFalse(h.classifier.isOwner(chrome, of: "chrome"), "fails closed until the team ID is resolved on this Mac")
        // Resolved (what OwnerResolver does at daemon start): the team pins the whole OR-list.
        var catalog = h.data.catalog
        let i = catalog.categories.firstIndex { $0.id == "chrome" }!
        catalog.categories[i].owners[0].teamIDs = ["EQHXZ8M8AV"]
        let resolved = PathClassifier(catalog: catalog, normalizer: h.normalizer)
        XCTAssertTrue(resolved.isOwner(chrome, of: "chrome"))
        XCTAssertFalse(resolved.isOwner(canary, of: "chrome"), "a fake sibling bundle has no Google team")
        XCTAssertFalse(resolved.isOwner(proc(3, "/Applications/Google Chrome Canary.app/Contents/MacOS/x", teamID: "EVILTEAM"), of: "chrome"))
        // /System bundles need no team (Terminal is a platform binary in a SIP location).
        XCTAssertTrue(h.classifier.isOwner(P.terminal, of: "shell-history"))
    }

    // paths-5
    func testShellsCurlAndGitAreNotOwners() throws {
        let h = try Harness()
        XCTAssertFalse(h.classifier.isOwner(P.zsh(1, parent: 100), of: "shell-history"))
        XCTAssertFalse(h.classifier.isOwner(proc(2, "/bin/bash", platform: true), of: "shell-history"))
        XCTAssertFalse(h.classifier.isOwner(proc(3, "/usr/bin/curl", platform: true), of: "netrc"))
        XCTAssertFalse(h.classifier.isOwner(proc(4, "/usr/bin/git", platform: true), of: "ssh"))
        XCTAssertFalse(h.classifier.isOwner(proc(5, "/Library/Developer/CommandLineTools/usr/bin/git", platform: true), of: "ssh"))
        XCTAssertTrue(h.classifier.isOwner(proc(6, "/usr/libexec/git-core/git-remote-https", platform: true), of: "netrc"))
        XCTAssertTrue(h.classifier.isOwner(proc(7, "/usr/bin/git", platform: true), of: "git-credentials"))
        // The agent template does not exempt owners (brief: deny > allow > owner).
        guard case .agentAncestor(_, let exceptOwners) = RuleTemplates.blockAgentsFromCritical().subject else { return XCTFail() }
        XCTAssertFalse(exceptOwners)
        // An agent printing a key through git is a critical non-owner read.
        let git = claudeShell(h, proc(700, "/usr/bin/git", ppid: 600, platform: true,
                                     argv: ["git", "diff", "--no-index", "/dev/null", sshKey]))
        let out = h.open(git, sshKey, 5)
        XCTAssertEqual(out.events.first?.isOwner, false)
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
        // And the template blocks it in Enforce mode, even through /usr/bin/ssh (an owner).
        let rules = try Harness(rules: [enforced(RuleTemplates.blockAgentsFromCritical())])
        let ssh = claudeShell(rules, proc(701, "/usr/bin/ssh", ppid: 600, platform: true))
        XCTAssertEqual(authDecision(rules, activity(.open, ssh, readTargets(sshKey))).verdict, .deny)
    }

    // paths-11
    func testAgentSessionStoresAreSeparateCategories() throws {
        let h = try Harness(learningDays: 1)
        XCTAssertNil(h.data.catalog.category("ai-sessions"))
        for id in ["claude-sessions", "codex-sessions", "gemini-sessions", "cursor-data", "opencode-data"] {
            XCTAssertEqual(h.data.catalog.category(id)?.group, "ai", id)
        }
        let claude = P.node(600, parent: 1, argv: ["node", "/opt/homebrew/bin/claude"])
        XCTAssertTrue(h.classifier.isOwner(claude, of: "claude-sessions"))
        XCTAssertFalse(h.classifier.isOwner(claude, of: "codex-sessions"))
        let rollout = "/Users/alice/.codex/sessions/2025/01/02/rollout-1.jsonl"
        XCTAssertEqual(h.classifier.classify(rollout)?.categoryID, "codex-sessions")
        // After learning, Claude Code reading Codex's transcripts is news.
        let t = 2 * 86400.0
        let reader = h.spawn(P.terminal, P.node(610, parent: 100, argv: ["node", "/opt/homebrew/bin/claude"]), t)
        let out = h.open(reader, rollout, t + 1)
        XCTAssertEqual(out.events.first?.isOwner, false)
        XCTAssertEqual(out.alerts.first?.alert.kind, .firstAccess)
    }
}

// MARK: - Rules (rules-*)

final class RuleRound1Tests: XCTestCase {
    // rules-2
    func testDirectoryMovesAreJudgedByTheWorstFileInside() throws {
        let h = try Harness(rules: [enforced(RuleTemplates.blockAgentsFromCritical())])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        func rename(_ src: String, dir: Bool?) -> FileActivity {
            activity(.rename, mv, OperationSemantics.rename(ReportedPath(src, isDirectory: dir), ReportedPath("/private/tmp/p")))
        }
        let profile = authDecision(h, rename(chromeProfile, dir: true))
        XCTAssertEqual(profile.verdict, .deny, "the profile holds Cookies / Login Data")
        XCTAssertEqual(authDecision(h, rename(chromeProfile, dir: nil)).verdict, .deny, "unknown file type: assume a directory")
        let google = authDecision(h, rename("/Users/alice/Library/Application Support/Google", dir: true))
        XCTAssertEqual(google.verdict, .deny, "an ancestor carries the critical files below it")
        XCTAssertEqual(authDecision(h, rename(chromeProfile + "/Preferences", dir: false)).verdict, .allow,
                       "a single medium file is not over-blocked")
        // Clone of the profile directory.
        let clone = activity(.clone, mv, OperationSemantics.clone(ReportedPath(chromeProfile, isDirectory: true), ReportedPath("/private/tmp/p")))
        XCTAssertEqual(authDecision(h, clone).verdict, .deny)
        // The high-severity alert template sees the move too.
        let alerts = try Harness(rules: [{ var r = RuleTemplates.alertAgentsOnHigh(); r.enabled = true; return r }()])
        let mv2 = claudeShell(alerts, proc(700, "/bin/mv", ppid: 600, platform: true))
        let d = authDecision(alerts, activity(.rename, mv2, OperationSemantics.rename(ReportedPath(chromeProfile, isDirectory: true),
                                                                                       ReportedPath("/private/tmp/p"))))
        XCTAssertEqual(d.reason, .alertRule)
    }

    // rules-3
    func testUnsignedDenyFollowsThePinnedCdhashAnywhere() throws {
        let rule = Rule(id: "deny-tool", enabled: true, enforce: true, target: .category("ssh"),
                        subject: .unsigned(path: "/Users/alice/bin/tool", cdhash: "ABCD"), access: .any, action: .deny)
        let h = try Harness(rules: [rule])
        func tool(_ path: String, _ cdhash: String?) -> ProcessRecord {
            var p = proc(800, path)
            p.cdhash = cdhash
            return p
        }
        XCTAssertEqual(authDecision(h, activity(.open, tool("/Users/alice/bin/tool", "abcd"), readTargets(sshKey))).verdict, .deny)
        XCTAssertEqual(authDecision(h, activity(.open, tool("/Users/alice/bin/tool2", "abcd"), readTargets(sshKey))).verdict, .deny,
                       "same code at another path")
        XCTAssertEqual(authDecision(h, activity(.open, tool("/Users/alice/bin/tool", "ffff"), readTargets(sshKey))).verdict, .allow,
                       "different code at the pinned path")
        // Path-only subjects stay path-only.
        let pathOnly = try Harness(rules: [Rule(id: "p", enabled: true, enforce: true, target: .category("ssh"),
                                                subject: .unsigned(path: "/Users/alice/bin/tool", cdhash: nil), action: .deny)])
        XCTAssertEqual(authDecision(pathOnly, activity(.open, tool("/Users/alice/bin/tool", "abcd"), readTargets(sshKey))).verdict, .deny)
        XCTAssertEqual(authDecision(pathOnly, activity(.open, tool("/Users/alice/bin/tool2", "abcd"), readTargets(sshKey))).verdict, .allow)
        // Exceptions are not widened: a copy of an excepted binary is still denied.
        var broad = Rule(id: "b", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny,
                         includePlatformBinaries: true)
        broad.exceptions = [RuleException(subject: .unsigned(path: "/Users/alice/bin/tool", cdhash: "abcd"))]
        let ex = try Harness(rules: [broad])
        XCTAssertEqual(authDecision(ex, activity(.open, tool("/Users/alice/bin/tool", "abcd"), readTargets(sshKey))).verdict, .allow)
        XCTAssertEqual(authDecision(ex, activity(.open, tool("/Users/alice/bin/tool2", "abcd"), readTargets(sshKey))).verdict, .deny)
    }

    // rules-4
    func testAlwaysAllowForAnAppIsNoTunnelForAnotherAgent() throws {
        var rule = enforced(RuleTemplates.blockAgentsFromCritical())
        rule.exceptions = [RuleException(subject: .responsible(key: "agent:cursor", teamID: "CURSORTEAM"), categoryID: "aws",
                                         chainAgents: ["cursor"])]
        let h = try Harness(rules: [rule])
        let creds = "/Users/alice/.aws/credentials"
        let rgPath = "/Applications/Cursor.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg"
        // Cursor's own rg: covered by the exception.
        let cursor = h.spawn(P.launchd, proc(300, "/Applications/Cursor.app/Contents/MacOS/Cursor", ppid: 1, teamID: "CURSORTEAM"))
        let rg = h.spawn(cursor, proc(301, rgPath, ppid: 300, teamID: "CURSORTEAM", argv: ["rg", "x", creds]), 1)
        XCTAssertEqual(authDecision(h, activity(.open, rg, readTargets(creds))).verdict, .allow)
        // Claude Code running Cursor's signed rg: the chain has an agent the user never approved.
        let tunnel = claudeShell(h, proc(701, rgPath, ppid: 600, teamID: "CURSORTEAM", argv: ["rg", "x", creds]))
        XCTAssertEqual(h.attributor.attribute(chain: h.tree.chain(for: tunnel, at: at(10))).key, "agent:cursor",
                       "attribution alone would have matched the exception")
        XCTAssertEqual(authDecision(h, activity(.open, tunnel, readTargets(creds))).verdict, .deny)
        XCTAssertTrue(rule.hasChainDependentExceptions, "scoped exceptions make decisions chain-dependent (no caching)")
    }

    // rules-5
    func testExceptionsCoverOnlyTheApprovedAccessKind() throws {
        var rule = Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                        access: .any, action: .deny, includePlatformBinaries: true)
        rule.exceptions = [RuleException(subject: .responsible(key: terminalKey, teamID: nil), categoryID: "ssh", access: .read,
                                         remainingUses: 1)]
        let h = try Harness(rules: [rule])
        let cat = terminalShell(h, P.cat(501, parent: 500))
        func uses() -> Int? { h.rules.rules[0].exceptions[0].remainingUses }
        // A write arrives first: not covered, denied, and the use is not spent.
        let truncate = authDecision(h, activity(.truncate, cat, OperationSemantics.truncate(path: sshKey)))
        XCTAssertEqual(truncate.verdict, .deny)
        XCTAssertEqual(uses(), 1)
        let rw = authDecision(h, activity(.open, cat, OperationSemantics.open(path: sshKey, fflag: 3)))
        XCTAssertEqual(rw.verdict, .deny, "O_RDWR needs more than a read approval")
        XCTAssertEqual(uses(), 1)
        // The approved read goes through once; the write bit stays denied for AUTH_OPEN flags.
        let read = authDecision(h, activity(.open, cat, readTargets(sshKey)))
        XCTAssertEqual(read.verdict, .allow)
        // The write bit stays denied, so the native source does not cache this allow.
        XCTAssertTrue(read.policyDenied.contains(.write))
        XCTAssertFalse(read.policyDenied.contains(.read))
        XCTAssertEqual(uses(), 0)
        XCTAssertEqual(authDecision(h, activity(.open, cat, readTargets(sshKey))).verdict, .deny)
    }

    // analysis-15
    func testReplacingTheClassifierKeepsLiveRuleState() throws {
        var rule = Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                        action: .deny, includePlatformBinaries: true)
        rule.exceptions = [RuleException(subject: .responsible(key: terminalKey, teamID: nil), remainingUses: 1)]
        let h = try Harness(rules: [rule])
        let cat = terminalShell(h, P.cat(501, parent: 500))
        XCTAssertEqual(authDecision(h, activity(.open, cat, readTargets(sshKey))).verdict, .allow)
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 0)
        // A rule added meanwhile (another IPC thread).
        h.rules.mutate { $0.append(Rule(id: "path-rule", enabled: true, enforce: true, target: .pathPrefix("~/vault"),
                                        subject: .anyNonOwner, action: .deny, includePlatformBinaries: true)) }
        // A settings change recompiles the classifier with another home.
        let n2 = PathNormalizer(homeDirectories: [home, "/Users/bob"])
        h.analyzer.replace(classifier: PathClassifier(catalog: h.data.catalog, normalizer: n2))
        XCTAssertEqual(h.rules.rules.map(\.id), ["deny-ssh", "path-rule"], "the concurrent rule survives")
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 0, "a used allow-once is not restored")
        XCTAssertEqual(authDecision(h, activity(.open, cat, readTargets(sshKey))).verdict, .deny)
        // Recompiled against the new normalizer: ~/vault now also means /Users/bob/vault.
        let bobTarget = EvaluationTarget(path: "/Users/bob/vault/x", access: .read, categories: [TargetCategory(id: "custom", severity: .high)])
        let d = h.rules.evaluate(process: P.cat(9, parent: 1), chain: [], targets: [bobTarget], enforcementActive: true, now: at(20))
        XCTAssertEqual(d.ruleID, "path-rule")

        // Concurrently: settings changes recompiling while IPC threads add rules lose nothing.
        let engine = RuleEngine(rules: [], classifier: h.classifier)
        let analyzer = Analyzer(classifier: h.classifier, tree: h.tree, attributor: h.attributor,
                                benign: BenignClassifier(catalog: h.data.benign), rules: engine, baseline: h.baseline,
                                coalescer: AlertCoalescer())
        let other = PathClassifier(catalog: h.data.catalog, normalizer: n2)
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            for i in 0..<1500 {
                engine.mutate { $0.append(Rule(id: "r\(i)", target: .category("ssh"), subject: .anyNonOwner, action: .alert)) }
            }
            done.signal()
        }
        var flips = 0
        while done.wait(timeout: .now()) == .timedOut {
            analyzer.replace(classifier: flips % 2 == 0 ? other : h.classifier)
            flips += 1
            // Darwin's locks are not fair: a loop that re-locks at once can starve the other
            // thread for minutes. A short pause keeps the two interleaved, which is what this
            // test is about (settings changes are rare in practice).
            usleep(50)
        }
        XCTAssertEqual(engine.rules.count, 1500, "after \(flips) recompiles")
    }
}

// MARK: - Process tree and attribution (process-1)

final class ProcessTreeRound1Tests: XCTestCase {
    // process-1 [1] + Analyzer stored chain cap.
    func testDeepChainsKeepTheAgentAtTheTop() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var parent = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]))
        for i in 0..<70 {
            parent = h.spawn(parent, proc(Int32(1000 + i), "/bin/bash", ppid: parent.pid, platform: true))
        }
        let cat = h.spawn(parent, P.cat(2000, parent: parent.pid))
        let chain = h.tree.chain(for: cat, at: at(1))
        XCTAssertEqual(chain.count, 75, "cat + 70 bash + node + zsh + Terminal + launchd")
        XCTAssertEqual(chain.nearestAgent, "claude-code")

        let out = h.open(cat, sshKey, 2)
        let e = try XCTUnwrap(out.events.first)
        XCTAssertEqual(e.chain.count, 64, "stored chain is capped")
        XCTAssertEqual(e.chain.last?.name, "cat", "the nearest links are kept, root first")
        XCTAssertEqual(e.chain.first?.name, "bash")
        XCTAssertEqual(e.agentID, "claude-code", "agentID uses the full chain")
        XCTAssertEqual(e.responsible.key, "agent:claude-code")
        XCTAssertEqual(out.alerts.first?.alert.chain.count, 64)
    }

    // process-1 [2]
    func testPruningALongExitedChainIsLinear() throws {
        let data = try defaultData()
        let tree = ProcessTree(detector: AgentDetector(catalog: data.agents), tombstoneTTL: 10)
        let depth = 4000
        var records: [ProcessRecord] = []
        var parent = proc(2, "/bin/sh", ppid: 1, platform: true)
        tree.observe(parent, at: t0)
        records.append(parent)
        for i in 0..<depth - 1 {
            let child = proc(Int32(10 + i), "/bin/sh", ppid: parent.pid, platform: true)
            tree.fork(parent: parent, child: child, at: t0)
            records.append(child)
            parent = child
        }
        for r in records { tree.exit(r, at: at(1)) }
        let before = tree.count
        let start = Date()
        let removed = tree.prune(now: at(100))
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(removed, depth)
        XCTAssertEqual(tree.count, before - depth)
        XCTAssertLessThan(elapsed, 1.0, "prune holds the lock the AUTH path needs")
        print("pruned a \(depth)-deep exited chain in \(String(format: "%.3f", elapsed)) s")
    }

    // process-1 [3]
    func testCapEvictionKeepsExitedAgentsWithChildrenAndSplicesAncestors() throws {
        let data = try defaultData()
        let detector = AgentDetector(catalog: data.agents)
        func build(maxNodes: Int, flood: Int) -> (ProcessTree, ProcessRecord) {
            let tree = ProcessTree(detector: detector, maxNodes: maxNodes)
            let terminal = P.terminal
            tree.observe(terminal, at: t0)
            let zsh = P.zsh(101, parent: 100)
            tree.fork(parent: terminal, child: zsh, at: t0)
            var claudeFork = zsh
            claudeFork.pid = 102
            claudeFork.ppid = 101
            tree.fork(parent: zsh, child: claudeFork, at: t0)
            let claude = P.node(102, parent: 101, argv: ["node", "/opt/homebrew/bin/claude"])
            tree.exec(old: claudeFork, new: claude, at: t0)
            let bash1 = proc(103, "/bin/bash", ppid: 102, platform: true)
            tree.fork(parent: claude, child: bash1, at: t0)
            let bash2 = proc(104, "/bin/bash", ppid: 103, platform: true)
            tree.fork(parent: bash1, child: bash2, at: t0)
            let cat = P.cat(105, parent: 104)
            tree.fork(parent: bash2, child: cat, at: t0)
            // The agent and the shells exit; cat (a background job) lives on.
            for r in [claude, bash1, bash2] { tree.exit(r, at: at(1)) }
            for i in 0..<flood {
                let p = proc(Int32(5000 + i), "/usr/bin/true", ppid: 101, platform: true)
                tree.fork(parent: zsh, child: p, at: at(2))
                tree.exit(p, at: at(2 + Double(i) * 0.001))
            }
            return (tree, cat)
        }
        // Flood of short-lived processes: only childless tombstones go.
        let (flooded, cat) = build(maxNodes: 50, flood: 100)
        flooded.prune(now: at(5))
        XCTAssertLessThanOrEqual(flooded.count, 50)
        let chain = flooded.chain(for: cat, at: at(6))
        XCTAssertEqual(chain.displayString(), "launchd → Terminal → zsh → node → bash → bash → cat")
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        // Forced splice: exited shells are removed, their children re-linked; the exited agent stays.
        let (tight, cat2) = build(maxNodes: 5, flood: 0)
        tight.prune(now: at(5))
        let spliced = tight.chain(for: cat2, at: at(6))
        XCTAssertEqual(spliced.displayString(), "launchd → Terminal → zsh → node → cat")
        XCTAssertEqual(spliced.nearestAgent, "claude-code")
    }

    // process-1 [4]
    func testXcodeToolchainIsNotTheResponsibleApp() throws {
        XCTAssertEqual(BundlePath.attributableAppBundles(in: "/Applications/Xcode.app/Contents/Developer/usr/bin/git"), [])
        XCTAssertNil(BundlePath.outermostApp(in: "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"))
        XCTAssertEqual(BundlePath.outermostApp(in: "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator"),
                       "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app")
        XCTAssertEqual(BundlePath.outermostApp(in: "/Applications/Xcode.app/Contents/MacOS/Xcode"), "/Applications/Xcode.app")
        XCTAssertEqual(BundlePath.outermostApp(in: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"),
                       "/Applications/Google Chrome.app")
        // Claude Code → zsh → Xcode's python3 is charged to Claude Code, not to "Xcode".
        let h = try Harness()
        let py = claudeShell(h, proc(700, "/Applications/Xcode.app/Contents/Developer/usr/bin/python3", ppid: 600, platform: true))
        XCTAssertEqual(h.attributor.attribute(chain: h.tree.chain(for: py, at: at(1))).key, "agent:claude-code")
    }
}

// MARK: - Analyzer (analysis-*, spec-9)

final class AnalyzerRound1Tests: XCTestCase {
    // analysis-1
    func testMovingAParentCarriesEveryCategoryBelow() throws {
        let deny = Rule(id: "deny-gh", enabled: true, enforce: true, target: .category("gh"), subject: .anyNonOwner,
                        action: .deny, includePlatformBinaries: true)
        let h = try Harness(rules: [deny])
        let mv = claudeShell(h, proc(700, "/bin/mv", ppid: 600, platform: true))
        let move = activity(.rename, mv, OperationSemantics.rename(source: "/Users/alice/.config", destination: "/Users/alice/.config.bak"))
        let classified = h.analyzer.classify(move)
        XCTAssertEqual(Set(classified[0].categories.map(\.id)), ["gcloud", "gh", "git-credentials"])
        let d = authDecision(h, move)
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "deny-gh")
        let out = h.analyzer.handle(.file(move))
        XCTAssertEqual(Set(out.events.map(\.categoryID)), ["gcloud", "gh", "git-credentials"])
        XCTAssertTrue(out.events.allSatisfy(\.viaAncestor))
    }

    // analysis-2
    func testRulesAreEvaluatedPerCategory() throws {
        let allow = Rule(id: "allow-terminal-volumes", enabled: true, target: .category("volumes"),
                         subject: .responsible(key: terminalKey, teamID: nil), action: .allow)
        let h = try Harness(rules: [allow])
        let cp = terminalShell(h, proc(501, "/bin/cp", ppid: 500, platform: true))
        let out = h.file(.clone, cp, OperationSemantics.clone(source: sshKey, destination: "/Volumes/USB/id_ed25519"), 5)
        let ssh = try XCTUnwrap(out.events.first { $0.categoryID == "ssh" })
        let usb = try XCTUnwrap(out.events.first { $0.categoryID == "volumes" })
        XCTAssertNil(ssh.ruleID, "the volumes allow does not silence the key copy")
        XCTAssertEqual(usb.ruleID, "allow-terminal-volumes")
        XCTAssertEqual(out.alerts.map(\.alert.categoryID), ["ssh"])
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)

        // The reverse: a dry-run deny on ssh does not turn the volumes event into "would block".
        let dry = Rule(id: "dry-ssh", enabled: true, enforce: false, target: .category("ssh"), subject: .anyNonOwner,
                       action: .deny, includePlatformBinaries: true)
        let h2 = try Harness(rules: [dry])
        let cp2 = terminalShell(h2, proc(501, "/bin/cp", ppid: 500, platform: true))
        let out2 = h2.file(.clone, cp2, OperationSemantics.clone(source: sshKey, destination: "/Volumes/USB/id_ed25519"), 5)
        XCTAssertEqual(out2.events.first { $0.categoryID == "ssh" }?.decision, .wouldDeny)
        XCTAssertEqual(out2.events.first { $0.categoryID == "volumes" }?.decision, .observed)
        XCTAssertNil(out2.events.first { $0.categoryID == "volumes" }?.ruleID)
        XCTAssertEqual(out2.alerts.first { $0.alert.categoryID == "ssh" }?.alert.kind, .wouldBlock)
        XCTAssertNotEqual(out2.alerts.first { $0.alert.categoryID == "volumes" }?.alert.kind, .wouldBlock)
    }

    // analysis-2, for a denied operation: every category is a denial, only the denied one is "blocked by" a rule.
    func testDeniedMultiCategoryOperationChargesOnlyTheDeniedCategory() throws {
        let denySSH = Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                           action: .deny, includePlatformBinaries: true)
        let h = try Harness(rules: [denySSH])
        let cp = terminalShell(h, proc(501, "/bin/cp", ppid: 500, platform: true))
        let clone = activity(.clone, cp, OperationSemantics.clone(source: sshKey, destination: "/Volumes/USB/id_ed25519"), 5)
        let d = authDecision(h, clone)
        XCTAssertEqual(d.verdict, .deny)
        let out = h.analyzer.handle(.file(clone), context: .decided(d))
        XCTAssertEqual(out.events.map(\.decision), [.denied, .denied], "nothing was written to the stick either")
        XCTAssertEqual(out.events.first { $0.categoryID == "ssh" }?.ruleID, "deny-ssh")
        XCTAssertNil(out.events.first { $0.categoryID == "volumes" }?.ruleID)
        XCTAssertEqual(out.alerts.map(\.alert.categoryID), ["ssh"], "one blocked alert, about the key")
        XCTAssertEqual(out.alerts.first?.alert.kind, .blocked)
        // Each category denied by its own rule keeps its own rule.
        let denyUSB = Rule(id: "deny-usb", enabled: true, enforce: true, target: .category("volumes"), subject: .anyNonOwner,
                           action: .deny, includePlatformBinaries: true)
        let h2 = try Harness(rules: [denySSH, denyUSB])
        let cp2 = terminalShell(h2, proc(501, "/bin/cp", ppid: 500, platform: true))
        let clone2 = activity(.clone, cp2, OperationSemantics.clone(source: sshKey, destination: "/Volumes/USB/id_ed25519"), 5)
        let out2 = h2.analyzer.handle(.file(clone2), context: .decided(authDecision(h2, clone2)))
        XCTAssertEqual(out2.events.first { $0.categoryID == "volumes" }?.ruleID, "deny-usb")
        XCTAssertEqual(Set(out2.alerts.map(\.alert.categoryID)), ["ssh", "volumes"])
        // A denial no current rule explains (rules changed since AUTH) keeps the AUTH decision everywhere.
        let h3 = try Harness()
        let cp3 = terminalShell(h3, proc(501, "/bin/cp", ppid: 500, platform: true))
        let clone3 = activity(.clone, cp3, OperationSemantics.clone(source: sshKey, destination: "/Volumes/USB/id_ed25519"), 5)
        let out3 = h3.analyzer.handle(.file(clone3), context: .decided(d))
        XCTAssertEqual(out3.events.map(\.ruleID), ["deny-ssh", "deny-ssh"])
        XCTAssertEqual(out3.alerts.count, 2)
    }

    // analysis-3
    func testBlockedAttemptsAndSuccessfulAccessesAreSeparateAlerts() throws {
        let h = try Harness(learningDays: 1)
        let t = 2 * 86400.0
        let cat = terminalShell(h, P.cat(501, parent: 500), t: t)
        let first = h.open(cat, "/Users/alice/.ssh/known_hosts", t + 1)
        let open = try XCTUnwrap(first.alerts.first)
        XCTAssertEqual(open.alert.kind, .firstAccess)
        let denied = RuleDecision(verdict: .deny, reason: .explicitDeny, ruleID: "r", forceAlert: true)
        let blocked = try XCTUnwrap(h.open(cat, sshKey, t + 2, context: .decided(denied)).alerts.first)
        XCTAssertEqual(blocked.change, .created, "not an escalation of the alert about a read that went through")
        XCTAssertNotEqual(blocked.alert.id, open.alert.id)
        XCTAssertEqual(blocked.alert.kind, .blocked)
        XCTAssertEqual(blocked.alert.count, 1)
        // Later reads that went through (allow once, kill switch) count on the other alert.
        for i in 0..<4 { _ = h.open(cat, sshKey, t + 3 + Double(i)) }
        let again = try XCTUnwrap(h.open(cat, sshKey, t + 10, context: .decided(denied)).alerts.first)
        XCTAssertEqual(again.alert.id, blocked.alert.id)
        XCTAssertEqual(again.alert.count, 2, "\"blocked ×N\" counts only blocked attempts")
        let zh = AlertFormatter(language: .zhHans, abbreviate: { [n = h.normalizer] in n.abbreviate($0) })
        XCTAssertEqual(zh.headline(again.alert), "已拦截：Terminal 试图读取 ~/.ssh/id_ed25519（2 次）")
    }

    // analysis-4 (and the coalescer side of policy-7)
    func testEscalationMovesTheHeadlineToTheTriggeringPath() {
        let c = AlertCoalescer(window: 600)
        func event(_ id: Int64, _ path: String, _ severity: Severity, decision: EventDecision = .observed) -> AnalyzedEvent {
            AnalyzedEvent(id: id, time: at(Double(id)), operation: .open, access: .read, path: path, secondaryPath: nil,
                          categoryID: "ssh", severity: severity, process: proc(1, "/x"), chain: [],
                          responsible: ResponsibleEntity(kind: .app, key: terminalKey, displayName: "Terminal"),
                          agentID: id == 2 ? "claude-code" : nil, isOwner: false, benignServiceID: nil, decision: decision, ruleID: nil)
        }
        let first = c.ingest(event(1, "/Users/alice/.ssh/known_hosts", .medium), kind: .firstAccess)!
        let up = c.ingest(event(2, sshKey, .critical), kind: .criticalNonOwner)!
        XCTAssertEqual(up.change, .escalated)
        XCTAssertEqual(up.alert.id, first.alert.id)
        XCTAssertEqual(up.alert.firstPath, sshKey)
        XCTAssertEqual(up.alert.firstEventID, 2)
        XCTAssertEqual(up.alert.paths.first, sshKey)
        XCTAssertEqual(up.alert.agentID, "claude-code")
        XCTAssertEqual(AlertFormatter(language: .en).headline(up.alert),
                       "Terminal read \(sshKey) (ssh, not an expected owner) (×2)")
        // Paths stay capped and the trigger is always listed.
        let capped = AlertCoalescer(window: 600, maxPaths: 2)
        _ = capped.ingest(event(1, "/Users/alice/.ssh/a", .medium), kind: .firstAccess)
        _ = capped.ingest(event(3, "/Users/alice/.ssh/b", .medium), kind: nil)
        let esc = capped.ingest(event(4, sshKey, .critical), kind: .criticalNonOwner)!
        XCTAssertEqual(esc.alert.paths, [sshKey, "/Users/alice/.ssh/a"])
    }

    // analysis-5
    func testDirectoryOpensAreListingsAndOffByDefault() throws {
        XCTAssertEqual(OperationSemantics.open(ReportedPath("/Users/alice/.ssh", isDirectory: true), fflag: 1).0, .readdir)
        XCTAssertEqual(OperationSemantics.open(ReportedPath("/Users/alice/.ssh"), fflag: 0x0110_0001).0, .readdir,
                       "eslogger's sample fflag FREAD|O_DIRECTORY|O_CLOEXEC")
        XCTAssertEqual(OperationSemantics.open(ReportedPath(sshKey, isDirectory: false), fflag: 0x0010_0001).0, .open,
                       "stat wins over the flag")
        XCTAssertEqual(OperationSemantics.open(ReportedPath(sshKey), fflag: 1).0, .open)
        XCTAssertTrue(OperationSemantics.isDirectory(mode: 0o040755))
        XCTAssertFalse(OperationSemantics.isDirectory(mode: 0o100644))
        XCTAssertFalse(OperationSemantics.isDirectory(mode: 0o120755))

        let h = try Harness()
        let find = terminalShell(h, proc(501, "/usr/bin/find", ppid: 500, platform: true))
        let (op, targets) = OperationSemantics.open(ReportedPath("/Users/alice/.ssh", isDirectory: true), fflag: 0x0110_0001)
        XCTAssertTrue(h.file(op, find, targets, 5).events.isEmpty, "ls ~/.ssh is not a read of the keys")
        XCTAssertTrue(h.file(op, find, targets, 5).alerts.isEmpty)
        h.analyzer.readdirEnabled = true
        let listed = h.file(op, find, targets, 6)
        XCTAssertEqual(listed.events.first?.operation, .readdir)
        XCTAssertEqual(listed.events.first?.categoryID, "ssh")
    }

    // analysis-6
    func testAlertVerbsAndANewAccessKindNotifiesAgain() throws {
        func alert(_ kind: AlertKind, _ access: AccessSet, count: Int = 1, firstTime: Bool = false) -> Alert {
            Alert(id: 1, kind: kind, createdAt: t0, updatedAt: t0, windowEndsAt: at(600),
                  responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "Zoom"),
                  categoryID: "ssh", severity: .critical, count: count, accesses: access, firstPath: sshKey,
                  firstEventID: 1, lastEventID: 1, paths: [sshKey], chain: [], agentID: nil, ruleID: nil, firstTime: firstTime)
        }
        let n = PathNormalizer(homeDirectories: [home])
        let zh = AlertFormatter(language: .zhHans, abbreviate: { n.abbreviate($0) }, categoryName: { _ in LocalizedText(en: "SSH keys", zhHans: "SSH 密钥") })
        let en = AlertFormatter(language: .en, abbreviate: { n.abbreviate($0) }, categoryName: { _ in LocalizedText(en: "SSH keys", zhHans: "SSH 密钥") })
        let p = "~/.ssh/id_ed25519"
        XCTAssertEqual(zh.headline(alert(.firstAccess, .read)), "Zoom 第一次读取了 \(p)")
        XCTAssertEqual(zh.headline(alert(.firstAccess, .write)), "Zoom 第一次写入了 \(p)")
        XCTAssertEqual(zh.headline(alert(.firstAccess, .readWrite)), "Zoom 第一次读写了 \(p)")
        XCTAssertEqual(en.headline(alert(.firstAccess, .read)), "Zoom read \(p) for the first time")
        XCTAssertEqual(en.headline(alert(.firstAccess, .write)), "Zoom wrote \(p) for the first time")
        XCTAssertEqual(en.headline(alert(.firstAccess, .readWrite)), "Zoom read and modified \(p) for the first time")
        XCTAssertEqual(zh.headline(alert(.criticalNonOwner, .write)), "Zoom 写入了 \(p)（SSH 密钥，不是预期的访问者）")
        XCTAssertEqual(en.headline(alert(.criticalNonOwner, .readWrite, count: 2)), "Zoom read and modified \(p) (SSH keys, not an expected owner) (×2)")
        XCTAssertEqual(zh.headline(alert(.ruleAlert, .readWrite)), "Zoom 读写了 \(p)（规则提醒）")
        XCTAssertEqual(en.headline(alert(.ruleAlert, .write)), "Zoom wrote \(p) (rule alert)")
        XCTAssertEqual(zh.headline(alert(.wouldBlock, .write)), "规则将会拦截：Zoom 写入 \(p)（当前为监控模式）")
        XCTAssertEqual(en.headline(alert(.wouldBlock, .readWrite)), "A rule would block Zoom from reading and modifying \(p) (monitor mode)")
        XCTAssertEqual(en.headline(alert(.wouldBlock, .write)), "A rule would block Zoom from writing \(p) (monitor mode)")
        XCTAssertEqual(zh.headline(alert(.blocked, .readWrite)), "已拦截：Zoom 试图读写 \(p)")
        XCTAssertEqual(en.headline(alert(.blocked, .readWrite)), "Blocked: Zoom tried to read and modify \(p)")
        XCTAssertEqual(en.headline(alert(.blocked, .write, count: 3)), "Blocked: Zoom tried to write \(p) (×3)")

        // `mv ~/.zsh_history` after learning: the new triple is a write, and the verb says so.
        let h = try Harness(learningDays: 1)
        let cat = terminalShell(h, P.cat(501, parent: 500))
        _ = h.open(cat, "/Users/alice/.zsh_history", 10)
        let t = 2 * 86400.0
        let mv = h.spawn(h.tree.node(pid: 500)!.image, proc(502, "/bin/mv", ppid: 500, start: t, platform: true), t)
        let moved = h.file(.rename, mv, OperationSemantics.rename(source: "/Users/alice/.zsh_history", destination: "/private/tmp/h"), t + 1)
        let a = try XCTUnwrap(moved.alerts.first?.alert)
        XCTAssertEqual(a.kind, .firstAccess)
        let hz = AlertFormatter(language: .zhHans, abbreviate: { [n = h.normalizer] in n.abbreviate($0) })
        XCTAssertEqual(hz.headline(a), "Terminal 第一次读写了 ~/.zsh_history")

        // A first write merging into an open read alert of the same level re-notifies.
        let c = AlertCoalescer(window: 600)
        func ev(_ id: Int64, _ access: AccessSet, _ path: String) -> AnalyzedEvent {
            AnalyzedEvent(id: id, time: at(Double(id)), operation: .open, access: access, path: path, secondaryPath: nil,
                          categoryID: "ssh", severity: .critical, process: proc(1, "/x"), chain: [],
                          responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "Zoom"),
                          agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
        }
        let readAlert = c.ingest(ev(1, .read, "/Users/alice/.ssh/id_rsa"), kind: .criticalNonOwner)!
        c.updateStatus(alertID: readAlert.alert.id, status: .read, resolution: nil)
        let write = c.ingest(ev(2, .write, "/Users/alice/.ssh/authorized_keys"), kind: .criticalNonOwner)!
        XCTAssertEqual(write.change, .escalated)
        XCTAssertEqual(write.alert.status, .unread)
        XCTAssertEqual(write.alert.accesses, .readWrite)
        XCTAssertEqual(write.alert.firstPath, "/Users/alice/.ssh/authorized_keys")
        XCTAssertEqual(c.ingest(ev(3, .write, "/Users/alice/.ssh/authorized_keys"), kind: .criticalNonOwner)?.change, .merged)
    }

    // spec-9
    func testBriefExampleZoomReadingAnSSHKeyForTheFirstTime() throws {
        let h = try Harness(learningDays: 1)
        let names: @Sendable (String) -> LocalizedText? = { [c = h.classifier] in c.spec($0)?.name }
        let zh = AlertFormatter(language: .zhHans, abbreviate: { [n = h.normalizer] in n.abbreviate($0) }, categoryName: names)
        let zoomPath = "/Applications/zoom.us.app/Contents/MacOS/zoom.us"
        // During learning: not "first time" (nothing is new while learning).
        let learningZoom = proc(700, zoomPath, start: 10, teamID: "BJ4HAAB9B3")
        let during = try XCTUnwrap(h.open(learningZoom, "/Users/alice/.ssh/id_rsa", 11).alerts.first?.alert)
        XCTAssertFalse(during.firstTime)
        XCTAssertEqual(zh.headline(during), "zoom.us 读取了 ~/.ssh/id_rsa（SSH 密钥，不是预期的访问者）")
        // After learning, a Zoom that never touched SSH keys reads one.
        let t = 2 * 86400.0
        let zoom = proc(701, zoomPath, start: t, teamID: "BJ4HAAB9B3")
        let h2 = try Harness(learningDays: 1)
        let out = h2.open(zoom, sshKey, t + 1)
        let a = try XCTUnwrap(out.alerts.first?.alert)
        XCTAssertEqual(a.kind, .criticalNonOwner)
        XCTAssertTrue(a.firstTime)
        let zh2 = AlertFormatter(language: .zhHans, abbreviate: { [n = h2.normalizer] in n.abbreviate($0) },
                                 categoryName: { [c = h2.classifier] in c.spec($0)?.name })
        let en2 = AlertFormatter(language: .en, abbreviate: { [n = h2.normalizer] in n.abbreviate($0) },
                                 categoryName: { [c = h2.classifier] in c.spec($0)?.name })
        XCTAssertEqual(zh2.line(a), "zoom.us 第一次读取了 ~/.ssh/id_ed25519（SSH 密钥，不是预期的访问者）｜调用链：launchd → zoom.us｜始终允许 · 以后拦截 · 忽略")
        XCTAssertEqual(en2.headline(a), "zoom.us read ~/.ssh/id_ed25519 for the first time (SSH keys, not an expected owner)")
        // Repeats merge and keep the wording.
        let again = try XCTUnwrap(h2.open(zoom, sshKey, t + 30).alerts.first)
        XCTAssertEqual(again.change, .merged)
        XCTAssertEqual(zh2.headline(again.alert), "zoom.us 第一次读取了 ~/.ssh/id_ed25519（SSH 密钥，不是预期的访问者）（2 次）")
    }

    // analysis-11
    func testIgnoredPIDsAndReaddirAreSafeToChangeWhileEventsFlow() throws {
        let h = try Harness()
        let cat = terminalShell(h, P.cat(501, parent: 500))
        let iterations = 2000
        DispatchQueue.concurrentPerform(iterations: iterations) { i in
            switch i % 4 {
            case 0: h.analyzer.ignoredPIDs = [Int32(i)]
            case 1: h.analyzer.readdirEnabled = i % 8 == 1
            case 2: _ = h.analyzer.ignoredPIDs.contains(501)
            default: _ = h.open(cat, sshKey, Double(i))
            }
        }
        // Assignment replaces the set (no accumulation of stale eslogger PIDs).
        h.analyzer.ignoredPIDs = [501]
        XCTAssertTrue(h.open(cat, sshKey, 3000).events.isEmpty)
        h.analyzer.ignoredPIDs = [999]
        XCTAssertEqual(h.analyzer.ignoredPIDs, [999])
        XCTAssertEqual(h.open(cat, sshKey, 3001).events.count, 1)
    }

    // analysis-13
    func testAfterAuthKeepsTheRuleAlert() throws {
        let deny = Rule(id: "deny-history", enabled: true, enforce: true, target: .category("shell-history"), subject: .anyNonOwner,
                        action: .deny, includePlatformBinaries: true)
        let h = try Harness(rules: [deny], learningDays: 1)
        let cat = terminalShell(h, P.cat(501, parent: 500))
        _ = h.open(cat, "/Users/alice/.zsh_history", 10, context: .monitorOnly)  // learned in dry run
        let t = 2 * 86400.0
        let out = h.open(cat, "/Users/alice/.zsh_history", t, context: .afterAuth)
        let e = try XCTUnwrap(out.events.first)
        XCTAssertEqual(e.decision, .allowed, "it happened, so AUTH allowed it")
        XCTAssertEqual(e.ruleID, "deny-history")
        XCTAssertEqual(out.alerts.first?.alert.kind, .ruleAlert, "an access that matched an enforcing deny is not silent")
    }

    // analysis-14
    func testFailedBaselineSavesCanBeRetried() {
        let b = Baseline(learningStartedAt: t0)
        b.approve(responsibleKey: terminalKey, categoryID: "ssh", at: at(1))
        let dirty = b.takeDirty()
        XCTAssertEqual(dirty.count, 2)
        XCTAssertTrue(b.takeDirty().isEmpty)
        b.markDirty(dirty.map(\.0))
        let retry = b.takeDirty()
        XCTAssertEqual(Set(retry.map(\.0)), Set(dirty.map(\.0)))
        XCTAssertTrue(retry.allSatisfy { $0.1?.source == .approved })
    }

    // spec-8 (Core side): unsigned binaries carry their cdhash on the responsible entity.
    func testUnsignedResponsibleBinaryCarriesItsCdhash() throws {
        let h = try Harness()
        var tool = proc(800, "/Users/alice/bin/tool", ppid: 1)
        tool.cdhash = "abcd"
        let unsigned = h.attributor.attribute(chain: h.tree.chain(for: tool, at: at(1)))
        XCTAssertEqual(unsigned.kind, .binary)
        XCTAssertEqual(unsigned.cdhash, "abcd")
        XCTAssertEqual(unsigned.key, "bin:/users/alice/bin/tool", "the baseline key stays path-based")
        var signed = proc(801, "/Users/alice/bin/signed", ppid: 1, signingID: "com.x.signed", teamID: "TEAM")
        signed.cdhash = "ef01"
        XCTAssertNil(h.attributor.attribute(chain: h.tree.chain(for: signed, at: at(1))).cdhash)
        // A responsible subject pinned to a cdhash only matches that code.
        let rule = Rule(id: "deny", enabled: true, enforce: true, target: .category("ssh"),
                        subject: .responsible(key: "bin:/users/alice/bin/tool", teamID: nil, cdhash: "ABCD"), action: .deny)
        let r = try Harness(rules: [rule])
        var replaced = tool
        replaced.cdhash = "9999"
        XCTAssertEqual(authDecision(r, activity(.open, tool, readTargets(sshKey))).verdict, .deny)
        XCTAssertEqual(authDecision(r, activity(.open, replaced, readTargets(sshKey))).verdict, .allow)
    }

    // Subject JSON round trip for the new fields.
    func testNewRuleFieldsRoundTripAndOldJSONStillDecodes() throws {
        let rule = Rule(id: "x", target: .category("ssh"),
                        subject: .responsible(key: "bin:/a", teamID: nil, cdhash: "abcd", exceptOwners: true), action: .deny,
                        createdAt: t0,
                        exceptions: [RuleException(subject: .anyNonOwner, access: .read, chainAgents: ["cursor"], createdAt: t0)])
        let back = try JSONDecoder().decode(Rule.self, from: JSONEncoder().encode(rule))
        XCTAssertEqual(back, rule)
        let old = #"{"id":"o","target":{"category":"ssh"},"subject":{"type":"responsible","key":"app:/x"},"action":"deny","exceptions":[{"id":"e","subject":{"type":"anyNonOwner"},"createdAt":0}]}"#
        let decoded = try JSONDecoder().decode(Rule.self, from: Data(old.utf8))
        XCTAssertEqual(decoded.subject, .responsible(key: "app:/x", teamID: nil, cdhash: nil, exceptOwners: false))
        XCTAssertNil(decoded.exceptions[0].access)
        XCTAssertNil(decoded.exceptions[0].chainAgents)
    }
}

// MARK: - Argv redaction (analysis-7..10)

final class ArgvRedactorRound1Tests: XCTestCase {
    let R = ArgvRedactor.placeholder
    func r(_ argv: [String]) -> [String] { ArgvRedactor.redact(argv, maxArgs: 32, maxLength: 1000)! }

    // analysis-7
    func testURLUserinfoQueryTokensAndPrefixedTokensAnywhere() {
        XCTAssertEqual(r(["git", "remote", "set-url", "origin", "https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/o/r"]),
                       ["git", "remote", "set-url", "origin", "https://\(R)@github.com/o/r"])
        XCTAssertEqual(r(["curl", "https://h/x?a=1&api_key=SECRETVALUE1&b=2"]), ["curl", "https://h/x?a=1&api_key=\(R)&b=2"])
        XCTAssertEqual(r(["curl", "https://h/x?sig=abc123def&page=1"]), ["curl", "https://h/x?sig=\(R)&page=1"])
        // The sensitive parameter first, others after it (the URL used to be split at its first "=").
        XCTAssertEqual(r(["curl", "https://api.example.com/cb?access_token=abcdEFGH1234&state=1"]),
                       ["curl", "https://api.example.com/cb?access_token=\(R)&state=1"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "curl 'https://api.example.com/cb?access_token=abcdEFGH1234&state=1' -o out"]),
                       ["/bin/zsh", "-c", "curl 'https://api.example.com/cb?access_token=\(R)&state=1' -o out"])
        XCTAssertEqual(r(["curl", "--url=https://h/x?api_key=SECRETVALUE1&b=2"]), ["curl", "--url=https://h/x?api_key=\(R)&b=2"])
        XCTAssertEqual(r(["psql", "postgresql://app:hunter2@db.example.com/prod"]), ["psql", "postgresql://app:\(R)@db.example.com/prod"])
        XCTAssertEqual(r(["open", "https://example.com/search?q=a&page=2"]), ["open", "https://example.com/search?q=a&page=2"])
        XCTAssertEqual(r(["git", "clone", "ssh://git@github.com/o/r.git"]), ["git", "clone", "ssh://git@github.com/o/r.git"])
        XCTAssertEqual(r(["open", "/Users/alice/Downloads/report.pdf"]), ["open", "/Users/alice/Downloads/report.pdf"])
    }

    // analysis-8
    func testPositionalSecretsAndAWSStyleKeys() {
        XCTAssertEqual(r(["aws", "configure", "set", "aws_session_token", "IQoJb3JpZ2luX2VjEXAMPLE"]),
                       ["aws", "configure", "set", "aws_session_token", R])
        XCTAssertEqual(r(["openssl", "enc", "-k", "hunter2"]), ["openssl", "enc", "-k", R])
        XCTAssertEqual(r(["mysqldump", "-pS3cret", "db"]), ["mysqldump", "-p\(R)", "db"])
        XCTAssertEqual(r(["security", "add-internet-password", "-a", "me", "-s", "host", "-w", "hunter2", "-p", "/path"]),
                       ["security", "add-internet-password", "-a", "me", "-s", "host", "-w", R, "-p", "/path"], "-p is a path here")
        XCTAssertEqual(r(["curl", "--proxy-user=u:hunter2", "https://x"]), ["curl", "--proxy-user=u:\(R)", "https://x"])
        XCTAssertEqual(r(["wget", "--password=hunter2", "ftp://x/f"]), ["wget", "--password=\(R)", "ftp://x/f"])
        XCTAssertEqual(r(["env", "PGPASSWORD=hunter2", "psql", "-h", "db"]), ["env", "PGPASSWORD=\(R)", "psql", "-h", "db"])
    }

    // analysis-9
    func testHeadersInsideOneArgumentCommandLines() {
        XCTAssertEqual(r(["/bin/zsh", "-c", "curl -H 'X-Api-Key: abc123' https://x"]),
                       ["/bin/zsh", "-c", "curl -H 'X-Api-Key: \(R)' https://x"])
        let agentCommand = r(["/bin/zsh", "-c", "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx && python run.py"])
        XCTAssertFalse(agentCommand[2].contains("abcdefghijklmnopqrstuvwx"))
        XCTAssertTrue(agentCommand[2].hasSuffix("&& python run.py"), "only the value goes, not the rest of the command")
    }

    // analysis-10
    func testForensicDataIsKept() {
        XCTAssertEqual(r(["cat", "-b", "/Users/alice/.ssh/id_ed25519"]), ["cat", "-b", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(r(["cat", "-u", "/Users/alice/.ssh/id_ed25519"]), ["cat", "-u", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(r(["cp", "-H", "/Users/alice/.ssh/id_ed25519", "/Volumes/USB/"]), ["cp", "-H", "/Users/alice/.ssh/id_ed25519", "/Volumes/USB/"])
        XCTAssertEqual(r(["sudo", "-H", "cat", "/Users/alice/.aws/credentials"]), ["sudo", "-H", "cat", "/Users/alice/.aws/credentials"])
        XCTAssertEqual(r(["git", "commit", "--author=Alice <a@x>"]), ["git", "commit", "--author=Alice <a@x>"])
        XCTAssertEqual(r(["gcloud", "--credential-file-override=/Users/alice/.config/gcloud/sa.json", "auth", "list"]),
                       ["gcloud", "--credential-file-override=/Users/alice/.config/gcloud/sa.json", "auth", "list"])
        XCTAssertEqual(r(["claude", "--session-id=1234"]), ["claude", "--session-id=1234"])
        // curl's -u still redacts the password part only.
        XCTAssertEqual(r(["curl", "-u", "alice:hunter2", "https://x"]), ["curl", "-u", "alice:\(R)", "https://x"])
        XCTAssertEqual(r(["curl", "--cookie", "session=abc", "https://x"]), ["curl", "--cookie", R, "https://x"])
    }
}

// MARK: - Path normalizer homes

final class NormalizerRound1Tests: XCTestCase {
    // paths-8 (Core side): homes outside /Users expand `~` like any other.
    func testHomesOutsideUsersExpand() throws {
        let data = try defaultData()
        let n = PathNormalizer(homeDirectories: ["/Volumes/Data/alice", "/Network/Servers/srv/Users/bob"])
        let c = PathClassifier(catalog: data.catalog, normalizer: n)
        XCTAssertEqual(c.classify("/Volumes/Data/alice/.ssh/id_ed25519")?.categoryID, "ssh", "ssh wins over volumes (deeper)")
        XCTAssertEqual(c.classify("/Volumes/Data/alice/.ssh/id_ed25519")?.severity, .critical)
        XCTAssertEqual(c.classify("/Network/Servers/srv/Users/bob/.aws/credentials")?.categoryID, "aws")
    }
}

// MARK: - Second review of the round-1 fixes

final class Round1FollowUpCoreTests: XCTestCase {
    func r(_ argv: [String]) -> [String] { ArgvRedactor.redact(argv, maxArgs: 32, maxLength: 1000)! }

    // A quote that starts mid-word (`print('a b')`) made redactCommandLine → redactSequence recurse on the
    // same string forever: the daemon died of a stack overflow on argv as common as `python3 -c "print('a b')"`.
    func testRedactorTerminatesOnMidWordQuotesUnbalancedQuotesAndDeepNesting() {
        XCTAssertEqual(r(["python3", "-c", "print('hello world')"]), ["python3", "-c", "print('hello world')"])
        XCTAssertEqual(r(["jq", ".a | select(.b == \"x y\")"]), ["jq", ".a | select(.b == \"x y\")"])
        XCTAssertEqual(r(["sh", "-c", "echo \"unbalanced quote"]), ["sh", "-c", "echo \"unbalanced quote"])
        XCTAssertEqual(r(["sh", "-c", "touch a\\ b"]), ["sh", "-c", "touch a\\ b"])
        XCTAssertEqual(r(["node", "-e", "console.log(`a b`, x='c d')"]).count, 3)
        let headers = r(["python3", "-c", "requests.get(u, headers={'Authorization': 'Bearer abcdefghijkl123'})"])
        XCTAssertFalse(headers[2].contains("abcdefghijkl123"), headers[2])
        XCTAssertTrue(headers[2].hasPrefix("requests.get(u,"), "the rest of the command is kept")
        // Command lines nested in command lines are unwrapped a few levels, then treated as tokens.
        var nested = "curl -u admin:hunter2 https://x"
        for _ in 0..<12 { nested = "sh -c '" + nested.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        _ = r(["sh", "-c", nested])
        XCTAssertEqual(r(["sh", "-c", "bash -c 'curl -u admin:hunter2 https://x'"]),
                       ["sh", "-c", "bash -c 'curl -u admin:‹redacted› https://x'"])
    }

    // One huge argument (argv holds ~1 MB) went through superlinear regular expressions for every event of
    // its chain. Elements are now cut at a word boundary first.
    func testRedactorBoundsHugeArguments() {
        let dotted = String(repeating: "a.", count: 100_000)
        XCTAssertEqual(ArgvRedactor.bounded(dotted), ArgvRedactor.placeholder + "…", "one overlong token is replaced")
        let words = Array(repeating: "word", count: 50_000).joined(separator: " ")
        let cut = ArgvRedactor.bounded("TOKEN=s3cr3tv4lue " + words)
        XCTAssertLessThanOrEqual(cut.utf8.count, ArgvRedactor.maxElementLength + 4)
        XCTAssertTrue(cut.hasSuffix(" …"))
        XCTAssertEqual(ArgvRedactor.bounded("short"), "short")
        let start = Date()
        let out = ArgvRedactor.redact(["sh", "-c", dotted, "x" + dotted, "TOKEN=s3cr3tv4lue " + words])!
        XCTAssertLessThan(Date().timeIntervalSince(start), 2, "bounded work per element")
        XCTAssertFalse(out.joined().contains("s3cr3tv4lue"))
        // Nothing past the cut can surface in the stored value.
        let tail = String(repeating: "x", count: 1200) + " ghp_" + String(repeating: "A", count: 30)
        XCTAssertFalse(ArgvRedactor.redact(["echo", tail], maxArgs: 8, maxLength: 5000)!.joined().contains("ghp_"))
    }

    func testRedactionIsMemoizedWithABoundedCache() {
        let argv = ["git", "clone", "https://u:pass1234@host/x"]
        let a = ArgvRedactor.redact(argv), b = ArgvRedactor.redact(argv)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a, ["git", "clone", "https://u:‹redacted›@host/x"])
        for i in 0..<(ArgvRedactor.cache.capacity + 50) { _ = ArgvRedactor.redact(["echo", "\(i)"]) }
        XCTAssertLessThanOrEqual(ArgvRedactor.cache.count, ArgvRedactor.cache.capacity)
        XCTAssertEqual(ArgvRedactor.redact(argv), a, "a cleared cache recomputes the same value")
        XCTAssertEqual(ArgvRedactor.redact(argv, maxArgs: 2), ["git", "clone", "…(+1)"], "the key includes the limits")
    }

    func testRedactorCoversHeaderConfigJSONBodiesAndKeyPassphrases() {
        XCTAssertEqual(r(["git", "-c", "http.extraHeader=Authorization: Basic dXNlcjpwYXNzd29yZA==", "clone", "x"]),
                       ["git", "-c", "http.extraHeader=Authorization: ‹redacted›", "clone", "x"])
        XCTAssertEqual(r(["sh", "-c", "git -c http.extraheader='AUTHORIZATION: basic dXNlcjpwYXNzd29yZA==' fetch"]),
                       ["sh", "-c", "git -c http.extraheader='AUTHORIZATION: ‹redacted›' fetch"])
        XCTAssertEqual(r(["curl", "-d", "{\"client_secret\":\"hunter2abc\",\"grant_type\":\"client_credentials\"}", "https://o/token"]),
                       ["curl", "-d", "{\"client_secret\":\"‹redacted›\",\"grant_type\":\"client_credentials\"}", "https://o/token"])
        XCTAssertEqual(r(["sh", "-c", "curl -d '{\"password\": \"hunter2abc\"}' https://x"]),
                       ["sh", "-c", "curl -d '{\"password\": \"‹redacted›\"}' https://x"])
        XCTAssertEqual(r(["tool", "{\"token_file\":\"/Users/alice/.config/t\",\"secret_name\":\"prod\"}"]),
                       ["tool", "{\"token_file\":\"/Users/alice/.config/t\",\"secret_name\":\"prod\"}"], "references are kept")
        // ssh-keygen writes ~/.ssh: its argv is stored with the event.
        XCTAssertEqual(r(["ssh-keygen", "-N", "newpass123", "-P", "oldpass123", "-f", "/Users/alice/.ssh/k"]),
                       ["ssh-keygen", "-N", "‹redacted›", "-P", "‹redacted›", "-f", "/Users/alice/.ssh/k"])
        XCTAssertEqual(r(["security", "unlock-keychain", "-p", "hunter2", "/Users/alice/Library/Keychains/login.keychain-db"]),
                       ["security", "unlock-keychain", "-p", "‹redacted›", "/Users/alice/Library/Keychains/login.keychain-db"])
        XCTAssertEqual(r(["vault", "login", "hvs.CAESIabcdefghijklmnopqrstuvwxyz0123"]), ["vault", "login", "‹redacted›"])
        XCTAssertEqual(r(["git", "commit", "-m", "Basic auth fix"]), ["git", "commit", "-m", "Basic auth fix"])
    }

    // paths-1 follow-up: argv is matched at the script position, but an option that takes a value could put
    // an owner's script path there (`python3 -X /opt/homebrew/bin/aws -c '<read the key>'` runs the -c code).
    func testInterpreterOptionsCannotChooseTheScript() throws {
        let h = try Harness()
        let python = "/opt/homebrew/Cellar/python@3.12/3.12.4/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
        func py(_ argv: [String]) -> ProcessRecord { proc(900, python, argv: argv) }
        let read = "print(open('/Users/alice/.aws/credentials').read())"
        XCTAssertTrue(h.classifier.isOwner(py(["python3", "/opt/homebrew/bin/aws", "s3", "ls"]), of: "aws"))
        XCTAssertTrue(h.classifier.isOwner(py(["python3", "-I", "-W", "ignore", "/opt/homebrew/bin/aws", "s3", "ls"]), of: "aws"))
        XCTAssertFalse(h.classifier.isOwner(py(["python3", "-X", "/opt/homebrew/bin/aws", "-c", read]), of: "aws"))
        XCTAssertFalse(h.classifier.isOwner(py(["python3", "-W", "/opt/homebrew/bin/aws", "-c", read]), of: "aws"))
        XCTAssertFalse(h.classifier.isOwner(py(["python3", "-c", read, "/opt/homebrew/bin/aws"]), of: "aws"))
        XCTAssertFalse(h.classifier.isOwner(py(["python3", "--unknown-option", "/opt/homebrew/bin/aws"]), of: "aws"),
                       "an unknown option might take a value: fail closed")
        XCTAssertTrue(h.classifier.isOwner(py(["python3", "-Im", "azure.cli", "account", "show"]), of: "azure"))
        let node = "/opt/homebrew/Cellar/node/22.9.0/bin/node"
        XCTAssertTrue(h.classifier.isOwner(proc(901, node, argv: ["node", "--no-warnings", "/opt/homebrew/bin/claude"]), of: "claude-sessions"))
        XCTAssertFalse(h.classifier.isOwner(proc(901, node, argv: ["node", "--require", "/opt/homebrew/bin/claude", "-e", "x"]),
                                            of: "claude-sessions"))
        XCTAssertFalse(h.classifier.isOwner(proc(901, node, argv: ["node", "-r", "/opt/homebrew/bin/claude", "-e", "x"]), of: "claude-sessions"))
        XCTAssertEqual(IdentitySpec.scriptArgument(["node", "-r", "ts-node/register", "/x/app.js"]), "/x/app.js")
        XCTAssertEqual(IdentitySpec.scriptArgument(["python3", "-Wignore", "-m", "pip"]), "pip")
        XCTAssertEqual(IdentitySpec.scriptArgument(["python3", "-OO", "--", "/x/y.py"]), "/x/y.py")
        XCTAssertNil(IdentitySpec.scriptArgument(["python3", "-"]))
        XCTAssertNil(IdentitySpec.scriptArgument(["node", "--eval", "x", "/opt/homebrew/bin/claude"]))
    }

    // paths-9 follow-up: links are only searched in dotfile directories. Sandbox containers link Desktop,
    // Downloads… back into the home; walking them made every file there "WeChat" (or "Bitwarden") data.
    func testSymlinkWalkStaysInDotfileDirectoriesAndRefusesWholeTrees() throws {
        let data = try defaultData()
        let n = PathNormalizer(homeDirectories: [home])
        let resolver = MapSymlinkResolver([:], links: [
            "/Users/alice/Library/Containers/com.tencent.xinWeChat": [
                (link: "/Users/alice/Library/Containers/com.tencent.xinWeChat/Data/Desktop", target: "/Users/alice/Desktop"),
                (link: "/Users/alice/Library/Containers/com.tencent.xinWeChat/Data/.CFUserTextEncoding",
                 target: "/Users/alice/.CFUserTextEncoding"),
            ],
            "/Volumes": [(link: "/Volumes/NAS/docs", target: "/Users/alice/Documents")],
            "/Users/alice/.ssh": [
                (link: "/Users/alice/.ssh/home", target: "/Users/alice"),
                (link: "/Users/alice/.ssh/users", target: "/Users"),
                (link: "/Users/alice/.ssh/root", target: "/"),
                (link: "/Users/alice/.ssh/config", target: "/Users/alice/dotfiles/ssh/config"),
            ],
        ])
        let c = PathClassifier(catalog: data.catalog, normalizer: n, symlinks: resolver)
        XCTAssertNil(c.classify("/Users/alice/Desktop/report.pdf"))
        XCTAssertNil(c.classify("/Users/alice/.CFUserTextEncoding"))
        XCTAssertNil(c.classify("/Users/alice/Documents/taxes.pdf"))
        XCTAssertNil(c.classify("/Users/alice/notes.txt"), "the home never becomes a category")
        XCTAssertFalse(c.prefixes.contains { $0.path == "/Users/alice" || $0.path == "/Users" })
        XCTAssertEqual(c.classify("/Users/alice/dotfiles/ssh/config")?.categoryID, "ssh", "dotfile links still count")
        XCTAssertTrue(c.categoriesBelow(normalized: "/Users/alice/.config").contains("gh"), "parent moves stay covered")
        XCTAssertTrue(PathClassifier.walksForLinks("/Users/alice/.aws", homes: [home]))
        XCTAssertFalse(PathClassifier.walksForLinks("/Users/alice/Library/Mail", homes: [home]))
        XCTAssertFalse(PathClassifier.walksForLinks("/Volumes", homes: [home]))
    }

    // analysis-5 (decision: directory listings are never blocked). Enforcer.decide classifies through
    // Analyzer.classify, so a readdir has no sensitive target there; it is still recorded when enabled.
    func testDirectoryListingsAreNeverBlocked() throws {
        let deny = Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                        access: .any, action: .deny, includePlatformBinaries: true)
        let h = try Harness(rules: [deny, enforced(RuleTemplates.blockAgentsFromCritical())])
        let ls = claudeShell(h, proc(700, "/bin/ls", ppid: 600, platform: true))
        let listing = activity(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"))
        XCTAssertTrue(h.analyzer.classify(listing).isEmpty)
        let d = authDecision(h, listing)
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .notSensitive)
        XCTAssertEqual(authDecision(h, activity(.open, ls, readTargets(sshKey))).verdict, .deny, "reading a key still is")
        h.analyzer.readdirEnabled = true
        let recorded = h.file(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 20, context: .afterAuth)
        XCTAssertEqual(recorded.events.first?.categoryID, "ssh")
        XCTAssertEqual(recorded.events.first?.decision, .allowed)
        XCTAssertNil(recorded.events.first?.ruleID, "a deny rule has nothing to say about a listing")
        XCTAssertFalse(recorded.alerts.contains { $0.alert.kind == .ruleAlert || $0.alert.kind == .wouldBlock })
        // In monitor mode a dry-run deny rule does not claim it "would block" a listing either.
        var dry = deny
        dry.enforce = false
        let m = try Harness(rules: [dry])
        m.analyzer.readdirEnabled = true
        let ls2 = terminalShell(m, proc(701, "/bin/ls", ppid: 500, platform: true))
        let observed = m.file(.readdir, ls2, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 20)
        XCTAssertEqual(observed.events.first?.decision, .observed)
        XCTAssertFalse(observed.alerts.contains { $0.alert.kind == .wouldBlock })
    }

    // rules-2 follow-up: with no file type from the source, every rename of a classified path was judged at
    // the category's worst severity. An agent's atomic save of `.env` (temp `.env.tmp123` → `.env`) was then
    // "critical" and blocked by the agent template. A path a specific file pattern named is a file.
    func testUnknownTypeRenameOfANamedFileIsNotRaised() throws {
        let h = try Harness(rules: [enforced(RuleTemplates.blockAgentsFromCritical())], projectRoots: ["~/code"])
        let node = claudeShell(h, proc(700, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 600))
        func rename(_ src: String, _ dst: String) -> FileActivity {
            activity(.rename, node, OperationSemantics.rename(ReportedPath(src), ReportedPath(dst)))
        }
        XCTAssertEqual(authDecision(h, rename("/Users/alice/code/web/.env.tmp-1234", "/Users/alice/code/web/.env")).verdict, .allow)
        XCTAssertEqual(authDecision(h, rename("/Users/alice/code/web/.env", "/Users/alice/code/web/.env.bak")).verdict, .allow)
        XCTAssertEqual(authDecision(h, rename(chromeProfile + "/History", "/private/tmp/h")).verdict, .allow)
        XCTAssertEqual(authDecision(h, rename(chromeProfile, "/private/tmp/p")).verdict, .deny, "a profile folder is still judged by Cookies")
        XCTAssertEqual(authDecision(h, rename("/Users/alice/code/web/server.pem", "/private/tmp/k")).verdict, .deny)
        let c = h.classifier
        XCTAssertTrue(c.mayContainFiles(try XCTUnwrap(c.classify(chromeProfile))))
        XCTAssertTrue(c.mayContainFiles(try XCTUnwrap(c.classify(chromeProfile + "/Network"))))
        XCTAssertFalse(c.mayContainFiles(try XCTUnwrap(c.classify("/Users/alice/code/web/.env.tmp-1234"))))
        XCTAssertTrue(c.mayContainFiles(try XCTUnwrap(c.classify("/Users/alice/.ssh/keys"))), "no pattern: may be a folder")
    }
}
