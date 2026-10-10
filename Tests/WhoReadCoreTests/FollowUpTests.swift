import XCTest
@testable import WhoReadCore

/// Follow-ups from review round 1 (ingest and native source).
final class FollowUpTests: XCTestCase {
    func testSymlinkToDevNullIsNotMonitored() throws {
        let data = try defaultData()
        // ~/.zsh_history -> /dev/null (a common way to turn history off).
        let links = MapSymlinkResolver(["/Users/alice/.zsh_history": "/dev/null"],
                                       links: ["/Users/alice/.aws": [(link: "/Users/alice/.aws/x", target: "/dev/zero")]])
        let c = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: [home]), symlinks: links)
        XCTAssertFalse(c.mutePaths.contains { $0 == "/dev/null" || $0.hasPrefix("/dev/") })
        XCTAssertFalse(c.prefixes.contains { $0.path.hasPrefix("/dev") })
        XCTAssertNil(c.classify("/dev/null"))
        XCTAssertEqual(c.classify("/Users/alice/.zsh_history")?.categoryID, "shell-history")
    }

    func testDirectoryListingIsNeverWouldBlock() throws {
        let rule = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .any, action: .deny,
                        includePlatformBinaries: true)
        let h = try Harness(rules: [rule])
        h.analyzer.readdirEnabled = true
        let ls = h.spawn(P.terminal, ProcessRecord(pid: 700, ppid: 100, executablePath: "/bin/ls", isPlatformBinary: true), 1)
        let out = h.file(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 2)
        XCTAssertEqual(out.events.first?.decision, .observed, "listings are never blocked, so never 'would block'")
        XCTAssertNil(out.events.first?.ruleID, "deny rules do not apply to listings")
        XCTAssertNotEqual(out.alerts.first?.alert.kind, .wouldBlock)
    }
}

final class CloseDoesNotConsumeTests: XCTestCase {
    /// A modified close reports a write an earlier open already decided; it must not use up an
    /// "allow once" meant for the next open (monitor-only path too).
    func testModifiedCloseKeepsTheAllowOnce() throws {
        let now = t0
        var rule = Rule(id: "deny", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .any,
                        action: .deny, includePlatformBinaries: true)
        rule.exceptions = [RuleException(subject: .anyNonOwner, expiresAt: now.addingTimeInterval(3600), remainingUses: 1, createdAt: now)]
        let h = try Harness(rules: [rule])
        let vim = h.spawn(P.terminal, ProcessRecord(pid: 710, ppid: 100, executablePath: "/usr/bin/vim", isPlatformBinary: true), 1)
        _ = h.file(.close, vim, OperationSemantics.close(path: "/Users/alice/.ssh/config", modified: true), 2)
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 1)
    }
}

/// "Trust Apple programs" looks at the whole chain, not only the leaf.
final class AppleTrustChainTests: XCTestCase {
    func ask(_ h: Harness, _ p: ProcessRecord) -> RuleDecision {
        let chain = h.tree.chain(for: p, at: at(5))
        let target = EvaluationTarget(path: "/Users/alice/.ssh/id_ed25519", access: .read,
                                      categories: [TargetCategory(id: "ssh", severity: .critical)])
        return h.rules.evaluate(process: chain.first?.image ?? p, chain: chain, targets: [target], enforcementActive: true,
                                now: at(5), ask: AskPolicy(enabled: true, trustApplePrograms: true, benignChain: false))
    }

    func testTerminalShellIsTrustedButAnAppSpawningCatIsNot() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100), 1)
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 2)
        XCTAssertEqual(ask(h, cat).reason, .trustedApple, "Terminal → zsh → cat: every node is Apple")
        XCTAssertTrue(AskPolicy.isTrustableAppleProgram(cat, chain: h.tree.chain(for: cat, at: at(5))))

        let zoom = h.spawn(P.terminal, proc(600, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", ppid: 100,
                                            teamID: "BJ4HAAB9B3"), 1)
        let sh = h.spawn(zoom, proc(601, "/bin/sh", ppid: 600, platform: true), 2)
        let zcat = h.spawn(sh, P.cat(602, parent: 601), 3)
        XCTAssertEqual(ask(h, zcat).verdict, .ask, "Zoom → sh → cat is not an Apple chain")
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(zcat, chain: h.tree.chain(for: zcat, at: at(5))))
    }

    func testAgentAnywhereInTheChainIsNeverTrusted() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100), 1)
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 1)
        let cat = h.spawn(claude, P.cat(601, parent: 600), 2)
        XCTAssertEqual(ask(h, cat).verdict, .ask)
    }
}

final class AnswerKeepsAlertRulesTests: XCTestCase {
    /// An answer ("always allow") only answers the question: an alert rule the user enabled still alerts.
    func testAlertRuleStillAlertsAfterAnAnswer() throws {
        let alert = Rule(id: "alert-ssh", enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .alert,
                         includePlatformBinaries: true)
        let answer = Rule(id: "ans", enabled: true, target: .category("ssh"),
                          subject: .responsible(key: "app:/system/applications/utilities/terminal.app", teamID: nil),
                          access: .read, action: .allow, template: RuleTemplates.askAnswer, chainAgents: [])
        let h = try Harness(rules: [alert, answer])
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100), 1)
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 2)
        let chain = h.tree.chain(for: cat, at: at(5))
        let target = EvaluationTarget(path: "/Users/alice/.ssh/known_hosts", access: .read,
                                      categories: [TargetCategory(id: "ssh", severity: .medium)])
        let d = h.rules.evaluate(process: cat, chain: chain, targets: [target], enforcementActive: true, now: at(5),
                                 ask: AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false))
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .alertRule)
        XCTAssertTrue(d.forceAlert)
        XCTAssertFalse(d.suppressAlert)
    }
}
