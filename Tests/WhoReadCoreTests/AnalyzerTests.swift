import XCTest
@testable import WhoReadCore

final class BaselineTests: XCTestCase {
    func testLearningWindowAndTriples() {
        let b = Baseline(learningStartedAt: t0, learningDuration: 7 * 86400)
        XCTAssertTrue(b.isLearning(at: at(86400)))
        XCTAssertFalse(b.isLearning(at: at(7 * 86400 + 1)))
        let k = BaselineKey(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", access: .read)
        XCTAssertTrue(b.record(k, at: at(1), learning: true))
        XCTAssertFalse(b.record(k, at: at(2), learning: true))
        XCTAssertEqual(b.entry(k)?.count, 2)
        XCTAssertEqual(b.entry(k)?.source, .learned)
        XCTAssertFalse(b.contains(BaselineKey(responsibleKey: k.responsibleKey, categoryID: "ssh", access: .write)))
        b.approve(responsibleKey: k.responsibleKey, categoryID: "aws", at: at(3))
        XCTAssertTrue(b.isApproved(BaselineKey(responsibleKey: k.responsibleKey, categoryID: "aws", access: .write)))
        XCTAssertEqual(b.takeDirty().count, 3)
        XCTAssertEqual(b.takeDirty().count, 0)
        b.remove(responsibleKey: k.responsibleKey)
        XCTAssertFalse(b.contains(k))
    }
}

final class AlertCoalescerTests: XCTestCase {
    func event(_ id: Int64, _ t: TimeInterval, app: String = "app:/applications/zoom.us.app", category: String = "ssh",
               path: String = "/Users/alice/.ssh/id_rsa", access: AccessSet = .read, severity: Severity = .critical) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: at(t), operation: .open, access: access, path: path, secondaryPath: nil, categoryID: category,
                      severity: severity, process: proc(1, "/x"), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: app, displayName: "zoom.us"), agentID: nil, isOwner: false,
                      benignServiceID: nil, decision: .observed, ruleID: nil)
    }

    func testTenMinuteWindowMergesWithCount() {
        let c = AlertCoalescer(window: 600)
        let first = c.ingest(event(1, 0), kind: .firstAccess)
        XCTAssertEqual(first?.change, .created)
        XCTAssertEqual(first?.shouldNotify, true)
        // Not alert-worthy on its own (already learned), still counted.
        let second = c.ingest(event(2, 60, path: "/Users/alice/.ssh/id_ed25519"), kind: nil)
        XCTAssertEqual(second?.change, .merged)
        XCTAssertEqual(second?.shouldNotify, false)
        let third = c.ingest(event(3, 599, access: .write), kind: .firstAccess)
        XCTAssertEqual(third?.alert.count, 3)
        XCTAssertEqual(third?.alert.accesses, .readWrite)
        XCTAssertEqual(third?.alert.paths, ["/Users/alice/.ssh/id_rsa", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(third?.alert.id, first?.alert.id)
        // After the window: a new alert, only if alert-worthy.
        XCTAssertNil(c.ingest(event(4, 601), kind: nil))
        let fresh = c.ingest(event(5, 602), kind: .criticalNonOwner)
        XCTAssertEqual(fresh?.change, .created)
        XCTAssertNotEqual(fresh?.alert.id, first?.alert.id)
    }

    func testOtherAppOrCategoryIsSeparate() {
        let c = AlertCoalescer(window: 600)
        let a = c.ingest(event(1, 0), kind: .firstAccess)!
        let b = c.ingest(event(2, 1, category: "aws"), kind: .firstAccess)!
        let d = c.ingest(event(3, 2, app: "agent:codex"), kind: .firstAccess)!
        XCTAssertEqual(Set([a.alert.id, b.alert.id, d.alert.id]).count, 3)
    }

    func testEscalationReopensDismissedAlert() {
        let c = AlertCoalescer(window: 600)
        let a = c.ingest(event(1, 0), kind: .firstAccess)!
        c.updateStatus(alertID: a.alert.id, status: .resolved, resolution: .ignore)
        let merged = c.ingest(event(2, 10), kind: .firstAccess)!
        XCTAssertEqual(merged.change, .merged, "dismissed alerts absorb repeats silently")
        XCTAssertEqual(merged.alert.status, .resolved)
        let up = c.ingest(event(3, 20), kind: .blocked)!
        XCTAssertEqual(up.change, .escalated)
        XCTAssertEqual(up.alert.kind, .blocked)
        XCTAssertEqual(up.alert.status, .unread)
    }
}

final class AnalyzerTests: XCTestCase {
    let key = "/Users/alice/.ssh/id_ed25519"

    func testNonSensitiveIsDropped() throws {
        let h = try Harness()
        XCTAssertTrue(h.open(P.cat(501, parent: 1), "/usr/lib/libz.dylib").events.isEmpty)
    }

    func testCriticalNonOwnerAlertsDuringLearning() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 1)
        let out = h.open(cat, key, 2)
        XCTAssertEqual(out.events.count, 1)
        let e = out.events[0]
        XCTAssertEqual(e.categoryID, "ssh")
        XCTAssertEqual(e.severity, .critical)
        XCTAssertEqual(e.responsible.displayName, "Terminal")
        XCTAssertEqual(e.chainDisplay, "launchd → Terminal → zsh → cat")
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
        XCTAssertEqual(e.alertID, out.alerts.first?.alert.id)
    }

    func testHighSeverityIsLearnedSilentlyThenAlertsWhenNew() throws {
        let h = try Harness(learningDays: 1)
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 1)
        // Learning: shell history read by Terminal-attributed cat → learned, no alert.
        XCTAssertTrue(h.open(cat, "/Users/alice/.zsh_history", 10).alerts.isEmpty)
        // After learning: same triple → still quiet; new app → alert.
        XCTAssertTrue(h.open(cat, "/Users/alice/.zsh_history", 2 * 86400).alerts.isEmpty)
        let zoom = proc(700, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", start: 2 * 86400, teamID: "BJ4HAAB9B3")
        let out = h.open(zoom, "/Users/alice/.zsh_history", 2 * 86400 + 1)
        XCTAssertEqual(out.alerts.first?.alert.kind, .firstAccess)
        let f = AlertFormatter(language: .zhHans, abbreviate: { [n = h.normalizer] in n.abbreviate($0) })
        XCTAssertEqual(f.line(out.alerts[0].alert), "zoom.us 第一次读取了 ~/.zsh_history｜调用链：launchd → zoom.us｜始终允许 · 以后拦截 · 忽略")
        // Repeats within 10 minutes merge.
        let again = h.open(zoom, "/Users/alice/.zsh_history", 2 * 86400 + 30)
        XCTAssertEqual(again.alerts.first?.change, .merged)
        XCTAssertEqual(again.alerts.first?.alert.count, 2)
    }

    func testOwnerIsQuietAndBenignIsFolded() throws {
        let h = try Harness()
        let ssh = proc(800, "/usr/bin/ssh", start: 0, platform: true)
        let out = h.open(ssh, key, 1)
        XCTAssertTrue(out.events[0].isOwner)
        XCTAssertTrue(out.alerts.isEmpty)
        let mdw = proc(900, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                       start: 0, platform: true)
        let b = h.open(mdw, key, 2)
        XCTAssertEqual(b.events[0].benignServiceID, "spotlight")
        XCTAssertTrue(b.alerts.isEmpty)
        XCTAssertTrue(h.baseline.allEntries.allSatisfy { !$0.key.responsibleKey.contains("mdworker") }, "benign noise stays out of the baseline")
    }

    func testBenignBinaryUnderAnAgentIsNotBenign() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 1)
        let mdw = h.spawn(claude, proc(601, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                                       start: 2, platform: true), 2)
        let out = h.open(mdw, key, 3)
        XCTAssertNil(out.events[0].benignServiceID)
        XCTAssertEqual(out.events[0].agentID, "claude-code")
        XCTAssertEqual(out.events[0].responsible.key, "agent:claude-code")
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
    }

    func testExfiltrationWithoutOpen() throws {
        let h = try Harness()
        let mv = proc(510, "/bin/mv", start: 0, platform: true)
        // rename out of ~/.ssh
        var out = h.file(.rename, mv, OperationSemantics.rename(source: key, destination: "/private/tmp/x"), 1)
        XCTAssertEqual(out.events.count, 1)
        XCTAssertEqual(out.events[0].path, key)
        XCTAssertEqual(out.events[0].secondaryPath, "/private/tmp/x")
        XCTAssertEqual(out.events[0].access, .readWrite)
        // clone / link out
        out = h.file(.clone, mv, OperationSemantics.clone(source: key, destination: "/private/tmp/c"), 2)
        XCTAssertEqual(out.events.first?.access, .read)
        out = h.file(.link, mv, OperationSemantics.link(source: key, destination: "/private/tmp/l"), 3)
        XCTAssertEqual(out.events.first?.operation, .link)
        // Moving a parent directory carries every category below it (gh, gcloud, git credentials).
        out = h.file(.rename, mv, OperationSemantics.rename(source: "/Users/alice/.config", destination: "/private/tmp/cfg"), 4)
        XCTAssertEqual(Set(out.events.map(\.categoryID)), ["gh", "gcloud", "git-credentials"])
        XCTAssertTrue(out.events.allSatisfy(\.viaAncestor))
        XCTAssertTrue(out.events.allSatisfy { $0.severity == .critical })
        // Rename within the same category is one event.
        out = h.file(.rename, mv, OperationSemantics.rename(source: key, destination: "/Users/alice/.ssh/id_ed25519.bak"), 5)
        XCTAssertEqual(out.events.count, 1)
    }

    func testCloseOnlyWhenModified() throws {
        let h = try Harness()
        let vim = proc(520, "/usr/bin/vim", start: 0, platform: true)
        let quiet = h.file(.close, vim, OperationSemantics.close(path: key, modified: false), 1)
        XCTAssertTrue(quiet.events.isEmpty)
        let out = h.file(.close, vim, OperationSemantics.close(path: key, modified: true), 2)
        XCTAssertEqual(out.events.first?.access, .write)
    }

    func testDecisionsFlowIntoEventsAndAlerts() throws {
        var rule = RuleTemplates.blockAgentsFromCritical()
        rule.enabled = true
        let h = try Harness(rules: [rule])
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 1)
        let cat = h.spawn(claude, P.cat(601, parent: 600), 2)
        // eslogger / monitor-only: the dry-run deny shows up as "would block".
        var out = h.open(cat, key, 3)
        XCTAssertEqual(out.events[0].decision, .wouldDeny)
        XCTAssertEqual(out.alerts[0].alert.kind, .wouldBlock)
        XCTAssertEqual(out.events[0].ruleID, rule.id)
        // Native AUTH denial.
        let denied = RuleDecision(verdict: .deny, policyDenied: .read, reason: .explicitDeny, ruleID: rule.id, forceAlert: true)
        out = h.open(cat, key, 4, context: .decided(denied))
        XCTAssertEqual(out.events[0].decision, .denied)
        XCTAssertEqual(out.alerts[0].alert.kind, .blocked)
        // Blocked attempts get their own alert: "blocked ×N" never counts reads that went through.
        XCTAssertEqual(out.alerts[0].change, .created)
        // Denied accesses never enter the baseline (they did not happen).
        let k = BaselineKey(responsibleKey: "agent:claude-code", categoryID: "ssh", access: .read)
        XCTAssertEqual(h.baseline.entry(k)?.count, 1, "only the monitor-only read was recorded")
    }

    func testArgvIsRedactedInStoredEvents() throws {
        let h = try Harness()
        let curl = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)),
                           proc(530, "/usr/bin/curl", start: 1, platform: true,
                                argv: ["curl", "-H", "Authorization: Bearer abc", "--token=ghp_0123456789abcdefghij", "https://x"]), 1)
        let out = h.open(curl, "/Users/alice/.netrc", 2)
        XCTAssertEqual(out.events[0].process.argv, ["curl", "-H", "Authorization: ‹redacted›", "--token=‹redacted›", "https://x"])
        XCTAssertEqual(out.events[0].chain.last?.argv, ["curl", "-H", "Authorization: ‹redacted›", "--token=‹redacted›", "https://x"])
        // The tree still has the raw argv for agent detection.
        XCTAssertEqual(h.tree.node(pid: 530)?.image.argv?[2], "Authorization: Bearer abc")
    }

    func testReaddirIsOptional() throws {
        let h = try Harness()
        let ls = proc(540, "/bin/ls", start: 0, platform: true)
        XCTAssertTrue(h.file(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 1).events.isEmpty)
        h.analyzer.readdirEnabled = true
        XCTAssertEqual(h.file(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 2).events.count, 1)
    }

    func testIgnoredPIDs() throws {
        let h = try Harness()
        h.analyzer.ignoredPIDs = [541]
        XCTAssertTrue(h.open(proc(541, "/usr/bin/eslogger", platform: true), key, 1).events.isEmpty)
    }
}
