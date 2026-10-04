import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine

// Regression tests for review round 1, at DaemonCore / ServiceHandler / Daemon level.

private let r1Key = "/Users/alice/.ssh/id_ed25519"
private let r1T = Date(timeIntervalSince1970: 1_760_000_000)
private let r1TerminalKey = "app:/system/applications/utilities/terminal.app"
private let rootPeer = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)
private let agentPeer = IPCPeer(pid: 4242, euid: 501, isTrustedCode: false)

/// `baseConfig` without the codesign calls owner resolution makes at start on macOS (hermetic tests).
private func r1Config(_ dir: TempDir) -> DaemonConfiguration {
    var config = baseConfig(dir)
    config.resolveOwners = false
    return config
}

private func r1Core(_ dir: TempDir, _ configure: (inout DaemonConfiguration) -> Void = { _ in }) throws -> (DaemonCore, FakeSource) {
    var config = r1Config(dir)
    configure(&config)
    let fake = FakeSource(canEnforce: true)
    let core = try DaemonCore(config: config, makeSource: { _ in fake })
    return (core, fake)
}

private func strictHandler(_ core: DaemonCore, verifier: PeerVerifier = NoAppPeers()) -> ServiceHandler {
    let h = ServiceHandler(daemon: core, policy: .strict, peerVerifier: verifier)
    h.consoleUID = { 501 }
    return h
}

private func errorCode(_ r: IPCResponse) -> IPCError.Code? {
    if case .error(let e) = r { return e.code }
    return nil
}

/// Terminal → zsh → leaf, registered in the core's process tree.
private func r1TerminalChild(_ core: DaemonCore, _ leaf: ProcessRecord) -> ProcessRecord {
    let terminal = proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, platform: true)
    core.tree.observe(terminal, at: r1T)
    core.tree.observe(proc(500, "/bin/zsh", ppid: 100, platform: true), at: r1T)
    var l = leaf
    l.ppid = 500
    l.originalPPID = 500
    core.tree.observe(l, at: r1T)
    return l
}

/// zsh → node running Claude Code → leaf.
private func r1AgentChild(_ core: DaemonCore, _ leaf: ProcessRecord) -> ProcessRecord {
    core.tree.observe(proc(500, "/bin/zsh", ppid: 1, platform: true), at: r1T)
    core.tree.observe(proc(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 500, argv: ["node", "/opt/homebrew/bin/claude"]), at: r1T)
    var l = leaf
    l.ppid = 600
    l.originalPPID = 600
    core.tree.observe(l, at: r1T)
    return l
}

private func r1Open(_ p: ProcessRecord, _ path: String, write: Bool = false, at t: TimeInterval = 100) -> FileActivity {
    FileActivity(time: r1T.addingTimeInterval(t), operation: .open, process: p,
                 targets: OperationSemantics.open(path: path, fflag: write ? 3 : 1))
}

/// Runs an access through AUTH and, like the native source, records a denial with `.decided`.
@discardableResult
private func r1Auth(_ core: DaemonCore, _ a: FileActivity) -> RuleDecision {
    let d = core.enforcer.decide(a)
    if d.verdict == .deny {
        core.pipeline.receive(.file(a), context: .decided(d))
    } else {
        core.pipeline.receive(.file(a), context: .afterAuth)
    }
    core.writer.flush()
    return d
}

private func enableEnforcement(_ core: DaemonCore) throws {
    try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
    core.drainPolicyQueue()
}

private func r1Alert(id: Int64, kind: AlertKind, category: String = "ssh", path: String = r1Key, access: AccessSet = .read,
                     responsible: ResponsibleEntity = ResponsibleEntity(kind: .app, key: r1TerminalKey, displayName: "Terminal"),
                     ruleID: String? = nil, chain: [ChainLink] = []) -> Alert {
    Alert(id: id, kind: kind, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date().addingTimeInterval(600),
          responsible: responsible, categoryID: category, severity: .critical, count: 1, accesses: access, firstPath: path,
          firstEventID: 1, lastEventID: 1, paths: [path], chain: chain, agentID: nil, ruleID: ruleID)
}

/// A second connection to the core's SQLite file, to inject failures with triggers.
private func sql(_ core: DaemonCore, _ statements: String) throws {
    let db = try SQLiteDatabase(path: core.config.databasePath)
    try db.exec(statements)
}

private func denySSH(enforce: Bool = true, id: String = "deny-ssh") -> Rule {
    Rule(id: id, enabled: true, enforce: enforce, target: .category("ssh"), subject: .anyNonOwner, access: .any, action: .deny,
         includePlatformBinaries: true)
}

// MARK: - Permissions (policy-1, policy-10, storage-ipc-1, policy-11, mac-system-7)

final class PermissionRound1Tests: XCTestCase {
    // policy-1, storage-ipc-1
    func testAConsoleUserAgentCannotSilenceTheAlertAboutItself() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        let handler = strictHandler(core)
        XCTAssertEqual(handler.privilege(of: .markAlertsRead(ids: nil)), .weaken)
        for action in [AlertAction.ignore, .keepBlocking, .allowOnce, .alwaysAllow] {
            XCTAssertEqual(handler.privilege(of: .alertAction(alertID: 1, action: action)), .weaken, "\(action)")
        }
        XCTAssertEqual(handler.privilege(of: .alertAction(alertID: 1, action: .blockFromNowOn)), .strengthen)

        try core.store.upsert([r1Alert(id: 1, kind: .criticalNonOwner, category: "aws", path: "/Users/alice/.aws/credentials")])
        XCTAssertEqual(errorCode(handler.handle(.markAlertsRead(ids: nil), peer: agentPeer)), .notPermitted)
        XCTAssertEqual(errorCode(handler.handle(.markAlertsRead(ids: [1]), peer: agentPeer)), .notPermitted)
        XCTAssertEqual(errorCode(handler.handle(.alertAction(alertID: 1, action: .ignore), peer: agentPeer)), .notPermitted)
        XCTAssertEqual(errorCode(handler.handle(.alertAction(alertID: 1, action: .keepBlocking), peer: agentPeer)), .notPermitted)
        XCTAssertEqual(try core.store.alert(id: 1)?.status, .unread)
        // "Block from now on" from the agent: the rule is added, the alert stays open.
        XCTAssertNil(errorCode(handler.handle(.alertAction(alertID: 1, action: .blockFromNowOn), peer: agentPeer)))
        XCTAssertTrue(core.rules.rules.contains { $0.template == DaemonCore.blockFromNowOnTemplate && $0.target == .category("aws") })
        let still = try XCTUnwrap(core.store.alert(id: 1))
        XCTAssertEqual(still.status, .unread)
        XCTAssertNil(still.resolution)
        // Root resolves it.
        XCTAssertNil(errorCode(handler.handle(.alertAction(alertID: 1, action: .ignore), peer: rootPeer)))
        XCTAssertEqual(try core.store.alert(id: 1)?.status, .resolved)
        XCTAssertEqual(try core.store.alert(id: 1)?.resolution, .ignore)
    }

    // policy-10
    func testUnknownPeerOrConsoleUserFailsClosed() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        let handler = strictHandler(core)
        XCTAssertEqual(errorCode(handler.handle(.status, peer: IPCPeer(pid: 7, euid: nil, isTrustedCode: false))), .notPermitted)
        XCTAssertEqual(errorCode(handler.handle(.rules, peer: IPCPeer(pid: nil, euid: nil, isTrustedCode: true))), .notPermitted)
        XCTAssertNil(errorCode(handler.handle(.status, peer: agentPeer)))
        handler.consoleUID = { nil }
        XCTAssertEqual(errorCode(handler.handle(.status, peer: agentPeer)), .notPermitted, "no console user known")
        XCTAssertNil(errorCode(handler.handle(.status, peer: rootPeer)), "root is always served")
    }

    // policy-11, mac-system-7
    func testAppRequirementWithoutClientRequirementIsReported() throws {
        let dir = TempDir()
        var config = r1Config(dir)
        config.appRequirement = "anchor apple generic and identifier \"com.whoread.app\""
        config.clientRequirement = nil
        let logPath = dir.path("stderr.log")
        fflush(stderr)
        let saved = dup(2)
        let fd = open(logPath, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        dup2(fd, 2)
        let daemon = try? Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: false) })
        fflush(stderr)
        dup2(saved, 2)
        close(saved)
        close(fd)
        XCTAssertNotNil(daemon)
        let log = (try? String(contentsOfFile: logPath, encoding: .utf8)) ?? ""
        XCTAssertTrue(log.contains("--app-requirement has no effect without --client-requirement"), log)

        // isApp is only consulted for connections that passed the client requirement (a pid check alone is racy).
        struct AlwaysApp: PeerVerifier { func isApp(pid: Int32) -> Bool { true } }
        let dir2 = TempDir()
        let (core, _) = try r1Core(dir2)
        let handler = strictHandler(core, verifier: AlwaysApp())
        XCTAssertFalse(handler.isPrivileged(IPCPeer(pid: 99, euid: 501, isTrustedCode: false)))
        XCTAssertTrue(handler.isPrivileged(IPCPeer(pid: 99, euid: 501, isTrustedCode: true)))
        XCTAssertEqual(errorCode(handler.handle(.setPaused(true), peer: IPCPeer(pid: 99, euid: 501, isTrustedCode: false))), .notPermitted)
    }
}

// MARK: - Rules (rules-1, rules-4, rules-5, policy-2, policy-5, policy-7, policy-8, spec-5, spec-8, critic-5)

final class RuleRound1DaemonTests: XCTestCase {
    // rules-1
    func testPathRuleOnAnUnmonitoredPathCoversIt() throws {
        let dir = TempDir()
        let (core, fake) = try r1Core(dir)
        let updatesBefore = fake.monitoringUpdates
        let rule = Rule(id: "deny-secret", enabled: true, enforce: true, target: .pathPrefix("~/Documents/secret"),
                        subject: .anyNonOwner, action: .deny, includePlatformBinaries: true)
        XCTAssertNil(core.analyzer.classifier.classify("/Users/alice/Documents/secret/taxes.pdf"))
        try core.upsert(rule: rule, peer: .inProcess)
        XCTAssertTrue(core.data.catalog.category("custom")?.paths.contains("~/Documents/secret") == true)
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/Documents/secret/taxes.pdf")?.categoryID, "custom")
        XCTAssertTrue(core.analyzer.classifier.mutePaths.contains("/Users/alice/Documents/secret"), "ES muting / prefilter cover it")
        XCTAssertGreaterThan(fake.monitoringUpdates, updatesBefore, "the source was told")
        XCTAssertTrue(FileManager.default.fileExists(atPath: core.config.userCatalogPath), "persisted")
        try enableEnforcement(core)
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        let d = core.enforcer.decide(r1Open(cat, "/Users/alice/Documents/secret/taxes.pdf"))
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "deny-secret")
        // A covered prefix leaves the catalog alone; a relative one is refused.
        let catalogBefore = core.data.catalog
        try core.upsert(rule: Rule(id: "deny-keys", enabled: true, target: .pathPrefix("~/.ssh/keys"), subject: .anyNonOwner,
                                   action: .deny), peer: .inProcess)
        XCTAssertEqual(core.data.catalog, catalogBefore)
        XCTAssertThrowsError(try core.upsert(rule: Rule(id: "rel", enabled: true, target: .pathPrefix("Documents"),
                                                        subject: .anyNonOwner, action: .deny), peer: .inProcess))
    }

    // policy-7, rules-4, rules-5 (end to end): "allow once" lets the blocked path through once.
    func testAllowOnceTargetsTheBlockedPathAccessAndChain() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        try enableEnforcement(core)
        let cat = r1AgentChild(core, proc(601, "/bin/cat", platform: true))
        // Two blocked reads merge into one blocked alert named after the first.
        XCTAssertEqual(r1Auth(core, r1Open(cat, "/Users/alice/.ssh/known_hosts", at: 100)).verdict, .deny)
        XCTAssertEqual(r1Auth(core, r1Open(cat, r1Key, at: 101)).verdict, .deny)
        let blocked = try XCTUnwrap(core.store.alerts(AlertQuery()).first { $0.kind == .blocked })
        XCTAssertEqual(blocked.firstPath, "/Users/alice/.ssh/known_hosts")
        XCTAssertEqual(blocked.count, 2)
        try core.apply(action: .allowOnce, toAlert: blocked.id, peer: .inProcess)
        let exception = try XCTUnwrap(core.rules.rules.first { $0.id == "deny-ssh" }?.exceptions.last)
        XCTAssertEqual(exception.pathPrefix, blocked.firstPath)
        XCTAssertEqual(exception.remainingUses, 1)
        XCTAssertEqual(exception.access, .read)
        XCTAssertEqual(exception.categoryID, "ssh")
        XCTAssertEqual(exception.chainAgents, ["claude-code"])
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, "/Users/alice/.ssh/known_hosts", write: true)).verdict, .deny,
                       "a read approval is not a write approval")
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny, "other paths stay blocked")
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, "/Users/alice/.ssh/known_hosts")).verdict, .allow)
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, "/Users/alice/.ssh/known_hosts")).verdict, .deny, "once")
        // "Allow once" is refused on alerts that are not blocks.
        try core.store.upsert([r1Alert(id: 900, kind: .criticalNonOwner, ruleID: "deny-ssh")])
        XCTAssertThrowsError(try core.apply(action: .allowOnce, toAlert: 900, peer: .inProcess)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid)
        }
    }

    // policy-7: an escalated (non-blocked → blocked) alert is a separate alert naming the blocked path.
    func testBlockedAlertAfterAnAllowedReadNamesTheBlockedPath() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([Rule(id: "deny-key", enabled: true, enforce: true, target: .severityAtLeast(.critical),
                                subject: .anyNonOwner, access: .read, action: .deny, includePlatformBinaries: true)])
        try enableEnforcement(core)
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        XCTAssertEqual(r1Auth(core, r1Open(cat, "/Users/alice/.ssh/known_hosts", at: 100)).verdict, .allow)
        XCTAssertEqual(r1Auth(core, r1Open(cat, r1Key, at: 101)).verdict, .deny)
        let alerts = try core.store.alerts(AlertQuery())
        let blocked = try XCTUnwrap(alerts.first { $0.kind == .blocked })
        XCTAssertEqual(blocked.firstPath, r1Key)
        try core.apply(action: .allowOnce, toAlert: blocked.id, peer: .inProcess)
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow, "the retried read goes through")
    }

    // policy-7 / analysis-2: a denied copy to a USB stick has one blocked alert, and "allow once" on it works.
    func testAllowOnceOnADeniedCopyLetsTheRetryThrough() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        try enableEnforcement(core)
        let cp = r1TerminalChild(core, proc(501, "/bin/cp", platform: true))
        let clone = FileActivity(time: r1T.addingTimeInterval(100), operation: .clone, process: cp,
                                 targets: OperationSemantics.clone(source: r1Key, destination: "/Volumes/USB/id_ed25519"))
        XCTAssertEqual(r1Auth(core, clone).verdict, .deny)
        let alerts = try core.store.alerts(AlertQuery())
        XCTAssertEqual(alerts.map(\.categoryID), ["ssh"], "no second, unactionable alert for the stick")
        try core.apply(action: .allowOnce, toAlert: alerts[0].id, peer: .inProcess)
        XCTAssertEqual(core.enforcer.decide(clone).verdict, .allow)
        XCTAssertEqual(core.enforcer.decide(clone).verdict, .deny)
    }

    // policy-2
    func testRuleLimitsAndTheRuleCap() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        func invalid(_ r: Rule, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try DaemonCore.validate(r), what, file: file, line: line) { e in
                XCTAssertEqual((e as? IPCError)?.code, .invalid, file: file, line: line)
            }
        }
        let ok = Rule(id: "ok.rule-1_A", name: "fine", target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        XCTAssertNoThrow(try DaemonCore.validate(ok))
        var r = ok
        r.id = "x\n2026-10-04T10:00:00.000Z INFO enforcement switched on by pid 1 uid 0"; invalid(r, "id with a newline")
        r = ok; r.id = String(repeating: "a", count: 129); invalid(r, "long id")
        r = ok; r.id = ""; invalid(r, "empty id")
        r = ok; r.name = String(repeating: "n", count: 257); invalid(r, "long name")
        r = ok; r.target = .pathPrefix("/" + String(repeating: "p", count: 1024)); invalid(r, "long prefix")
        r = ok; r.subject = .unsigned(path: "/" + String(repeating: "e\u{301}", count: 1_000_000), cdhash: nil); invalid(r, "huge unsigned path")
        r = ok; r.subject = .unsigned(path: "/bin/x", cdhash: String(repeating: "a", count: 65)); invalid(r, "long cdhash")
        r = ok; r.subject = .signed(signingID: String(repeating: "s", count: 257), teamID: nil); invalid(r, "long signing id")
        r = ok; r.subject = .signed(signingID: "com.x", teamID: String(repeating: "T", count: 33)); invalid(r, "long team id")
        r = ok; r.subject = .responsible(key: String(repeating: "k", count: 1025), teamID: nil); invalid(r, "long key")
        r = ok; r.subject = .agentAncestor(agentIDs: (0..<33).map { "a\($0)" }, exceptOwners: false); invalid(r, "many agents")
        r = ok; r.subject = .agentAncestor(agentIDs: [String(repeating: "a", count: 65)], exceptOwners: false); invalid(r, "long agent id")
        r = ok; r.exceptions = (0..<257).map { _ in RuleException(subject: .anyNonOwner) }; invalid(r, "many exceptions")
        r = ok; r.exceptions = [RuleException(subject: .anyNonOwner, pathPrefix: String(repeating: "p", count: 1025))]; invalid(r, "long exception prefix")
        r = ok; r.exceptions = [RuleException(subject: .anyNonOwner, chainAgents: (0..<33).map { "a\($0)" })]; invalid(r, "many exception agents")

        // Through the handler, from an unprivileged console user (a "strengthening" request).
        let handler = strictHandler(core)
        var huge = Rule(id: "huge", enabled: true, target: .severityAtLeast(.medium),
                        subject: .unsigned(path: "/" + String(repeating: "e\u{301}", count: 100_000), cdhash: nil), action: .alert)
        XCTAssertEqual(errorCode(handler.handle(.upsertRule(huge), peer: agentPeer)), .invalid)
        huge.subject = .unsigned(path: "/bin/tool", cdhash: nil)
        XCTAssertNil(errorCode(handler.handle(.upsertRule(huge), peer: agentPeer)), "a reasonable new alert rule is fine")

        // At most 512 rules.
        let many = (0..<DaemonCore.maxRules).map { Rule(id: "r\($0)", enabled: false, target: .category("ssh"), subject: .anyNonOwner, action: .alert) }
        XCTAssertNoThrow(try core.setRules(many))
        XCTAssertThrowsError(try core.setRules(many + [ok]))
        XCTAssertThrowsError(try core.upsert(rule: ok, peer: .inProcess))
        XCTAssertEqual(core.rules.rules.count, DaemonCore.maxRules)
        try core.store.upsert([r1Alert(id: 5, kind: .criticalNonOwner)])
        XCTAssertThrowsError(try core.apply(action: .blockFromNowOn, toAlert: 5, peer: .inProcess), "block from now on respects the cap")
    }

    // policy-2: "block from now on" is idempotent.
    func testBlockFromNowOnTwiceAddsOneRule() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([])
        try core.store.upsert([r1Alert(id: 1, kind: .criticalNonOwner)])
        let handler = strictHandler(core)
        for _ in 0..<5 { XCTAssertNil(errorCode(handler.handle(.alertAction(alertID: 1, action: .blockFromNowOn), peer: agentPeer))) }
        XCTAssertEqual(core.rules.rules.count, 1)
    }

    // critic-5: the rule made by "block from now on" keeps the category's owners working.
    func testBlockFromNowOnOnATerminalAlertKeepsSSHWorking() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([])
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        core.pipeline.receive(.file(r1Open(cat, "/Users/alice/.ssh/id_ed25519.pub")), context: .monitorOnly)
        core.pipeline.receive(.file(r1Open(cat, r1Key)), context: .monitorOnly)
        core.writer.flush()
        let alert = try XCTUnwrap(core.store.alerts(AlertQuery()).first { $0.responsible.key == r1TerminalKey })
        try core.apply(action: .blockFromNowOn, toAlert: alert.id, peer: .inProcess)
        let rule = try XCTUnwrap(core.rules.rules.first)
        XCTAssertEqual(rule.subject, .responsible(key: r1TerminalKey, teamID: nil, cdhash: nil, exceptOwners: true))
        XCTAssertTrue(rule.enforce)
        XCTAssertEqual(rule.template, DaemonCore.blockFromNowOnTemplate)
        try enableEnforcement(core)
        let ssh = r1TerminalChild(core, proc(502, "/usr/bin/ssh", platform: true))
        XCTAssertEqual(core.enforcer.decide(r1Open(ssh, r1Key)).verdict, .allow, "ssh started from Terminal still works")
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
    }

    // spec-8: alert actions on an unsigned binary pin its cdhash.
    func testAlwaysAllowForAnUnsignedBinaryPinsItsCdhash() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        try enableEnforcement(core)
        var tool = proc(800, "/Users/alice/bin/tool", ppid: 1)
        tool.cdhash = "abcd"
        core.tree.observe(tool, at: r1T)
        XCTAssertEqual(r1Auth(core, r1Open(tool, r1Key)).verdict, .deny)
        let blocked = try XCTUnwrap(core.store.alerts(AlertQuery()).first { $0.kind == .blocked })
        XCTAssertEqual(blocked.responsible.cdhash, "abcd")
        try core.apply(action: .alwaysAllow, toAlert: blocked.id, peer: .inProcess)
        let e = try XCTUnwrap(core.rules.rules[0].exceptions.first)
        XCTAssertEqual(e.subject, .responsible(key: "bin:/users/alice/bin/tool", teamID: nil, cdhash: "abcd"))
        XCTAssertEqual(core.enforcer.decide(r1Open(tool, r1Key)).verdict, .allow)
        // Another binary written to the same path (an agent replacing it) does not inherit the approval.
        var replaced = proc(801, "/Users/alice/bin/tool", ppid: 1)
        replaced.cdhash = "eeee"
        core.tree.observe(replaced, at: r1T)
        XCTAssertEqual(core.enforcer.decide(r1Open(replaced, r1Key)).verdict, .deny)
    }

    // policy-5
    func testConcurrentSettingsAndRuleChangesDoNotLoseUpdates() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([])
        DispatchQueue.concurrentPerform(iterations: 60) { i in
            if i % 2 == 0 {
                // An agent looping `whoread enforcement on` (allowed: it strengthens).
                try? core.mutateSettings(peer: agentPeer, reenable: true) { $0.enforcementEnabled = true }
            } else {
                try? core.mutateSettings(peer: .inProcess) { $0.projectRoots.append("~/work\(i)") }
            }
        }
        XCTAssertEqual(core.currentSettings.projectRoots.count, 30, "no project root lost to a stale copy")
        XCTAssertEqual(try core.store.settings().projectRoots.count, 30)
        DispatchQueue.concurrentPerform(iterations: 40) { i in
            try? core.upsert(rule: Rule(id: "c\(i)", enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .alert),
                             peer: .inProcess, mustBeNew: true)
        }
        XCTAssertEqual(core.rules.rules.count, 40)
        XCTAssertEqual(try core.store.loadRules()?.count, 40)
        // mustBeNew re-checked under the lock.
        XCTAssertThrowsError(try core.upsert(rule: Rule(id: "c1", enabled: true, target: .category("ssh"), subject: .anyNonOwner,
                                                        action: .alert), peer: agentPeer, mustBeNew: true)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .notPermitted)
        }
        // A generic settings update (stale copy) never flips enforcement or pause.
        try enableEnforcement(core)
        var stale = core.currentSettings
        stale.enforcementEnabled = false
        stale.monitoringPaused = true
        stale.coalesceMinutes = 3
        XCTAssertNil(errorCode(strictHandler(core).handle(.updateSettings(stale), peer: rootPeer)))
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        XCTAssertFalse(core.currentSettings.monitoringPaused)
        XCTAssertEqual(core.currentSettings.coalesceMinutes, 3)
        XCTAssertTrue(core.enforcement.isActive)
    }

    // policy-8, spec-5
    func testRuleLoadFailureDisablesEnforcementAndKeepsTheStoredRules() throws {
        let dir = TempDir()
        do {
            let (core, _) = try r1Core(dir)
            try core.setRules([denySSH(id: "user-rule")])
            try enableEnforcement(core)
        }
        // Make loading fail (an unreadable rules table).
        do {
            let (core, _) = try r1Core(dir)
            try sql(core, "ALTER TABLE rules RENAME TO rules_saved; CREATE TABLE rules(id TEXT PRIMARY KEY, position INTEGER NOT NULL);")
        }
        let (core, _) = try r1Core(dir)
        XCTAssertTrue(core.rules.rules.isEmpty, "never the templates in place of the user's rules")
        XCTAssertFalse(core.enforcement.isActive)
        XCTAssertTrue(core.enforcement.inactiveReasons.contains(.rulesFailedToLoad))
        XCTAssertNotNil(core.status().rulesLoadError)
        XCTAssertTrue(core.currentSettings.enforcementEnabled, "the user's setting is kept for when rules load again")
        // An unprivileged client cannot overwrite the unreadable rules.
        XCTAssertThrowsError(try core.setRules([], privileged: false)) { e in XCTAssertEqual((e as? IPCError)?.code, .unavailable) }
        XCTAssertThrowsError(try core.upsert(rule: denySSH(id: "new"), peer: agentPeer, mustBeNew: true, privileged: false))
        // The stored rows are untouched.
        try sql(core, "DROP TABLE rules; ALTER TABLE rules_saved RENAME TO rules;")
        XCTAssertEqual(try core.store.loadRules()?.map(\.id), ["user-rule"])
        // A privileged save that succeeds clears the failure.
        try core.setRules([denySSH(id: "user-rule")], privileged: true)
        XCTAssertFalse(core.enforcement.inactiveReasons.contains(.rulesFailedToLoad))
        XCTAssertNil(core.status().rulesLoadError)
        XCTAssertTrue(core.enforcement.isActive)
    }

    // update(catalog:) refuses to orphan rules.
    func testCatalogUpdateRefusesDanglingCategoryRules() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        var catalog = core.data.catalog
        catalog.categories.removeAll { $0.id == "ssh" }
        XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid)
            XCTAssertTrue((e as? IPCError)?.message.contains("deny-ssh") == true)
        }
        XCTAssertNotNil(core.data.catalog.category("ssh"))
        XCTAssertEqual(core.analyzer.classifier.classify(r1Key)?.categoryID, "ssh")
        // A disabled rule does not block the change.
        var off = denySSH()
        off.enabled = false
        try core.setRules([off])
        XCTAssertNoThrow(try core.update(catalog: catalog, peer: .inProcess))
        XCTAssertNil(core.analyzer.classifier.classify(r1Key))
        // Duplicate ids are refused.
        var dup = core.data.catalog
        dup.categories.append(dup.categories[0])
        XCTAssertThrowsError(try core.update(catalog: dup, peer: .inProcess))
    }
}

// MARK: - Settings, kill switches, persistence (policy-3, policy-4, native-es-1, spec-11, policy-12, analysis-14, critic-4)

final class EnforcementRound1Tests: XCTestCase {
    // policy-3
    func testEnforcementOnAfterALatencyTripWorksThroughTheHandler() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        try enableEnforcement(core)
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        core.enforcer.recordResponse(micros: 10, missedDeadline: true)
        core.drainPolicyQueue()
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow)
        let handler = strictHandler(core)
        // The console user may turn it back on (strengthening).
        XCTAssertNil(errorCode(handler.handle(.setEnforcement(enabled: true), peer: agentPeer)))
        core.drainPolicyQueue()
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
        XCTAssertFalse(core.enforcement.inactiveReasons.contains(.latencyTripped))
        // The latency monitor's own trip was reset too: the next check does not trip again.
        core.checkLatency()
        XCTAssertTrue(core.enforcement.isActive)

        // A trip while another switch already had enforcement off is persisted too (EnforcementState
        // reports trips, not only transitions); "enforcement on" clears it.
        core.enforcement.setKillSwitchFilePresent(true)
        core.drainPolicyQueue()
        core.enforcement.tripLatency("deadline missed")
        core.enforcement.setKillSwitchFilePresent(false)
        core.drainPolicyQueue()
        XCTAssertFalse(core.currentSettings.enforcementEnabled)
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow)
        XCTAssertNil(errorCode(handler.handle(.setEnforcement(enabled: true), peer: agentPeer)))
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
    }

    // policy-4
    func testKillSwitchAppliesEvenWhenSettingsCannotBeSaved() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try core.setRules([denySSH()])
        try enableEnforcement(core)
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
        try sql(core, """
            CREATE TRIGGER fail_meta_insert BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT, 'disk full'); END;
            CREATE TRIGGER fail_meta_update BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'disk full'); END;
            """)
        let handler = strictHandler(core)
        XCTAssertEqual(errorCode(handler.handle(.setEnforcement(enabled: false), peer: rootPeer)), .internalError, "the failure is reported")
        XCTAssertFalse(core.enforcement.isActive, "but enforcement is off right away")
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow)
        XCTAssertFalse(core.status().enforcementActive)
        // Pause is applied in memory too.
        XCTAssertEqual(errorCode(handler.handle(.setPaused(true), peer: rootPeer)), .internalError)
        XCTAssertTrue(core.currentSettings.monitoringPaused)
        // Once the disk recovers, a retry persists.
        try sql(core, "DROP TRIGGER fail_meta_insert; DROP TRIGGER fail_meta_update;")
        XCTAssertNil(errorCode(handler.handle(.setEnforcement(enabled: false), peer: rootPeer)))
        XCTAssertFalse(try core.store.settings().enforcementEnabled)
        XCTAssertTrue(try core.store.settings().monitoringPaused)
    }

    // native-es-1
    func testALatencyTripSurvivesARestartUntilTurnedOnAgain() throws {
        let dir = TempDir()
        do {
            let (core, _) = try r1Core(dir)
            try core.setRules([denySSH()])
            var s = core.currentSettings
            s.latencyP99ThresholdMs = 1
            try core.update(settings: s, peer: .inProcess)
            try enableEnforcement(core)
            for _ in 0..<100 { core.enforcer.recordResponse(micros: 5000, missedDeadline: false) }
            core.checkLatency()
            core.drainPolicyQueue()
            XCTAssertFalse(core.enforcement.isActive)
            XCTAssertFalse(try core.store.settings().enforcementEnabled, "the trip is saved as the setting")
        }
        let (core, _) = try r1Core(dir)
        XCTAssertFalse(core.enforcement.isActive, "a restart does not silently turn enforcement back on")
        XCTAssertTrue(core.enforcement.inactiveReasons.contains(.disabledByUser))
        XCTAssertNotNil(core.status().latencyTripReason, "the reason is still shown")
        XCTAssertNil(errorCode(strictHandler(core).handle(.setEnforcement(enabled: true), peer: agentPeer)))
        core.drainPolicyQueue()
        XCTAssertTrue(core.enforcement.isActive)
        XCTAssertNil(core.status().latencyTripReason)
        XCTAssertNil(try core.store.value(forKey: DaemonCore.tripKey))
    }

    // native-es-1 (b): death while AUTH was subscribed.
    func testAuthArmedMarkerLeavesEnforcementOffOnlyIfItWasOn() throws {
        let dir = TempDir()
        do { _ = try r1Core(dir) }
        XCTAssertTrue(FileManager.default.createFile(atPath: dir.path("data/auth-armed"), contents: Data()))
        let (core, _) = try r1Core(dir)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("data/auth-armed")), "the marker is consumed")
        XCTAssertNil(core.status().latencyTripReason, "enforcement was off: nothing to report")
    }

    // spec-11
    func testEnforcementObserversRunOffTheMutatingThread() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try enableEnforcement(core)
        let box = ThreadBox()
        core.onPolicyChanged = { box.record(Thread.current) }
        let caller = Thread.current
        core.enforcement.tripLatency("deadline missed")  // what the ES callback thread does on a miss
        core.drainPolicyQueue()
        let threads = box.threads
        XCTAssertFalse(threads.isEmpty)
        XCTAssertFalse(threads.contains { $0 === caller }, "no IO or callbacks on the thread that flipped the state")
    }

    // policy-12
    func testStopPersistsAUsedAllowOnce() throws {
        let dir = TempDir()
        let config = r1Config(dir)
        let daemon = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        try daemon.start()
        var rule = denySSH()
        rule.exceptions = [RuleException(subject: .anyNonOwner, remainingUses: 1)]
        try daemon.core.setRules([rule])
        try enableEnforcement(daemon.core)
        let cat = r1TerminalChild(daemon.core, proc(501, "/bin/cat", platform: true))
        XCTAssertEqual(daemon.core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow)
        XCTAssertEqual(daemon.core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
        daemon.stop()
        let again = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        // Adjusted in the second review: a used exception is now dropped when saved (it used to stay at 0 uses
        // and make maintenance rewrite the rules table every 30 s).
        XCTAssertEqual(again.rules.rules.count, 1)
        XCTAssertFalse(again.rules.rules[0].exceptions.contains { $0.isLive(at: Date()) }, "a used allow-once does not come back")
    }

    // analysis-14
    func testAnApprovalSurvivesAFailedBaselineSave() throws {
        let dir = TempDir()
        do {
            let (core, _) = try r1Core(dir)
            try core.store.upsert([r1Alert(id: 1, kind: .criticalNonOwner)])
            try sql(core, "CREATE TRIGGER fail_baseline BEFORE INSERT ON baseline BEGIN SELECT RAISE(ABORT, 'io error'); END;")
            try core.apply(action: .alwaysAllow, toAlert: 1, peer: .inProcess)
            XCTAssertTrue(try core.store.loadBaseline().isEmpty, "the save failed")
            try sql(core, "DROP TRIGGER fail_baseline;")
            core.persistBaseline()  // the next maintenance pass
        }
        let (core, _) = try r1Core(dir)
        XCTAssertTrue(core.baseline.isApproved(BaselineKey(responsibleKey: r1TerminalKey, categoryID: "ssh", access: .read)))
        XCTAssertTrue(core.baseline.isApproved(BaselineKey(responsibleKey: r1TerminalKey, categoryID: "ssh", access: .write)))
    }

    // critic-4. Adjusted in the second review: the lock is now taken when the Daemon is built (before its
    // core opens the store), so the second instance fails at init rather than at start().
    func testOneDaemonPerDataDirectory() throws {
        let dir = TempDir()
        let config = r1Config(dir)
        let first = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        try first.start()
        XCTAssertThrowsError(try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })) { e in
            XCTAssertEqual((e as? IPCError)?.code, .unavailable)
            XCTAssertTrue((e as? IPCError)?.message.contains("another WhoRead daemon") == true)
        }
        first.stop()
        first.stop()  // idempotent
        let second = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNoThrow(try second.start())
        second.stop()
        XCTAssertNoThrow(try second.start(), "a stopped daemon can start again (it takes the lock back)")
        second.stop()
    }

    // analysis-11 (daemon side): only the daemon itself is ignored; nothing accumulates.
    func testOnlyTheDaemonPIDIsIgnored() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        XCTAssertEqual(core.analyzer.ignoredPIDs, [getpid()])
    }
}

final class RecordingSource: EventSource, @unchecked Sendable {
    let kind: SourceKind = .native
    let canEnforce = true
    var state = SourceState(running: true)
    private let lock = NSLock()
    private var updates: [(prefixes: [String], ancestors: [String], readdir: Bool)] = []
    func start(sink: EventSink) throws {}
    func stop() {}
    func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool) {
        lock.lock(); updates.append((prefixes, ancestors, readdir)); lock.unlock()
    }
    func enforcementChanged(active: Bool) {}
    var last: (prefixes: [String], ancestors: [String], readdir: Bool)? { lock.lock(); defer { lock.unlock() }; return updates.last }
}

final class ThreadBox: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [Thread] = []
    func record(_ t: Thread) { lock.lock(); list.append(t); lock.unlock() }
    var threads: [Thread] { lock.lock(); defer { lock.unlock() }; return list }
}

// MARK: - Catalog merge, homes, rediscovery, log (critic-6, paths-8, paths-9, policy-9)

final class CatalogRound1Tests: XCTestCase {
    func defaults() throws -> Catalog {
        try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog
    }

    // critic-6
    func testMergeBringsNewDefaultsIntoAUserCopy() throws {
        let defaults = try defaults()
        // Unchanged defaults: the user's copy is used as is.
        var user = defaults
        user.categories[0].enabled = false
        XCTAssertEqual(DaemonCore.merge(user: user, base: defaults, defaults: defaults), user)

        // The old defaults the user's copy was made from: no codex-sessions, an older chrome pattern list, wechat present.
        var base = defaults
        base.version = 0
        base.categories.removeAll { $0.id == "codex-sessions" }
        let chromeIndex = base.categories.firstIndex { $0.id == "chrome" }!
        base.categories[chromeIndex].patterns.removeAll { $0.glob.pattern == "Account Web Data*" }
        // The user's edits: chrome off, custom paths, wechat deleted, a category of their own.
        var copy = base
        copy.categories[chromeIndex].enabled = false
        let customIndex = copy.categories.firstIndex { $0.id == "custom" }!
        copy.categories[customIndex].paths = ["~/Secrets/"]
        copy.categories.removeAll { $0.id == "wechat" }
        copy.categories.append(CategorySpec(id: "mine", name: LocalizedText("Mine"), kind: .custom, severity: .high, paths: ["~/mine/"]))

        let merged = DaemonCore.merge(user: copy, base: base, defaults: defaults)
        XCTAssertEqual(merged.version, defaults.version)
        XCTAssertNotNil(merged.category("codex-sessions"), "new default categories arrive")
        XCTAssertNil(merged.category("wechat"), "a category the user deleted stays deleted")
        XCTAssertNotNil(merged.category("mine"), "the user's own categories are kept")
        XCTAssertEqual(merged.category("chrome")?.enabled, false, "the user's toggle is kept")
        XCTAssertEqual(merged.category("chrome")?.patterns, defaults.category("chrome")?.patterns, "untouched fields take the new defaults")
        XCTAssertEqual(merged.category("custom")?.paths, ["~/Secrets/"], "the user's edit wins")
        XCTAssertEqual(merged.category("ssh"), defaults.category("ssh"))

        // A copy from before base tracking: only missing categories are added.
        let legacy = DaemonCore.merge(user: copy, base: nil, defaults: defaults)
        XCTAssertNotNil(legacy.category("codex-sessions"))
        XCTAssertNotNil(legacy.category("wechat"), "without a base a missing category cannot be told from a deleted one")
        XCTAssertEqual(legacy.category("chrome")?.patterns, copy.category("chrome")?.patterns, "nothing else changes")
        XCTAssertEqual(legacy.version, defaults.version)
    }

    // critic-6 at start: the stored copy is merged and rewritten.
    func testStartMergesAndRewritesTheUserCatalog() throws {
        let dir = TempDir()
        let defaults = try defaults()
        var base = defaults
        base.categories.removeAll { $0.id == "codex-sessions" }
        var user = base
        let i = user.categories.firstIndex { $0.id == "chrome" }!
        user.categories[i].enabled = false
        try FileManager.default.createDirectory(atPath: dir.path("data"), withIntermediateDirectories: true)
        try user.encoded().write(to: URL(fileURLWithPath: dir.path("data/catalog.json")))
        try base.encoded().write(to: URL(fileURLWithPath: dir.path("data/catalog.base.json")))
        let (core, _) = try r1Core(dir)
        XCTAssertNotNil(core.data.catalog.category("codex-sessions"))
        XCTAssertEqual(core.data.catalog.category("chrome")?.enabled, false)
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/.codex/sessions/a.jsonl")?.categoryID, "codex-sessions")
        let written = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: dir.path("data/catalog.json"))))
        XCTAssertNotNil(written.category("codex-sessions"))
        let newBase = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: dir.path("data/catalog.base.json"))))
        XCTAssertEqual(newBase, defaults)
        // Saving the catalog back (a category toggle) records the base again and never writes resolved owners.
        var edit = core.catalogInfo().catalog
        let j = edit.categories.firstIndex { $0.id == "custom" }!
        edit.categories[j].paths = ["~/Secrets/"]
        try core.update(catalog: edit, peer: .inProcess)
        let saved = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: dir.path("data/catalog.json"))))
        XCTAssertEqual(saved, edit)
        XCTAssertEqual(try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: dir.path("data/catalog.base.json")))), defaults)
    }

    // paths-4: what the daemon does at start on macOS (in memory): installed bundles pin their team.
    func testResolvedTeamRejectsFakeSiblingBundles() throws {
        struct Reader: CodesignReader {
            func read(path: String) -> CodesignInfo? {
                path == "/Applications/Google Chrome.app" ? CodesignInfo(identifier: "com.google.Chrome", teamID: "EQHXZ8M8AV") : nil
            }
        }
        let catalog = try defaults()
        let (resolved, _) = OwnerResolver.resolve(catalog: catalog, reader: Reader(),
                                                   exists: { $0 == "/Applications/Google Chrome.app" })
        let n = PathNormalizer(homeDirectories: ["/Users/alice"])
        let before = PathClassifier(catalog: catalog, normalizer: n)
        let after = PathClassifier(catalog: resolved, normalizer: n)
        var chrome = proc(1, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper")
        chrome.teamID = "EQHXZ8M8AV"
        let canary = proc(2, "/Applications/Google Chrome Canary.app/Contents/MacOS/x")
        XCTAssertFalse(before.isOwner(chrome, of: "chrome"), "unresolved: fails closed")
        XCTAssertTrue(after.isOwner(chrome, of: "chrome"), "helpers share the bundle's team")
        XCTAssertFalse(after.isOwner(canary, of: "chrome"), "a Canary bundle created by an admin user has no Google team")
        XCTAssertEqual(DaemonCore.resolveOwners(catalog, config: r1Config(TempDir())), catalog, "disabled by configuration")
    }

    // paths-8
    func testHomeDiscoveryPolicy() {
        let dirs: Set<String> = ["/Users/alice", "/Volumes/Data/bob", "/Network/Servers/srv/Users/carol", "/var/root", "/var/empty",
                                 "/Users/link", "/", "/private/var/root"]
        let entries: [(uid: uid_t, dir: String)] = [
            (501, "/Users/alice"),
            (502, "/Volumes/Data/bob"),                 // moved to another disk
            (503, "/Network/Servers/srv/Users/carol"),  // network home
            (504, "/Users/gone"),                       // does not exist
            (505, "/var/empty"),
            (506, "/var/root"),
            (507, "relative/home"),
            (508, "/Users/link"),                       // symlink to /Volumes/Data/dave
            (509, "/"),
            (510, "/dev/null"),
            (0, "/var/root"),
            (200, "/Users/alice"),                      // system account
            (65534, "/Users/alice"),                    // nobody
        ]
        let homes = HomeDirectories.select(entries, minUID: 501, isDirectory: { dirs.contains($0) },
                                           resolve: { $0 == "/Users/link" ? "/Volumes/Data/dave" : ($0 == "/var/empty" ? "/private/var/empty" : $0) })
        XCTAssertEqual(homes, ["/Network/Servers/srv/Users/carol", "/Users/alice", "/Users/link", "/Volumes/Data/bob", "/Volumes/Data/dave"])
        XCTAssertTrue(HomeDirectories.excluded.contains("/var/root"))
        XCTAssertTrue(HomeDirectories.excluded.contains("/root"))
        XCTAssertEqual(HomeDirectories.select([(501, "/Users/link")], minUID: 501, isDirectory: { _ in true },
                                              resolve: { _ in "/private/var/root" }), ["/Users/link"], "an excluded realpath is not added")
        // Every `~/` category expands under a home outside /Users.
        let n = PathNormalizer(homeDirectories: homes)
        XCTAssertTrue(n.expand("~/.ssh/").contains("/Volumes/Data/bob/.ssh"))
        XCTAssertTrue(n.expand("~/.ssh/").contains("/Network/Servers/srv/Users/carol/.ssh"))
    }

    // paths-9 / paths-8 at runtime: links that appear later are picked up by rediscovery.
    func testRediscoveryPicksUpNewSymlinks() throws {
        let dir = TempDir()
        // Not under /tmp: the normalizer maps /tmp to /private/tmp, which only exists on macOS.
        let homeDir = repoRoot.appendingPathComponent(".build/r1-home-\(UUID().uuidString.prefix(8))").path
        defer { try? FileManager.default.removeItem(atPath: homeDir) }
        try FileManager.default.createDirectory(atPath: homeDir + "/dotfiles/aws", withIntermediateDirectories: true)
        try "x".write(toFile: homeDir + "/dotfiles/aws/credentials", atomically: true, encoding: .utf8)
        let (core, fake) = try r1Core(dir) { $0.homeDirectories = [homeDir] }
        let target = (homeDir + "/dotfiles/aws/credentials")
        let resolvedTarget = RealpathSymlinkResolver().resolve(target) ?? target
        XCTAssertNil(core.analyzer.classifier.classify(resolvedTarget))
        let updates = fake.monitoringUpdates
        core.rediscover()
        XCTAssertEqual(fake.monitoringUpdates, updates, "nothing changed: no rebuild")
        // A dotfile manager links ~/.aws/credentials after the daemon started.
        try FileManager.default.createDirectory(atPath: homeDir + "/.aws", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: homeDir + "/.aws/credentials", withDestinationPath: target)
        core.rediscover()
        XCTAssertEqual(core.analyzer.classifier.classify(resolvedTarget)?.categoryID, "aws")
        XCTAssertTrue(core.analyzer.classifier.mutePaths.contains(resolvedTarget))
        XCTAssertGreaterThan(fake.monitoringUpdates, updates)
        // A monitored directory that later becomes a link (~/.kube -> dotfiles/kube).
        try FileManager.default.createDirectory(atPath: homeDir + "/dotfiles/kube", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: homeDir + "/.kube", withDestinationPath: homeDir + "/dotfiles/kube")
        core.rediscover()
        let kubeTarget = (RealpathSymlinkResolver().resolve(homeDir + "/dotfiles/kube") ?? homeDir + "/dotfiles/kube") + "/config"
        XCTAssertEqual(core.analyzer.classifier.classify(kubeTarget)?.categoryID, "kube")
    }

    // paths-10: the source is told every byte-distinct spelling, not just the canonical prefixes.
    func testSourceGetsMutePathsAndAncestors() throws {
        let dir = TempDir()
        let recorder = RecordingSource()
        let core = try DaemonCore(config: r1Config(dir), makeSource: { _ in recorder })
        try core.mutateSettings(peer: .inProcess) { $0.projectRoots = ["~/Projects"]; $0.readdirEnabled = true }
        let last = try XCTUnwrap(recorder.last)
        let c = core.analyzer.classifier
        XCTAssertEqual(last.prefixes, c.mutePaths)
        XCTAssertEqual(last.ancestors, c.ancestors)
        XCTAssertTrue(last.readdir)
        XCTAssertTrue(last.prefixes.contains("/Users/alice/Projects"))
        XCTAssertTrue(last.ancestors.contains("/Users/alice/.config"), "renaming ~/.config moves gh/gcloud tokens")
    }

    // policy-9
    func testLogLinesCannotBeForged() {
        XCTAssertEqual(Log.sanitize("rule x\n2026-10-04T10:00:00.000Z INFO forged saved"), "rule x\\u{a}2026-10-04T10:00:00.000Z INFO forged saved")
        XCTAssertEqual(Log.sanitize("a\rb\tc"), "a\\u{d}b\\u{9}c")
        XCTAssertEqual(Log.sanitize("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c")
        XCTAssertEqual(Log.sanitize("a\u{85}b\u{7F}c\u{0}"), "a\\u{85}b\\u{7f}c\\u{0}")
        XCTAssertEqual(Log.sanitize("中文 é ~/.ssh/id_ed25519"), "中文 é ~/.ssh/id_ed25519")
        XCTAssertEqual(Log.sanitize(String(repeating: "a", count: 4096)), String(repeating: "a", count: 4096))
        XCTAssertEqual(Log.sanitize(String(repeating: "a", count: 5000)), String(repeating: "a", count: 4096) + "…")
        XCTAssertFalse(Log.sanitize("x\u{1B}[2Jy").contains("\u{1B}"), "no terminal escapes")
    }
}

// MARK: - Second review of the round-1 fixes

private func countRows(_ core: DaemonCore, _ table: String) throws -> Int64 {
    let db = try SQLiteDatabase(path: core.config.databasePath)
    var n: Int64 = 0
    try db.prepare("SELECT COUNT(*) FROM \(table)").query { n = $0.int(0) }
    return n
}

final class Round1FollowUpDaemonTests: XCTestCase {
    // native-es-1 follow-up: the trip is persisted from an observer queued on the policy queue. If the user
    // turned enforcement on again before it ran, persisting then switched their explicit "on" back off.
    func testALateTripObserverDoesNotUndoAnExplicitReenable() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        try enableEnforcement(core)
        core.enforcement.tripLatency("deadline missed")
        core.drainPolicyQueue()
        XCTAssertFalse(core.currentSettings.enforcementEnabled, "the trip is persisted by turning the setting off")
        try enableEnforcement(core)
        XCTAssertTrue(core.enforcement.isActive)
        core.persistTrip("deadline missed")  // the observer of the first trip, running late
        XCTAssertTrue(core.enforcement.isActive)
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        XCTAssertTrue(try core.store.settings().enforcementEnabled)
    }

    // rules-1 follow-up: the catalog is a privileged setting, but a "strengthening" path rule from any
    // console-user client added its path to Custom. An agent could make the root daemon monitor (and, with
    // a deny rule, block for every user) /usr/lib or /Applications.
    func testUnprivilegedPathRulesOnlyExtendMonitoringOfTheUsersOwnFiles() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        let handler = strictHandler(core)
        let system = Rule(id: "deny-usr-lib", enabled: true, enforce: true, target: .pathPrefix("/usr/lib"),
                          subject: .anyNonOwner, action: .deny, includePlatformBinaries: true)
        let before = core.data.catalog
        XCTAssertEqual(errorCode(handler.handle(.upsertRule(system), peer: agentPeer)), .notPermitted)
        XCTAssertEqual(core.data.catalog, before)
        XCTAssertFalse(core.rules.rules.contains { $0.id == "deny-usr-lib" })
        let own = Rule(id: "deny-secret", enabled: true, enforce: true, target: .pathPrefix("~/Documents/secret"),
                       subject: .anyNonOwner, action: .deny)
        XCTAssertNil(errorCode(handler.handle(.upsertRule(own), peer: agentPeer)), "the user's own folder is fine")
        XCTAssertTrue(core.data.catalog.category("custom")?.paths.contains("~/Documents/secret") == true)
        XCTAssertNil(errorCode(handler.handle(.upsertRule(system), peer: rootPeer)), "root may monitor system paths")
        XCTAssertTrue(core.data.catalog.category("custom")?.paths.contains("/usr/lib") == true)
        // A rule that is going to be refused never changes the catalog first.
        let catalog = core.data.catalog
        let clash = Rule(id: "deny-secret", enabled: true, enforce: true, target: .pathPrefix("~/Documents/other"),
                         subject: .anyNonOwner, action: .deny)
        XCTAssertThrowsError(try core.upsert(rule: clash, peer: agentPeer, mustBeNew: true, privileged: false))
        XCTAssertEqual(core.data.catalog, catalog)
        try core.setRules((0..<DaemonCore.maxRules).map { denySSH(id: "r\($0)") })
        XCTAssertThrowsError(try core.upsert(rule: Rule(id: "one-more", enabled: true, target: .pathPrefix("~/Documents/more"),
                                                        subject: .anyNonOwner, action: .deny), peer: rootPeer))
        XCTAssertEqual(core.data.catalog, catalog, "the 512-rule cap is checked before the catalog changes")
    }

    // paths-9 / critic-6 follow-up: rediscovery rebuilt the classifier from a catalog snapshot without the
    // mutation lock, so a catalog update made meanwhile was replaced by the stale classifier.
    func testRediscoveryNeverInstallsAStaleCatalog() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        let base = core.data.catalog
        var withPath = base
        let i = withPath.categories.firstIndex { $0.id == "custom" }!
        withPath.categories[i].paths = ["~/Secret"]
        withPath.categories[i].enabled = true
        try core.update(catalog: withPath, peer: .inProcess)
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/Secret/a.txt")?.categoryID, "custom")
        let updated = DispatchGroup()
        core.rediscoveryHook = {
            // The user removes ~/Secret while rediscovery is between its snapshot and the install.
            DispatchQueue.global().async(group: updated) { try? core.update(catalog: base, peer: .inProcess) }
            Thread.sleep(forTimeInterval: 0.3)
        }
        core.rediscover()
        core.rediscoveryHook = nil
        updated.wait()
        XCTAssertNil(core.analyzer.classifier.classify("/Users/alice/Secret/a.txt"), "the newer catalog (without ~/Secret) is in effect")
        XCTAssertNil(core.data.catalog.category("custom")?.paths.first)
    }

    // critic-4 follow-up: the lock was taken in start(), after the second instance's core had already
    // consumed the running daemon's auth-armed marker and switched its stored enforcement setting off.
    func testASecondInstanceLeavesTheRunningDaemonsStoreAlone() throws {
        let dir = TempDir()
        let config = r1Config(dir)
        let first = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        try first.start()
        defer { first.stop() }
        try enableEnforcement(first.core)
        // What the native source keeps on disk while AUTH events are subscribed.
        XCTAssertTrue(FileManager.default.createFile(atPath: config.authArmedMarkerPath, contents: nil))
        XCTAssertThrowsError(try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) }))
        XCTAssertTrue(FileManager.default.fileExists(atPath: config.authArmedMarkerPath), "the running daemon's marker is left alone")
        XCTAssertTrue(try first.core.store.settings().enforcementEnabled)
        XCTAssertTrue(first.core.enforcement.isActive)
    }

    // critic-6 residual: `whoread catalog resolve-owners` (CLI) saves the catalog with owner identities
    // resolved on this Mac; merge then took the owners for a user edit and froze them for good.
    func testResolvedOwnerIdentitiesAreNeverPersisted() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        var resolved = core.data.catalog
        let ci = resolved.categories.firstIndex { $0.id == "chrome" }!
        let oi = try XCTUnwrap(resolved.categories[ci].owners.firstIndex { !($0.bundles ?? []).isEmpty })
        resolved.categories[ci].owners[oi].teamIDs = ["EQHXZ8M8AV"]  // what resolve-owners pins
        let custom = resolved.categories.firstIndex { $0.id == "custom" }!
        resolved.categories[custom].paths = ["~/Secret"]  // a real edit in the same save
        try core.update(catalog: resolved, peer: .inProcess)
        let saved = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: core.config.userCatalogPath)))
        XCTAssertEqual(saved.category("chrome")?.owners, core.defaultCatalog.category("chrome")?.owners)
        XCTAssertEqual(saved.category("custom")?.paths, ["~/Secret"])
        // A later owner fix in the defaults reaches the category.
        var newDefaults = core.defaultCatalog
        newDefaults.categories[ci].owners.append(IdentitySpec(label: "fix", executables: ["/opt/x/bin/x"], teamIDs: ["T"]))
        let merged = DaemonCore.merge(user: saved, base: core.defaultCatalog, defaults: newDefaults)
        XCTAssertEqual(merged.category("chrome")?.owners, newDefaults.category("chrome")?.owners)
        XCTAssertEqual(merged.category("custom")?.paths, ["~/Secret"])
        // A deliberate change to an owner is the user's and is kept.
        var edited = resolved
        edited.categories[ci].owners[oi].bundles = [Glob("/Applications/Other.app")]
        XCTAssertEqual(DaemonCore.stripResolvedOwners(edited, reference: core.defaultCatalog)
                        .category("chrome")?.owners[oi].bundles?.map(\.pattern), ["/Applications/Other.app"])
        // A copy that an older daemon or the CLI already wrote is cleaned at the next start.
        try resolved.encoded().write(to: URL(fileURLWithPath: core.config.userCatalogPath))
        let (again, _) = try r1Core(dir)
        XCTAssertEqual(again.data.catalog.category("chrome")?.owners, again.defaultCatalog.category("chrome")?.owners)
        let rewritten = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: core.config.userCatalogPath)))
        XCTAssertEqual(rewritten.category("chrome")?.owners, again.defaultCatalog.category("chrome")?.owners)
        XCTAssertEqual(rewritten.category("custom")?.paths, ["~/Secret"])
    }

    // paths-8 follow-up: directory-service (network / mobile AD) accounts have uids far above 65534, which
    // the discovery filter dropped together with nobody.
    func testHomeDiscoveryKeepsDirectoryServiceUsers() {
        let homes = HomeDirectories.select([(1_234_567_890, "/Network/Servers/srv/Users/erin"), (65534, "/Users/nobody"),
                                            (4_294_967_294, "/Users/nobody2"), (4_294_967_295, "/Users/nobody3")],
                                           minUID: 501, isDirectory: { _ in true }, resolve: { $0 })
        XCTAssertEqual(homes, ["/Network/Servers/srv/Users/erin"])
    }

    // paths-4 follow-up: owners are now resolved at every start, and the resolver pinned a spec's signing IDs
    // from its literal paths only. Platform specs mix literal and glob paths (`/usr/sbin/securityd`,
    // `/usr/libexec/**/secd`), so secd, trustd, cloudd… stopped being keychain owners: constant critical alerts.
    func testOwnerResolutionNeverShutsOutGlobMembers() throws {
        struct Reader: CodesignReader {
            func read(path: String) -> CodesignInfo? {
                switch path {
                case "/usr/sbin/securityd": return CodesignInfo(identifier: "com.apple.securityd", teamID: nil)
                case "/usr/bin/security": return CodesignInfo(identifier: "com.apple.security", teamID: nil)
                case "/Applications/Xcode.app/Contents/Developer/usr/bin/git": return CodesignInfo(identifier: "com.apple.git", teamID: nil)
                case "/usr/local/aws-cli/aws": return CodesignInfo(identifier: "aws", teamID: "TEAMAWS")
                default: return nil
                }
            }
        }
        let catalog = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog
        let installed: Set<String> = ["/usr/sbin/securityd", "/usr/bin/security", "/usr/local/aws-cli/aws",
                                      "/Applications/Xcode.app/Contents/Developer/usr/bin/git"]
        let (resolved, _) = OwnerResolver.resolve(catalog: catalog, reader: Reader(), exists: installed.contains)
        let c = PathClassifier(catalog: resolved, normalizer: PathNormalizer(homeDirectories: ["/Users/alice"]))
        var secd = proc(10, "/usr/libexec/secd", platform: true)
        secd.signingID = "com.apple.secd"
        XCTAssertTrue(c.isOwner(secd, of: "keychain"), "a glob member of a platform spec stays an owner")
        var trustd = proc(11, "/usr/libexec/trustd", platform: true)
        trustd.signingID = "com.apple.trustd"
        XCTAssertTrue(c.isOwner(trustd, of: "keychain"))
        XCTAssertEqual(resolved.category("keychain"), catalog.category("keychain"), "mixed specs are left as they are")
        // Literal-only specs are still pinned.
        XCTAssertEqual(resolved.category("aws")?.owners.first?.teamIDs, ["TEAMAWS"])
        var xcodeGit = proc(12, "/Applications/Xcode.app/Contents/Developer/usr/bin/git", platform: true)
        xcodeGit.signingID = "com.apple.git"
        XCTAssertTrue(c.isOwner(xcodeGit, of: "git-credentials"), "Xcode's git is trusted once its signing ID is pinned")
        var copied = xcodeGit
        copied.signingID = "com.apple.cat"
        XCTAssertFalse(c.isOwner(copied, of: "git-credentials"), "another Apple binary copied there is not")
        let unresolved = PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: ["/Users/alice"]))
        XCTAssertFalse(unresolved.isOwner(xcodeGit, of: "git-credentials"), "admin-writable location: fails closed until resolved")
    }

    // policy-12 follow-up: a used "allow once" stayed in the rule at 0 uses, which kept the rule
    // time-dependent: maintenance rewrote the whole rules table every 30 s from then on.
    func testRulesAreOnlyRewrittenWhenSomethingWasConsumed() throws {
        let dir = TempDir()
        let (core, _) = try r1Core(dir)
        var rule = denySSH()
        rule.exceptions = [RuleException(subject: .anyNonOwner, expiresAt: Date().addingTimeInterval(600), remainingUses: 1)]
        try core.setRules([rule])
        try sql(core, "CREATE TABLE rule_writes(n INTEGER); CREATE TRIGGER count_rule_writes AFTER INSERT ON rules BEGIN INSERT INTO rule_writes VALUES (1); END;")
        core.saveConsumableRules()
        core.maintenance()
        XCTAssertEqual(try countRows(core, "rule_writes"), 0, "nothing changed: nothing written")
        try enableEnforcement(core)
        let cat = r1TerminalChild(core, proc(501, "/bin/cat", platform: true))
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .allow, "the allow-once is used")
        core.saveConsumableRules()
        XCTAssertEqual(try countRows(core, "rule_writes"), 1)
        XCTAssertTrue(core.rules.rules[0].exceptions.isEmpty, "the used exception is dropped")
        core.saveConsumableRules()
        core.maintenance()
        XCTAssertEqual(try countRows(core, "rule_writes"), 1, "and not written again")
        XCTAssertEqual(core.enforcer.decide(r1Open(cat, r1Key)).verdict, .deny)
    }
}
