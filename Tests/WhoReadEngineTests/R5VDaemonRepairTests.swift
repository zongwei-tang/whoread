import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Repairs of the round-5 daemon fixes, after their verification (daemon-1, attribution-2, daemon-5,
// the markRead lock, the `~/` refusal). Fixtures: R5DaemonTestSupport (the test vault of /Users/alice).

/// daemon-1, data saved before the fix: "always allow" then approved both access kinds whatever the alert
/// covered. The answer rule saved with it records the kind that was answered, so the first start of this
/// build narrows such a pair of approvals to it, once.
final class R5VDaemonLegacyApprovalTests: XCTestCase {
    private func key(_ access: AccessKind, _ responsible: String = r5dZoomKey) -> BaselineKey {
        BaselineKey(responsibleKey: responsible, categoryID: "test-vault", access: access)
    }

    /// The allow rule "always allow" saved for zoom.us on the test vault.
    private func answerRule(_ access: RuleAccess, createdAt: Date) -> Rule {
        Rule(name: "Allow zoom.us to read WhoRead test vault", enabled: true, target: .category("test-vault"),
             subject: .responsible(key: r5dZoomKey, teamID: "ZOOMTEAM01", cdhash: nil), access: access, action: .allow,
             createdAt: createdAt, template: DaemonCore.askAnswerTemplate, chainAgents: [], coversUnknownAncestry: false)
    }

    /// The state an older build left after "always allow" on zoom.us's read alert: the read rule, and both
    /// kinds approved. `writesSeen`: zoom.us had also written to the vault before (or after) that.
    private func olderBuildState(_ dir: TempDir, rules: [RuleAccess], writesSeenAt: Date? = nil, approvedAt: Date) throws {
        let core = try r5dCore(dir)
        try core.store.saveRules(core.rules.rules + rules.map { answerRule($0, createdAt: approvedAt) })
        core.baseline.record(key(.read), at: approvedAt.addingTimeInterval(-60), learning: false)
        if let seen = writesSeenAt { core.baseline.record(key(.write), at: seen, learning: false) }
        core.baseline.approve(responsibleKey: r5dZoomKey, categoryID: "test-vault", access: .read, at: approvedAt)
        core.baseline.approve(responsibleKey: r5dZoomKey, categoryID: "test-vault", access: .write, at: approvedAt)
        core.persistBaseline()
        // As stored by the older build: it never narrowed anything.
        try core.store.setValue(nil, forKey: DaemonCore.approvalsNarrowedKey)
    }

    func testAnOlderBuildsPairOfApprovalsIsNarrowedToWhatItsAnswerRuleAllowed() throws {
        let dir = TempDir()
        let approvedAt = Date().addingTimeInterval(-86400)
        try olderBuildState(dir, rules: [.read], approvedAt: approvedAt)
        let core = try r5dCore(dir)
        XCTAssertTrue(core.baseline.isApproved(key(.read)))
        XCTAssertFalse(core.baseline.isApproved(key(.write)), "the answer allowed reads only")
        XCTAssertNil(core.baseline.entry(key(.write)), "never seen: as if it had not been approved")
        XCTAssertNotNil(try core.store.value(forKey: DaemonCore.approvalsNarrowedKey))
        XCTAssertFalse(try core.store.loadBaseline().contains { $0.key == key(.write) }, "saved as narrowed")

        // zoom.us writing the vault's private key alerts again.
        let zoom = r5dZoom(core)
        r5dReceive(core, r5dOpen(zoom, r5dVaultKey, .write, at: Date()))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.map(\.kind), [.criticalNonOwner], r5dDescribe(alerts))
        XCTAssertEqual(alerts.first?.accesses, .write)
    }

    func testAKindSeenBeforeTheApprovalStaysKnownButIsNoLongerApproved() throws {
        let dir = TempDir()
        let approvedAt = Date().addingTimeInterval(-86400)
        try olderBuildState(dir, rules: [.read], writesSeenAt: approvedAt.addingTimeInterval(-3600), approvedAt: approvedAt)
        let core = try r5dCore(dir)
        XCTAssertEqual(core.baseline.entry(key(.write))?.source, .observed, "it alerted when it was first seen")
        XCTAssertTrue(core.baseline.isApproved(key(.read)))
    }

    func testAKindOnlySeenAfterTheApprovalIsForgotten() throws {
        let dir = TempDir()
        let approvedAt = Date().addingTimeInterval(-86400)
        try olderBuildState(dir, rules: [.read], writesSeenAt: approvedAt.addingTimeInterval(3600), approvedAt: approvedAt)
        let core = try r5dCore(dir)
        XCTAssertNil(core.baseline.entry(key(.write)), "the approval kept it from alerting when it was first seen")
    }

    func testApprovalsBothAnswersAllowedStay() throws {
        let dir = TempDir()
        let approvedAt = Date().addingTimeInterval(-86400)
        try olderBuildState(dir, rules: [.read, .write], approvedAt: approvedAt)
        let core = try r5dCore(dir)
        XCTAssertTrue(core.baseline.isApproved(key(.read)))
        XCTAssertTrue(core.baseline.isApproved(key(.write)))
    }

    func testWithoutItsAnswerRuleAPairOfApprovalsCannotBeToldApartAndStays() throws {
        let dir = TempDir()
        try olderBuildState(dir, rules: [], approvedAt: Date().addingTimeInterval(-86400))
        let core = try r5dCore(dir)
        XCTAssertTrue(core.baseline.isApproved(key(.read)))
        XCTAssertTrue(core.baseline.isApproved(key(.write)))
    }

    /// Once: an approval this build makes is what the user answered, and a rule deleted later does not
    /// take it back at the next start.
    func testTheNarrowingRunsOnce() throws {
        let dir = TempDir()
        do {
            let core = try r5dCore(dir)
            XCTAssertNotNil(try core.store.value(forKey: DaemonCore.approvalsNarrowedKey))
            try core.store.saveRules(core.rules.rules + [answerRule(.read, createdAt: Date())])
            core.baseline.approve(responsibleKey: r5dZoomKey, categoryID: "test-vault", access: .read, at: Date())
            core.baseline.approve(responsibleKey: r5dZoomKey, categoryID: "test-vault", access: .write, at: Date())
            core.persistBaseline()
        }
        let core = try r5dCore(dir)
        XCTAssertTrue(core.baseline.isApproved(key(.write)))
    }
}

/// attribution-2, the coalescing window: an AI agent with a team and a process that only looks like it
/// (`exec -a claude`, no team) are different keys of the baseline, so they are different alerts. Merged,
/// the impostor's access would join the real agent's alert the user already handled, and its first
/// access would be counted as known for good.
final class R5VDaemonAgentWindowTests: XCTestCase {
    private func shell(_ core: DaemonCore, _ pid: Int32) -> ProcessRecord {
        var p = proc(pid, "/bin/zsh", ppid: 1, platform: true)
        p.signingID = "com.apple.zsh"
        return r5dObserve(core, p)
    }

    private func claude(_ core: DaemonCore, _ pid: Int32, parent: Int32) -> ProcessRecord {
        var p = proc(pid, "/Users/alice/.local/share/claude/versions/2.0.1", ppid: parent, argv: ["claude"])
        p.signingID = "com.anthropic.claude-code"
        p.teamID = "ANTHROPIC1"
        return r5dObserve(core, p)
    }

    /// `exec -a claude /bin/cat <path>` started by launchd: Claude Code by its argv0 alone, with no team.
    private func impostor(_ core: DaemonCore, _ pid: Int32, _ path: String) -> ProcessRecord {
        var p = proc(pid, "/bin/cat", ppid: 1, platform: true, argv: ["claude", path])
        p.signingID = "com.apple.cat"
        return r5dObserve(core, p)
    }

    func testAnImpostorsCriticalReadInsideTheAgentsResolvedWindowIsItsOwnAlert() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        _ = shell(core, 500)
        let agent = claude(core, 600, parent: 500)
        let t = Date()
        r5dReceive(core, r5dOpen(agent, r5dVaultKey, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        XCTAssertEqual(first.responsible.teamID, "ANTHROPIC1")
        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)

        let other = "/Users/alice/WhoReadTestVault/aws/credentials"
        r5dReceive(core, r5dOpen(impostor(core, 700, other), other, at: t.addingTimeInterval(60)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.count, 2, r5dDescribe(alerts))
        guard alerts.count == 2 else { return }
        XCTAssertEqual(alerts[0].status, .resolved)
        XCTAssertEqual(alerts[0].count, 1, "the agent's alert counts its own access only")
        XCTAssertEqual(alerts[1].kind, .criticalNonOwner)
        XCTAssertEqual(alerts[1].status, .unread)
        XCTAssertNil(alerts[1].responsible.teamID)
        XCTAssertEqual(alerts[1].firstPath, other)
    }

    func testAnImpostorsFirstAccessInsideTheAgentsReadWindowAlertsAndIsNotKnownForGood() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        _ = shell(core, 500)
        let agent = claude(core, 600, parent: 500)
        let t = Date()
        r5dReceive(core, r5dOpen(agent, r5dVaultNote, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        XCTAssertEqual(first.kind, .firstAccess)
        try core.markRead([first.id])

        let note2 = "/Users/alice/WhoReadTestVault/notes/plan.txt"
        r5dReceive(core, r5dOpen(impostor(core, 700, note2), note2, at: t.addingTimeInterval(60)))
        var alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.map(\.kind), [.firstAccess, .firstAccess], r5dDescribe(alerts))
        guard alerts.count == 2 else { return }
        XCTAssertEqual(alerts[0].count, 1)
        XCTAssertNil(alerts[1].responsible.teamID)
        XCTAssertEqual(alerts[1].status, .unread)

        // After a restart, the open windows are restored apart too.
        let restarted = try r5dCore(dir)
        let note3 = "/Users/alice/WhoReadTestVault/notes/list.txt"
        r5dReceive(restarted, r5dOpen(claude(restarted, 601, parent: 1), note3, at: t.addingTimeInterval(120)))
        alerts = try r5dAlerts(restarted)
        XCTAssertEqual(alerts.count, 2, r5dDescribe(alerts))
        guard alerts.count == 2 else { return }
        XCTAssertEqual(alerts[0].count, 2, "the agent's next access joins its own alert")
        XCTAssertEqual(alerts[1].count, 1)
    }
}

/// attribution-2, ask mode: a held access of a process that only looks like an AI agent is its own
/// question, not one more attempt of the real agent's, which an answer to the agent would release.
final class R5VAskBrokerAgentTeamTests: XCTestCase {
    private func request(team: String?) -> AskRequest {
        AskRequest(id: 0, key: AskKey(responsibleKey: "agent:claude-code", categoryID: "test-vault", access: .read, chainAgents: ["claude-code"]),
                   responsible: ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code", teamID: team),
                   severity: .critical, path: r5dVaultKey, process: proc(700, "/bin/cat", platform: true), chain: [],
                   agentID: "claude-code", appleProgram: false, firstAt: r5dT, lastAt: r5dT)
    }

    func testAnAgentAndAProcessNamedLikeItAreAskedApart() throws {
        let b = AskBroker(presenceWindow: 600, minimumBudget: 0.01)
        b.noteAnsweringClient()
        let answered = R5VAnswers()
        guard case .held(let agentQuestion) = b.hold(request(team: "ANTHROPIC1"), budget: 30, respond: answered.respond("agent")),
              case .held(let impostorQuestion) = b.hold(request(team: nil), budget: 30, respond: answered.respond("impostor")) else {
            return XCTFail("both accesses are held")
        }
        XCTAssertNotEqual(agentQuestion, impostorQuestion)
        XCTAssertEqual(b.request(id: agentQuestion)?.attempts, 1)
        XCTAssertEqual(b.request(id: agentQuestion)?.responsible.teamID, "ANTHROPIC1")
        XCTAssertNil(b.request(id: impostorQuestion)?.responsible.teamID)
        // The same agent again: one more attempt of its question.
        XCTAssertEqual(b.hold(request(team: "ANTHROPIC1"), budget: 30, respond: answered.respond("agent")), .held(requestID: agentQuestion))
        b.resolve(id: agentQuestion, answer: .allow)
        b.drain()
        XCTAssertEqual(answered.of("agent"), [.allow, .allow])
        XCTAssertEqual(answered.of("impostor"), [], "still held, for its own answer")
        b.denyAll()
    }
}

final class R5VAnswers: @unchecked Sendable {
    private let lock = NSLock()
    private var got: [String: [AskBroker.Answer]] = [:]
    func respond(_ who: String) -> @Sendable (AskBroker.Answer) -> Void {
        { [self] a in lock.lock(); got[who, default: []].append(a); lock.unlock() }
    }
    func of(_ who: String) -> [AskBroker.Answer] {
        lock.lock(); defer { lock.unlock() }
        return got[who] ?? []
    }
}

/// daemon-5, the whole stored blob unreadable ("*"): nothing of it can be kept, but retention keeps
/// waiting until its settings are set again, through any other save (a pause, a kill switch, the
/// console user's) and through restarts.
final class R5VDaemonUnreadableBlobTests: XCTestCase {
    private let consoleUser = IPCPeer(pid: 4242, euid: 501, isTrustedCode: false)

    private func alert(_ id: Int64, daysAgo: Double) -> Alert {
        let t = Date().addingTimeInterval(-daysAgo * 86400)
        return Alert(id: id, kind: .firstAccess, createdAt: t, updatedAt: t, windowEndsAt: t.addingTimeInterval(600),
                     responsible: ResponsibleEntity(kind: .app, key: r5dZoomKey, displayName: "zoom.us"),
                     categoryID: "test-vault", severity: .medium, count: 1, accesses: .read,
                     firstPath: r5dVaultKnownHosts, firstEventID: id, lastEventID: id, paths: [r5dVaultKnownHosts],
                     chain: [], agentID: nil, ruleID: nil)
    }

    /// Settings with a 90-day retention, then the whole blob made unreadable; an alert 60 days old.
    private func unreadableBlob(_ dir: TempDir) throws {
        let core = try r5dCore(dir)
        try core.mutateSettings(peer: .inProcess) { $0.retentionDays = 90 }
        try core.store.upsert([alert(1, daysAgo: 60)])
        try core.store.setValue(Data("not settings".utf8), forKey: "settings")
    }

    func testRetentionWaitsThroughAnotherSaveAndARestart() throws {
        let dir = TempDir()
        try unreadableBlob(dir)
        do {
            let core = try r5dCore(dir)
            try core.mutateSettings(peer: consoleUser) { $0.monitoringPaused = false }
            core.maintenance()
            XCTAssertNotNil(try core.store.alert(id: 1), "60 days of history are not deleted on a 30-day default")
            XCTAssertEqual(try core.store.value(forKey: "settings_backup"), Data("not settings".utf8))
        }
        let core = try r5dCore(dir)
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        core.maintenance()
        XCTAssertNotNil(try core.store.alert(id: 1), "still waiting after a restart")
    }

    func testSettingTheRetentionAgainResumesIt() throws {
        let dir = TempDir()
        try unreadableBlob(dir)
        do {
            let core = try r5dCore(dir)
            try core.mutateSettings(peer: .inProcess) { $0.monitoringPaused = false }
        }
        let core = try r5dCore(dir)
        try core.store.upsert([alert(2, daysAgo: 100)])
        try core.mutateSettings(peer: .inProcess) { $0.retentionDays = 90 }
        core.maintenance()
        XCTAssertNotNil(try core.store.alert(id: 1), "within the 90 days set")
        XCTAssertNil(try core.store.alert(id: 2), "retention runs again, on the period set")
        XCTAssertNil(try core.store.value(forKey: DaemonCore.retentionHoldKey))
    }
}

/// The markRead lock: "mark all read" holds the ingestion lock only while it changes the open windows
/// and queues them. Alerts whose window closed are read back and written with ingestion going on.
final class R5VDaemonMarkReadLockTests: XCTestCase {
    func testMarkingManyAlertsReadDoesNotStallIngestion() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        let t = Date().addingTimeInterval(-7200)
        let closed = (1...10_000).map { i -> Alert in
            let at = t.addingTimeInterval(Double(i))
            return Alert(id: Int64(i), kind: .firstAccess, createdAt: at, updatedAt: at, windowEndsAt: at.addingTimeInterval(600),
                         responsible: ResponsibleEntity(kind: .app, key: "app:/applications/a\(i).app", displayName: "a\(i)"),
                         categoryID: "test-vault", severity: .medium, count: 1, accesses: .read,
                         firstPath: r5dVaultNote, firstEventID: Int64(i), lastEventID: Int64(i), paths: [r5dVaultNote],
                         chain: [], agentID: nil, ruleID: nil)
        }
        try core.store.upsert(closed)
        let done = R5DaemonFlag()
        let longest = R5VLongest()
        let ingest = Thread {
            while !done.value {
                let start = Date()
                core.pipeline.whileIngestionHeld {}
                longest.note(Date().timeIntervalSince(start))
                usleep(500)
            }
        }
        ingest.start()
        try core.markRead(nil)
        done.value = true
        while !ingest.isFinished { usleep(1000) }
        XCTAssertEqual(try core.store.alerts(AlertQuery(statuses: [.unread], limit: 10_000)).count, 0)
        XCTAssertEqual(try core.store.alerts(AlertQuery(statuses: [.read], limit: 10_000)).count, 10_000)
        XCTAssertLessThan(longest.value, 0.15, "ingestion waited \(longest.value) s")
    }
}

final class R5VLongest: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: TimeInterval = 0
    func note(_ v: TimeInterval) { lock.lock(); _value = max(_value, v); lock.unlock() }
    var value: TimeInterval { lock.lock(); defer { lock.unlock() }; return _value }
}

/// The refusal of a `~/…` path rule on a Mac with several users says why, and what is allowed instead.
final class R5VDaemonHomeRelativeRefusalTests: XCTestCase {
    func testTheRefusalSaysThatTildeStandsForEveryUsersHome() throws {
        let dir = TempDir()
        let core = try r5dCore(dir) { c in
            c.homeDirectories = ["/Users/alice", "/Users/bob"]
            c.homeOf = { $0 == 501 ? "/Users/alice" : nil }
        }
        let alice = IPCPeer(pid: 4242, euid: 501, isTrustedCode: true)
        let rule = Rule(id: "deny-taxes", enabled: true, enforce: true, target: .pathPrefix("~/Documents/Taxes"), subject: .anyNonOwner,
                        access: .any, action: .deny, includePlatformBinaries: true)
        XCTAssertThrowsError(try core.upsert(rule: rule, peer: alice, mustBeNew: true, privileged: false)) { e in
            let message = (e as? IPCError)?.message ?? "\(e)"
            XCTAssertEqual((e as? IPCError)?.code, .notPermitted)
            XCTAssertTrue(message.contains("every user's home"), message)
            XCTAssertTrue(message.contains("/Users/alice/Documents/Taxes"), message)
        }
    }
}
