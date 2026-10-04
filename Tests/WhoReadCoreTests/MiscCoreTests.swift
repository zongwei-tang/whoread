import XCTest
@testable import WhoReadCore

final class LatencyMonitorTests: XCTestCase {
    func testPercentilesAndP99Trip() {
        let m = LatencyMonitor(capacity: 1000, p99ThresholdMicros: 5000, minimumSamples: 50)
        for i in 0..<100 { m.record(micros: UInt64(100 + i), missedDeadline: false) }
        var s = m.evaluate()
        XCTAssertEqual(s.samples, 100)
        XCTAssertEqual(s.p50Micros, 150, accuracy: 1)
        XCTAssertEqual(s.p99Micros, 199, accuracy: 1)
        XCTAssertFalse(m.isTripped)
        for _ in 0..<5 { m.record(micros: 80_000, missedDeadline: false) }
        s = m.evaluate()
        XCTAssertGreaterThan(s.p99Micros, 5000)
        XCTAssertTrue(m.isTripped)
        XCTAssertTrue(m.trippedReason!.contains("p99"))
        m.reset()
        XCTAssertFalse(m.isTripped)
    }

    func testDeadlineMissTripsImmediately() {
        let m = LatencyMonitor()
        m.record(micros: 10, missedDeadline: true)
        XCTAssertEqual(m.trippedReason, "deadline missed")
        XCTAssertEqual(m.evaluate().deadlineMisses, 1)
    }

    func testFewSamplesDoNotTrip() {
        let m = LatencyMonitor(p99ThresholdMicros: 10, minimumSamples: 50)
        for _ in 0..<10 { m.record(micros: 1_000_000, missedDeadline: false) }
        m.evaluate()
        XCTAssertFalse(m.isTripped)
    }
}

final class EnforcementStateTests: XCTestCase {
    func testAllSwitchesMustAgree() {
        let s = EnforcementState(userEnabled: false, sourceCanEnforce: true)
        var changes: [Bool] = []
        s.onChange { changes.append($0) }
        XCTAssertFalse(s.isActive)
        s.setUserEnabled(true)
        XCTAssertTrue(s.isActive)
        s.setKillSwitchFilePresent(true)
        XCTAssertFalse(s.isActive)
        XCTAssertEqual(s.inactiveReasons, [.killSwitchFile])
        s.setKillSwitchFilePresent(false)
        s.tripLatency("p99")
        XCTAssertFalse(s.isActive)
        XCTAssertEqual(s.inactiveReasons, [.latencyTripped])
        // Re-enabling by the user clears a latency trip.
        s.setUserEnabled(true)
        XCTAssertTrue(s.isActive)
        s.setRulesLoaded(false)
        XCTAssertFalse(s.isActive)
        s.setRulesLoaded(true)
        s.setSourceCanEnforce(false)
        XCTAssertEqual(s.inactiveReasons, [.sourceCannotEnforce])
        XCTAssertEqual(changes, [true, false, true, false, true, false, true, false])
    }
}

final class FormatterAndExportTests: XCTestCase {
    func alert(_ kind: AlertKind, count: Int = 1, access: AccessSet = .read) -> Alert {
        Alert(id: 1, kind: kind, createdAt: t0, updatedAt: t0, windowEndsAt: at(600),
              responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "Zoom"),
              categoryID: "ssh", severity: .critical, count: count, accesses: access, firstPath: "/Users/alice/.ssh/id_ed25519",
              firstEventID: 1, lastEventID: 1, paths: [], chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd"),
                                                               ChainLink(pid: 2, name: "zoom.us", path: "/Applications/zoom.us.app/Contents/MacOS/zoom.us")],
              agentID: nil, ruleID: nil)
    }

    func testSpecExampleBothLanguages() {
        let n = PathNormalizer(homeDirectories: [home])
        let zh = AlertFormatter(language: .zhHans, abbreviate: { n.abbreviate($0) })
        XCTAssertEqual(zh.line(alert(.firstAccess)), "Zoom 第一次读取了 ~/.ssh/id_ed25519｜调用链：launchd → zoom.us｜始终允许 · 以后拦截 · 忽略")
        let en = AlertFormatter(language: .en, abbreviate: { n.abbreviate($0) })
        XCTAssertEqual(en.line(alert(.firstAccess)),
                       "Zoom read ~/.ssh/id_ed25519 for the first time | Chain: launchd → zoom.us | Always allow · Block from now on · Ignore")
        XCTAssertEqual(zh.headline(alert(.blocked, count: 3)), "已拦截：Zoom 试图读取 ~/.ssh/id_ed25519（3 次）")
        XCTAssertEqual(en.headline(alert(.blocked, count: 3)), "Blocked: Zoom tried to read ~/.ssh/id_ed25519 (×3)")
        XCTAssertEqual(zh.line(alert(.blocked)).hasSuffix("允许一次 · 始终允许 · 保持拦截"), true)
        XCTAssertEqual(en.headline(alert(.firstAccess, access: .write)), "Zoom wrote ~/.ssh/id_ed25519 for the first time")
        XCTAssertEqual(en.headline(alert(.wouldBlock)), "A rule would block Zoom from reading ~/.ssh/id_ed25519 (monitor mode)")
        for kind in AlertKind.allCases {
            XCTAssertFalse(zh.kindTitle(kind).isEmpty)
            XCTAssertFalse(en.kindTitle(kind).isEmpty)
        }
    }

    func testCSVQuotingAndFormulaInjection() {
        XCTAssertEqual(Exporter.csvField("plain"), "plain")
        XCTAssertEqual(Exporter.csvField("a,b"), "\"a,b\"")
        XCTAssertEqual(Exporter.csvField("say \"hi\""), "\"say \"\"hi\"\"\"")
        XCTAssertEqual(Exporter.csvField("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"")
        XCTAssertEqual(Exporter.csvField("-cmd"), "'-cmd")
        XCTAssertEqual(Exporter.csvField("line\nbreak"), "\"line\nbreak\"")
    }

    func testExportFormats() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 1)
        let events = h.open(cat, "/Users/alice/.ssh/id_rsa", 2).events + h.open(cat, "/Users/alice/.aws/credentials", 3).events
        let csv = String(data: try Exporter.export(events: events, format: .csv, catalog: h.data.catalog), encoding: .utf8)!
        let rows = csv.split(separator: "\n")
        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows[0].split(separator: ",").count, Exporter.csvColumns.count)
        XCTAssertTrue(rows[1].contains("/Users/alice/.ssh/id_rsa"))
        XCTAssertTrue(rows[1].contains("SSH keys"))
        let json = try Exporter.export(events: events, format: .json)
        let back = try Exporter.decoder().decode([AnalyzedEvent].self, from: json)
        XCTAssertEqual(back.map(\.path), events.map(\.path))
        XCTAssertEqual(back[0].time.timeIntervalSince1970, events[0].time.timeIntervalSince1970, accuracy: 1e-5)
        let jsonl = String(data: try Exporter.export(events: events, format: .jsonl), encoding: .utf8)!
        XCTAssertEqual(jsonl.split(separator: "\n").count, 2)
        XCTAssertTrue(jsonl.contains("\"time\":\"20"))
    }
}

final class ArgvRedactorTests: XCTestCase {
    func testRedaction() {
        XCTAssertEqual(ArgvRedactor.redact(["curl", "-H", "Authorization: Bearer x", "https://api"]),
                       ["curl", "-H", "‹redacted›", "https://api"])
        XCTAssertEqual(ArgvRedactor.redact(["tool", "--password=hunter2", "API_KEY=abc", "--verbose"]),
                       ["tool", "--password=‹redacted›", "API_KEY=‹redacted›", "--verbose"])
        XCTAssertEqual(ArgvRedactor.redact(["aws", "AKIAIOSFODNN7EXAMPLE"]), ["aws", "‹redacted›"])
        XCTAssertEqual(ArgvRedactor.redact(["x", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]), ["x", "‹redacted›"])
        XCTAssertEqual(ArgvRedactor.redact(["x", "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7d"]), ["x", "‹redacted›"])
        // Paths and ordinary words survive.
        XCTAssertEqual(ArgvRedactor.redact(["cat", "/Users/alice/.ssh/id_ed25519"]), ["cat", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(ArgvRedactor.redact(["git", "commit", "-m", "fix authentication bug"]), ["git", "commit", "-m", "fix authentication bug"])
        // argv[0] is never redacted; long argv is capped.
        let long = ["prog"] + (1...20).map { "a\($0)" }
        let r = ArgvRedactor.redact(long)!
        XCTAssertEqual(r.count, 9)
        XCTAssertEqual(r.last, "…(+13)")
        XCTAssertNil(ArgvRedactor.redact(nil as [String]?))
    }
}

final class InMemoryStoreTests: XCTestCase {
    func testQueriesSummariesRetention() throws {
        let h = try Harness()
        let store = InMemoryEventStore()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 1)
        let mdw = proc(900, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores",
                       start: 0, platform: true)
        var all: [AnalyzedEvent] = []
        all += h.open(cat, "/Users/alice/.ssh/id_rsa", 10).events
        all += h.open(cat, "/Users/alice/.aws/credentials", 20).events
        all += h.open(mdw, "/Users/alice/.ssh/id_rsa", 30).events
        all += h.open(cat, "/Users/alice/.ssh/id_rsa", 9 * 86400).events
        try store.insert(all)
        XCTAssertEqual(try store.events(EventQuery()).count, 3, "benign hidden by default")
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).count, 4)
        XCTAssertEqual(try store.events(EventQuery(categoryIDs: ["aws"])).count, 1)
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true, afterID: all[1].id)).count, 2)
        XCTAssertEqual(try store.events(EventQuery(text: "terminal")).count, 3)
        XCTAssertEqual(try store.events(EventQuery(limit: 1)).first?.id, all[3].id, "newest first")
        let sums = try store.summaries(since: nil)
        let ssh = sums.first { $0.categoryID == "ssh" && !$0.benign }!
        XCTAssertEqual(ssh.count, 2)
        XCTAssertEqual(ssh.firstSeen, at(10))
        XCTAssertEqual(ssh.lastSeen, at(9 * 86400))
        let removed = try store.applyRetention(detailCutoff: at(7 * 86400), retentionCutoff: at(-1))
        XCTAssertEqual(removed, 3)
        XCTAssertEqual(try store.counts().events, 1)
        XCTAssertEqual(try store.summaries(since: nil).count, sums.count, "summaries survive detail roll-up")
    }

    func testSettingsDecodingIsForgiving() throws {
        let s = try JSONDecoder().decode(Settings.self, from: Data(#"{"learningDays": 3, "projectRoots": ["~/code", " ", "~/code"]}"#.utf8))
        XCTAssertEqual(s.learningDays, 3)
        XCTAssertEqual(s.retentionDays, 30)
        XCTAssertFalse(s.enforcementEnabled)
        XCTAssertEqual(s.validated().projectRoots, ["~/code"])
        var bad = Settings()
        bad.detailDays = 99
        bad.retentionDays = 10
        XCTAssertEqual(bad.validated().detailDays, 10)
        let store = InMemoryEventStore()
        try store.saveSettings(s)
        XCTAssertEqual(try store.settings().learningDays, 3)
    }
}
