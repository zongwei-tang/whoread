import XCTest
@testable import WhoReadCore

final class LatencyMonitorTests: XCTestCase {
    // Ask mode: statistics only. Slow responses are reported (isSlow), never a trip.
    func testPercentilesAndP99Warning() {
        let m = LatencyMonitor(capacity: 1000, p99ThresholdMicros: 5000, minimumSamples: 50)
        for i in 0..<100 { m.record(micros: UInt64(100 + i), missedDeadline: false) }
        var s = m.evaluate()
        XCTAssertEqual(s.samples, 100)
        XCTAssertEqual(s.p50Micros, 150, accuracy: 1)
        XCTAssertEqual(s.p99Micros, 199, accuracy: 1)
        XCTAssertFalse(m.isSlow)
        for _ in 0..<5 { m.record(micros: 80_000, missedDeadline: false) }
        s = m.evaluate()
        XCTAssertGreaterThan(s.p99Micros, 5000)
        XCTAssertTrue(m.isSlow)
        m.reset()
        XCTAssertFalse(m.isSlow)
    }

    func testDeadlineMissIsCountedOnly() {
        let m = LatencyMonitor()
        m.record(micros: 10, missedDeadline: true)
        XCTAssertFalse(m.isSlow)
        XCTAssertEqual(m.evaluate().deadlineMisses, 1)
        XCTAssertFalse(m.isSlow)
    }

    func testFewSamplesAreNotSlow() {
        let m = LatencyMonitor(p99ThresholdMicros: 10, minimumSamples: 50)
        for _ in 0..<10 { m.record(micros: 1_000_000, missedDeadline: false) }
        m.evaluate()
        XCTAssertFalse(m.isSlow)
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
        XCTAssertTrue(s.isActive)
        // Ask mode: only the manual switches turn it off.
        s.setUserEnabled(false)
        XCTAssertEqual(s.inactiveReasons, [.disabledByUser])
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
    let R = ArgvRedactor.placeholder

    func r(_ argv: [String]) -> [String] { ArgvRedactor.redact(argv, maxArgs: 32, maxLength: 1000)! }

    func testRedaction() {
        XCTAssertEqual(ArgvRedactor.redact(["curl", "-H", "Authorization: Bearer x", "https://api"]),
                       ["curl", "-H", "Authorization: \(R)", "https://api"])
        XCTAssertEqual(ArgvRedactor.redact(["tool", "--password=hunter2", "API_KEY=abc", "--verbose"]),
                       ["tool", "--password=\(R)", "API_KEY=\(R)", "--verbose"])
        XCTAssertEqual(ArgvRedactor.redact(["aws", "AKIAIOSFODNN7EXAMPLE"]), ["aws", R])
        XCTAssertEqual(ArgvRedactor.redact(["x", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]), ["x", R])
        XCTAssertEqual(ArgvRedactor.redact(["x", "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7d"]), ["x", R])
        // Paths and ordinary words survive.
        XCTAssertEqual(ArgvRedactor.redact(["cat", "/Users/alice/.ssh/id_ed25519"]), ["cat", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(ArgvRedactor.redact(["git", "commit", "-m", "fix authentication bug"]), ["git", "commit", "-m", "fix authentication bug"])
        XCTAssertEqual(r(["git", "commit", "-m", "update password reset flow"]), ["git", "commit", "-m", "update password reset flow"])
        // argv[0] is never redacted; long argv is capped.
        let long = ["prog"] + (1...20).map { "a\($0)" }
        let capped = ArgvRedactor.redact(long)!
        XCTAssertEqual(capped.count, 9)
        XCTAssertEqual(capped.last, "…(+13)")
        XCTAssertNil(ArgvRedactor.redact(nil as [String]?))
    }

    func testURLCredentialsAndQueryTokens() {
        XCTAssertEqual(r(["git", "clone", "https://x-access-token:ghs_16C7e42F292c6912E7710c838347Ae178B4a@github.com/o/r.git"]),
                       ["git", "clone", "https://x-access-token:\(R)@github.com/o/r.git"])
        XCTAssertEqual(r(["git", "push", "https://alice:hunter2pass@gitlab.example.com/o/r.git"]),
                       ["git", "push", "https://alice:\(R)@gitlab.example.com/o/r.git"])
        XCTAssertEqual(r(["curl", "https://api.example.com/cb?state=1&access_token=abcdEFGH1234"]),
                       ["curl", "https://api.example.com/cb?state=1&access_token=\(R)"])
        // A URL path containing "token" is not a key=value secret.
        XCTAssertEqual(r(["curl", "https://example.com/token/list?page=2"]), ["curl", "https://example.com/token/list?page=2"])
        XCTAssertEqual(r(["git", "clone", "https://github.com/o/r.git"]), ["git", "clone", "https://github.com/o/r.git"])
    }

    func testFlagValueFormsAndToolSpecificFlags() {
        XCTAssertEqual(r(["gpg", "--batch", "--passphrase=hunter2", "-d", "f"]), ["gpg", "--batch", "--passphrase=\(R)", "-d", "f"])
        XCTAssertEqual(r(["tool", "--pass=hunter2", "--key=hunter2"]), ["tool", "--pass=\(R)", "--key=\(R)"])
        XCTAssertEqual(r(["curl", "--user=alice:hunter2", "-ualice:hunter2", "--proxy-user", "u:hunter2"]),
                       ["curl", "--user=alice:\(R)", "-ualice:\(R)", "--proxy-user", "u:\(R)"])
        XCTAssertEqual(r(["sshpass", "-p", "hunter2", "ssh", "alice@host"]), ["sshpass", "-p", R, "ssh", "alice@host"])
        XCTAssertEqual(r(["mysql", "-uroot", "-pS3cretPass", "db"]), ["mysql", "-uroot", "-p\(R)", "db"])
        XCTAssertEqual(r(["redis-cli", "-a", "hunter2", "ping"]), ["redis-cli", "-a", R, "ping"])
        XCTAssertEqual(r(["openssl", "enc", "-pass", "pass:hunter2", "-passin", "env:PW"]),
                       ["openssl", "enc", "-pass", "pass:\(R)", "-passin", "env:PW"])
        XCTAssertEqual(r(["security", "add-generic-password", "-a", "me", "-s", "svc", "-w", "hunter2"]),
                       ["security", "add-generic-password", "-a", "me", "-s", "svc", "-w", R])
        XCTAssertEqual(r(["aws", "configure", "set", "aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]),
                       ["aws", "configure", "set", "aws_secret_access_key", R])
        XCTAssertEqual(r(["npm", "config", "set", "//registry.npmjs.org/:_authToken", "abc123"]),
                       ["npm", "config", "set", "//registry.npmjs.org/:_authToken", R])
        XCTAssertEqual(r(["kubectl", "create", "secret", "generic", "x", "--from-literal=password=xyz"]),
                       ["kubectl", "create", "secret", "generic", "x", "--from-literal=password=\(R)"])
        XCTAssertEqual(r(["sudo", "curl", "-u", "a:b", "https://x"]), ["sudo", "curl", "-u", "a:\(R)", "https://x"])
        XCTAssertEqual(r(["docker", "login", "-u", "me", "-p", "hunter2", "registry.example.com"]),
                       ["docker", "login", "-u", "me", "-p", R, "registry.example.com"])
        // AWS secret keys contain '/', relative paths survive the entropy check.
        XCTAssertEqual(r(["x", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]), ["x", R])
        XCTAssertEqual(r(["x", "src/components/HeaderNavigationBar2/index"]), ["x", "src/components/HeaderNavigationBar2/index"])
    }

    func testCommandLinesAsOneArgument() {
        XCTAssertEqual(r(["/bin/zsh", "-c", "curl -u admin:hunter2 https://x"]), ["/bin/zsh", "-c", "curl -u admin:\(R) https://x"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "git clone https://oauth2:glpat-AbCdEf1234567890xyz@gitlab.com/x.git"]),
                       ["/bin/zsh", "-c", "git clone https://oauth2:\(R)@gitlab.com/x.git"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "mysql --password hunter2 -e 'select 1'"]),
                       ["/bin/zsh", "-c", "mysql --password \(R) -e 'select 1'"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "cd /tmp && export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 && gh repo list"]),
                       ["/bin/zsh", "-c", "cd /tmp && export GITHUB_TOKEN=\(R) && gh repo list"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "cd /tmp; curl -u a:b https://x"]), ["/bin/zsh", "-c", "cd /tmp; curl -u a:\(R) https://x"])
        XCTAssertEqual(r(["/bin/bash", "-c", "curl -H \"Authorization: Bearer abc.def\" -H 'Accept: application/json' https://x"]),
                       ["/bin/bash", "-c", "curl -H \"Authorization: \(R)\" -H 'Accept: application/json' https://x"])
        XCTAssertEqual(r(["/bin/zsh", "-c", "bash -c \"curl -u a:b https://x\""]), ["/bin/zsh", "-c", "bash -c \"curl -u a:\(R) https://x\""])
        XCTAssertEqual(r(["/bin/zsh", "-c", "cat ~/.ssh/id_ed25519 | pbcopy"]), ["/bin/zsh", "-c", "cat ~/.ssh/id_ed25519 | pbcopy"])
    }

    func testCurlOnlyFlagsAndPathsKept() {
        XCTAssertEqual(r(["cat", "-b", "/Users/alice/.ssh/id_ed25519"]), ["cat", "-b", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(r(["cat", "-u", "/Users/alice/.ssh/id_ed25519"]), ["cat", "-u", "/Users/alice/.ssh/id_ed25519"])
        XCTAssertEqual(r(["cp", "-H", "/Users/alice/.ssh/id_ed25519", "/Volumes/USB/"]), ["cp", "-H", "/Users/alice/.ssh/id_ed25519", "/Volumes/USB/"])
        XCTAssertEqual(r(["sudo", "-H", "cat", "/Users/alice/.aws/credentials"]), ["sudo", "-H", "cat", "/Users/alice/.aws/credentials"])
        XCTAssertEqual(r(["git", "commit", "--author=Alice <a@x>"]), ["git", "commit", "--author=Alice <a@x>"])
        XCTAssertEqual(r(["gcloud", "--credential-file-override=/Users/alice/.config/gcloud/sa.json"]),
                       ["gcloud", "--credential-file-override=/Users/alice/.config/gcloud/sa.json"])
        XCTAssertEqual(r(["claude", "--session-id=1234"]), ["claude", "--session-id=1234"])
        XCTAssertEqual(r(["curl", "--key", "/Users/alice/.ssh/client.key", "https://x"]), ["curl", "--key", "/Users/alice/.ssh/client.key", "https://x"])
        XCTAssertEqual(r(["docker", "login", "--password-stdin", "registry.example.com"]), ["docker", "login", "--password-stdin", "registry.example.com"])
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
