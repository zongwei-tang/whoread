import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Records what a source emits.
final class RecordingSink: EventSink, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [SourceEvent] = []
    private var _states: [SourceState] = []
    func receive(_ event: SourceEvent, context: RuleContext) { lock.lock(); _events.append(event); lock.unlock() }
    func sourceStateChanged(_ state: SourceState) { lock.lock(); _states.append(state); lock.unlock() }
    var events: [SourceEvent] { lock.lock(); defer { lock.unlock() }; return _events }
    var states: [SourceState] { lock.lock(); defer { lock.unlock() }; return _states }
}

/// eslogger-shaped lines for sequence tests.
func exitLine(_ seq: Int, pid: Int = 501) -> String {
    #"{"schema_version":1,"global_seq_num":\#(seq),"process":{"audit_token":{"pid":\#(pid)},"executable":{"path":"\/bin\/cat"}},"event":{"exit":{"stat":0}}}"#
}

/// Passes the prefilter (lifecycle) but has no executable: the parser rejects it as malformed.
func malformedLine(_ seq: Int) -> String {
    #"{"schema_version":1,"global_seq_num":\#(seq),"process":{"audit_token":{"pid":9}},"event":{"exit":{"stat":0}}}"#
}

func lineCount(_ path: String) -> Int {
    ((try? String(contentsOfFile: path, encoding: .utf8)) ?? "").split(separator: "\n").count
}

final class IngestSourceTests: XCTestCase {
    func testReplayMalformedLineIsNotAKernelDrop() throws {
        let dir = TempDir()
        let file = dir.path("seq.jsonl")
        try ([exitLine(10), malformedLine(11), exitLine(12), exitLine(15)].joined(separator: "\n") + "\n")
            .write(toFile: file, atomically: true, encoding: .utf8)
        for prefixes in [nil, ["/Users/alice/.ssh"]] {
            let source = ReplaySource(path: file, prefixes: prefixes)
            let sink = RecordingSink()
            try source.start(sink: sink)
            XCTAssertTrue(source.waitUntilFinished(timeout: 10))
            XCTAssertEqual(source.parserStats?.malformed, 1)
            XCTAssertEqual(source.parserStats?.droppedByKernel, 2, "only 13 and 14 are missing")
            XCTAssertEqual(sink.events.count, 3)
        }
    }

    func testEsloggerMalformedLineIsNotAKernelDrop() throws {
        let dir = TempDir()
        let lines = dir.path("lines.jsonl")
        try ([exitLine(10), malformedLine(11), exitLine(12)].joined(separator: "\n") + "\n").write(toFile: lines, atomically: true, encoding: .utf8)
        let fake = script(dir, "eslogger", "cat \(lines)\nexec sleep 600")
        let source = EsloggerSource(executable: fake, prefixes: ["/Users/alice/.ssh"])
        let sink = RecordingSink()
        try source.start(sink: sink)
        defer { source.stop() }
        XCTAssertNotNil(waitFor(3) { source.parserStats?.lines == 3 })
        XCTAssertEqual(source.parserStats?.malformed, 1)
        XCTAssertEqual(source.parserStats?.droppedByKernel, 0)
    }

    func testRestartedEsloggerStartsANewSequence() throws {
        let dir = TempDir()
        let marker = dir.path("ran-once")
        let first = dir.path("first.jsonl")
        let second = dir.path("second.jsonl")
        try ([exitLine(20_000_000), exitLine(20_000_001)].joined(separator: "\n") + "\n").write(toFile: first, atomically: true, encoding: .utf8)
        // The new client counts from 0; 2…4 are genuinely missing.
        try ([exitLine(0), exitLine(1), exitLine(5)].joined(separator: "\n") + "\n").write(toFile: second, atomically: true, encoding: .utf8)
        let fake = script(dir, "eslogger", """
            if [ ! -e \(marker) ]; then touch \(marker); cat \(first); exit 0; fi
            cat \(second)
            exec sleep 600
            """)
        let source = EsloggerSource(executable: fake, prefixes: [])
        let sink = RecordingSink()
        try source.start(sink: sink)
        defer { source.stop() }
        XCTAssertNotNil(waitFor(6) { sink.events.count == 5 }, "backoff relaunch did not deliver the second stream")
        XCTAssertEqual(source.parserStats?.droppedByKernel, 3)
    }

    func testReaddirToggleRestartsAtOnceWithoutError() throws {
        let dir = TempDir()
        let args = dir.path("args")
        let fake = script(dir, "eslogger", "echo \"$@\" >> \(args)\nexec sleep 600")
        let source = EsloggerSource(executable: fake, prefixes: [], readdir: false)
        let sink = RecordingSink()
        try source.start(sink: sink)
        defer { source.stop() }
        XCTAssertNotNil(waitFor(3) { lineCount(args) == 1 })
        let requested = Date()
        source.updateMonitoring(prefixes: ["/Users/alice/.ssh"], ancestors: [], readdir: true)
        XCTAssertNotNil(waitFor(3) { lineCount(args) == 2 && source.state.running })
        print("readdir toggle → new eslogger in \(String(format: "%.3f", Date().timeIntervalSince(requested))) s")
        let passed = try String(contentsOfFile: args, encoding: .utf8).split(separator: "\n")
        XCTAssertEqual(passed.last.map { $0.split(separator: " ").map(String.init) }, EsloggerSource.eventNames(readdir: true))
        // A requested restart is not a failure: no error state (the crash path always publishes one).
        XCTAssertTrue(sink.states.allSatisfy { $0.error == nil }, "\(sink.states)")
        XCTAssertNil(source.state.error)
        // A change that keeps the event list does not restart.
        source.updateMonitoring(prefixes: [], ancestors: [], readdir: true)
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(lineCount(args), 2)
    }

    func testFailedRelaunchIsRetried() throws {
        let dir = TempDir()
        let runs = dir.path("runs")
        let fake = dir.path("eslogger")
        // Exits at once and removes itself, so the 1 s relaunch fails to spawn.
        _ = script(dir, "eslogger", "echo run >> \(runs)\nmv \"$0\" \"$0.off\"\nexit 1")
        let source = EsloggerSource(executable: fake, prefixes: [])
        let sink = RecordingSink()
        try source.start(sink: sink)
        defer { source.stop() }
        XCTAssertNotNil(waitFor(3) { source.state.error?.hasPrefix("cannot start") == true }, "\(source.state)")
        XCTAssertEqual(lineCount(runs), 1)
        // Restore it: the next backoff attempt (2 s after the failed one) must start it again.
        try FileManager.default.moveItem(atPath: fake + ".off", toPath: fake)
        XCTAssertNotNil(waitFor(4) { lineCount(runs) == 2 }, "no retry after a failed relaunch")
    }
}

final class IngestSanitizerTests: XCTestCase {
    /// An eslogger-shaped line with a process object; `body` is the event body JSON.
    func line(_ kind: String, _ body: String, pid: Int, ppid: Int, originalPPID: Int? = nil, exe: String = "/bin/cat",
              team: String = "null") -> String {
        let opp = originalPPID ?? ppid
        return #"{"schema_version":1,"event":{"\#(kind)":\#(body)},"process":{"audit_token":{"pid":\#(pid)},"ppid":\#(ppid),"original_ppid":\#(opp),"signing_id":"x","team_id":\#(team),"executable":{"path":"\#(exe)"}}}"#
    }

    func open(_ path: String) -> String { #"{"fflag":1,"file":{"path":"\#(path)"}}"# }

    func testFirmlinkedUserDataIsNotASystemSample() {
        let s = FixtureSanitizer(home: "/Users/bob", samplePerKind: 10)
        let lines = [
            line("open", open(#"\/System\/Volumes\/Data\/Users\/bob\/Documents\/Divorce\/lawyer.pdf"#), pid: 700, ppid: 1,
                 exe: #"\/System\/Library\/Frameworks\/CoreServices.framework\/mdworker_shared"#),
            line("open", open("/System/Volumes/Data/private/var/folders/x7/abc/T/NSIRD_screencaptureui/Screenshot.png"), pid: 701, ppid: 1,
                 exe: "/usr/sbin/screencapture"),
            line("open", open("/usr/local/Cellar/secret-tool/bin/x"), pid: 702, ppid: 1),
            line("open", open("/System/Library/Fonts/Helvetica.ttc"), pid: 703, ppid: 1, exe: "/usr/bin/fontd"),
        ]
        let joined = s.sanitize(lines: lines).output.joined(separator: "\n")
        XCTAssertFalse(joined.contains("Divorce"))
        XCTAssertFalse(joined.contains("Screenshot"))
        XCTAssertFalse(joined.contains("secret-tool"), "/usr/local is user-writable")
        XCTAssertTrue(joined.contains("Helvetica.ttc"), "a genuine system sample survives")
    }

    func testSampleFromNonSystemProcessIsDropped() {
        let s = FixtureSanitizer(home: "/Users/bob", samplePerKind: 10)
        let lines = [
            line("open", open("/System/Library/Fonts/Helvetica.ttc"), pid: 800, ppid: 1, exe: "/Users/bob/dev/acme-merger/.build/debug/tool"),
            line("open", open("/usr/share/icu/icudt.dat"), pid: 801, ppid: 1,
                 exe: "/Applications/SecretDatingApp.app/Contents/MacOS/SecretDatingApp", team: #""ABCDE12345""#),
            line("open", open("/usr/share/icu/icudt.dat"), pid: 802, ppid: 1, exe: "/usr/bin/sort"),
        ]
        let joined = s.sanitize(lines: lines).output.joined(separator: "\n")
        XCTAssertFalse(joined.contains("acme-merger"))
        XCTAssertFalse(joined.contains("SecretDatingApp"))
        XCTAssertFalse(joined.contains("ABCDE12345"))
        XCTAssertTrue(joined.contains("/usr/bin/sort"))
    }

    func testUserNameAndTemporaryFolderAreRewritten() {
        let s = FixtureSanitizer(home: "/Users/bob")
        let raw = #"{"a":"\/private\/var\/db\/sudo\/ts\/bob","b":"/private/var/db/dslocal/nodes/Default/users/bob.plist","c":"bob","#
            + #""d":"\/private\/var\/folders\/x7\/q1w2e3r4t5_y6u7i8o9p0\/T\/k","e":"/System/Volumes/Data/private/var/folders/zz/abc123/T/x","#
            + #""f":"\/Users\/bob\/x","g":"/usr/lib/bobcat"}"#
        let out = s.rewrite(raw)
        XCTAssertFalse(out.contains("/bob\""), out)
        XCTAssertFalse(out.contains("bob.plist"), out)
        XCTAssertFalse(out.contains("\"bob\""), out)
        XCTAssertFalse(out.contains("q1w2e3r4t5"), out)
        XCTAssertFalse(out.contains("abc123"), out)
        XCTAssertTrue(out.contains(#"\/private\/var\/folders\/xx\/alice\/T\/k"#), out)
        XCTAssertTrue(out.contains("/private/var/folders/xx/alice/T/x"), out)
        XCTAssertTrue(out.contains(#"\/Users\/alice\/x"#), out)
        XCTAssertTrue(out.contains("/usr/lib/bobcat"), "only whole components are replaced")
        // Per-user places under /private/var/db are not system samples.
        let lines = [line("open", open("/private/var/db/dslocal/nodes/Default/users/bob.plist"), pid: 90, ppid: 1, exe: "/usr/libexec/opendirectoryd")]
        XCTAssertTrue(s.sanitize(lines: lines).output.isEmpty)
    }

    func testTemporaryFolderInVaultCommandArgumentsIsRewritten() {
        // capture-fixture.sh runs `cp -c "$VAULT/…" "$TMPDIR/whoread-clone-test"`: the exec is a vault event,
        // kept with its argv, and $TMPDIR is spelled /var/folders/… (no /private).
        let s = FixtureSanitizer(home: "/Users/bob")
        let cp = line("exec", #"{"args":["cp","-c","\/Users\/bob\/WhoReadTestVault\/aws\/credentials","\/var\/folders\/x7\/q1w2e3r4t5\/T\/\/whoread-clone-test"],"env":["TMPDIR=\/var\/folders\/x7\/q1w2e3r4t5\/T\/"],"cwd":{"path":"\/Users\/bob"},"target":{"audit_token":{"pid":600},"executable":{"path":"\/bin\/cp"}}}"#,
                      pid: 600, ppid: 400, exe: "/bin/zsh")
        let out = s.sanitize(lines: [cp]).output
        XCTAssertEqual(out.count, 1, "a vault event")
        let joined = out.joined()
        XCTAssertFalse(joined.contains("q1w2e3r4t5"), joined)
        XCTAssertTrue(joined.contains(#"\/var\/folders\/xx\/alice\/T\/\/whoread-clone-test"#), joined)
        XCTAssertTrue(s.rewrite("/var/folders/zz/abc123/T/x").hasSuffix("/var/folders/xx/alice/T/x"))
    }

    func testThirdPartyInventoryIsNotASystemSample() {
        let s = FixtureSanitizer(home: "/Users/bob", samplePerKind: 10)
        let lines = [
            // /Applications/Utilities on the data volume holds third-party apps (Apple's are in /System/Applications).
            line("open", open("/System/Library/Fonts/Helvetica.ttc"), pid: 601,
                 ppid: 1, exe: "/Applications/Utilities/SecretVPN.app/Contents/MacOS/SecretVPN", team: #""TEAMVPN123""#),
            line("open", open("/Library/Preferences/com.secretvpn.plist"), pid: 602, ppid: 1, exe: "/usr/sbin/cfprefsd"),
            line("open", open("/private/var/db/receipts/com.secretvpn.pkg.bom"), pid: 603, ppid: 1, exe: "/usr/sbin/installer"),
            // APFS is case-insensitive: /usr/LOCAL is /usr/local.
            line("open", open("/usr/LOCAL/Cellar/secret-tool/x"), pid: 604, ppid: 1),
            line("open", open("/System/Applications/Utilities/Terminal.app/Contents/Info.plist"), pid: 605, ppid: 1),
        ]
        let joined = s.sanitize(lines: lines).output.joined(separator: "\n")
        XCTAssertFalse(joined.lowercased().contains("secret"), joined)
        XCTAssertTrue(joined.contains("Terminal.app"), "Apple's own utilities are still system samples")
    }

    func testReparentedChildKeepsItsAncestry() {
        let vault = "/Users/bob/WhoReadTestVault/ssh/id_ed25519"
        func child(_ pid: Int, _ ppid: Int) -> String {
            #"{"audit_token":{"pid":\#(pid)},"ppid":\#(ppid),"original_ppid":\#(ppid),"executable":{"path":"/bin/zsh"}}"#
        }
        let forkSubshell = line("fork", #"{"child":\#(child(401, 400))}"#, pid: 400, ppid: 300, exe: "/bin/zsh")
        let forkCat = line("fork", #"{"child":\#(child(402, 401))}"#, pid: 401, ppid: 400, exe: "/bin/zsh")
        let subshellExit = line("exit", #"{"stat":0}"#, pid: 401, ppid: 400, exe: "/bin/zsh")
        // After the subshell exits, cat is reparented to launchd: ppid 1, original_ppid 401.
        let read = line("open", open(vault), pid: 402, ppid: 1, originalPPID: 401)
        let catExit = line("exit", #"{"stat":0}"#, pid: 402, ppid: 1, originalPPID: 401)
        let unrelated = line("exit", #"{"stat":0}"#, pid: 999, ppid: 300, exe: "/bin/zsh")
        let s = FixtureSanitizer(home: "/Users/bob")

        let out = s.sanitize(lines: [forkSubshell, forkCat, subshellExit, read, catExit, unrelated]).output
        XCTAssertEqual(out.count, 5, "every line but the unrelated exit")
        XCTAssertTrue(out.contains(s.rewrite(subshellExit)), "the subshell's exit survives the reparent")
        XCTAssertTrue(out.contains(s.rewrite(forkSubshell)))

        // Without the fork line (cat started before the capture), original_ppid links it.
        let out2 = s.sanitize(lines: [forkSubshell, subshellExit, read, catExit]).output
        XCTAssertEqual(out2.count, 4)
    }
}
