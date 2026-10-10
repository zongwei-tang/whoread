import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Regression tests for review round 2: native mute plan, denial backlog, kernel
// drops, live buffer ring, closes while enforcing, and creates without an open.

private let r2Key = "/Users/alice/.ssh/id_ed25519"
private let r2T = Date(timeIntervalSince1970: 1_760_000_000)

private func r2Core(_ dir: TempDir) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

/// Terminal → zsh → leaf, registered in the core's process tree.
private func r2TerminalChild(_ core: DaemonCore, _ leaf: ProcessRecord) -> ProcessRecord {
    core.tree.observe(proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, platform: true), at: r2T)
    core.tree.observe(proc(500, "/bin/zsh", ppid: 100, platform: true), at: r2T)
    var l = leaf
    l.ppid = 500
    l.originalPPID = 500
    core.tree.observe(l, at: r2T)
    return l
}

private func r2Activity(_ p: ProcessRecord, _ op: FileOperation, _ targets: [FileTarget], at t: TimeInterval = 100) -> FileActivity {
    FileActivity(time: r2T.addingTimeInterval(t), operation: op, process: p, targets: targets)
}

private func r2Event(_ id: Int64, benign: Bool = false) -> AnalyzedEvent {
    AnalyzedEvent(id: id, time: r2T, operation: .open, access: .read, path: r2Key, secondaryPath: nil, categoryID: "ssh",
                  severity: .critical, process: proc(501, "/bin/cat"), chain: [],
                  responsible: ResponsibleEntity(kind: .app, key: "app:x", displayName: "X"), agentID: nil, isOwner: false,
                  benignServiceID: benign ? "spotlight" : nil, decision: .observed, ruleID: nil)
}

/// eslogger line for a create of `path` (existing_file, with st_mode when given).
private func createLine(_ path: String, mode: Int?, seq: Int = 1) -> String {
    let stat = mode.map { #","stat":{"st_mode":\#($0)}"# } ?? ""
    return #"{"schema_version":1,"global_seq_num":\#(seq),"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/bin\/ln"}},"event":{"create":{"destination_type":0,"destination":{"existing_file":{"path":"\#(path)"\#(stat)}},"acl":null}}}"#
}

// MARK: - Native mute plan (engine-runtime-2, docs-consistency-2)

final class NativeMutePlanRound2Tests: XCTestCase {
    let homes = ["/Users/alice"]

    func testMutePlanNeverSelectsDevForALinkedPrefix() {
        // ~/.zsh_history -> /dev/null (history turned off): every /dev/null open must not be selected.
        let plan = NativeMutePlan.plan(prefixes: ["/Users/alice/.zsh_history"], ancestors: ["/Users/alice"], homes: homes,
                                       resolve: { $0 == "/Users/alice/.zsh_history" ? "/dev/null" : nil })
        XCTAssertEqual(plan.prefixes.map(\.path), ["/Users/alice/.zsh_history"])
        for target in ["/dev", "/DEV/fd/3"] {
            let p = NativeMutePlan.plan(prefixes: ["/Users/alice/.mysql_history"], ancestors: [], homes: homes, resolve: { _ in target })
            XCTAssertEqual(p.prefixes.map(\.path), ["/Users/alice/.mysql_history"], target)
        }
    }

    func testMutePlanSkipsAResolvedHomeOrAncestor() {
        for target in ["/Users/alice", "/Users", "/users/ALICE", "/Users/alice/notes"] {
            let plan = NativeMutePlan.plan(prefixes: ["/Users/alice/notes/link"], ancestors: [], homes: homes, resolve: { _ in target })
            XCTAssertEqual(plan.prefixes.map(\.path), ["/Users/alice/notes/link"], "\(target) would select a whole tree")
        }
        // A usable target (a dotfile manager's) is still registered, on-disk case included.
        let plan = NativeMutePlan.plan(prefixes: ["/Users/alice/.aws/credentials"], ancestors: [], homes: homes,
                                       resolve: { _ in "/Users/alice/Dotfiles/aws/credentials" })
        XCTAssertEqual(Set(plan.prefixes.map(\.path)), ["/Users/alice/.aws/credentials", "/Users/alice/Dotfiles/aws/credentials"])
    }

    func testMutePlanDropsPathsWithANul() {
        // The C string es_mute_path and realpath see ends at the NUL: "/Users/alice/" would be selected.
        var resolved: [String] = []
        let plan = NativeMutePlan.plan(prefixes: ["/Users/alice/\u{0}x", "/Users/alice/.ssh"], ancestors: ["/Users/alice/\u{0}y"],
                                       homes: homes, resolve: { resolved.append($0); return nil })
        XCTAssertEqual(plan.prefixes.map(\.path), ["/Users/alice/.ssh"])
        XCTAssertTrue(plan.literals.isEmpty)
        XCTAssertEqual(resolved, ["/Users/alice/.ssh"], "a NUL path is never resolved either")
    }

    func testMutePlanWithRealLinkToDevNull() throws {
        let dir = TempDir()
        let home = dir.path("home")
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let history = home + "/.zsh_history"
        try FileManager.default.createSymbolicLink(atPath: history, withDestinationPath: "/dev/null")
        let resolver = RealpathSymlinkResolver()
        XCTAssertEqual(resolver.resolve(history), "/dev/null")
        let plan = NativeMutePlan.plan(prefixes: [history], ancestors: [home], homes: [home], resolve: resolver.resolve)
        XCTAssertFalse(plan.prefixes.contains(NativeMutePlan.Path("/dev/null")))
        XCTAssertTrue(plan.prefixes.contains(NativeMutePlan.Path(history)))
    }
}

extension NativeMutePlanRound2Tests {
    /// The finding's path end to end: an unprivileged client's path rules go into the classifier, and
    /// the plan built from its spellings with the real resolver selects neither the home, /dev/null nor
    /// a NUL-cut path.
    func testMutePlanFromTheDaemonsClassifier() throws {
        let dir = TempDir()
        // Not under /tmp: the normalizer maps /tmp to /private/tmp, which only exists on macOS.
        let homeDir = repoRoot.appendingPathComponent(".build/r2-home-\(UUID().uuidString.prefix(8))").path
        defer { try? FileManager.default.removeItem(atPath: homeDir) }
        try FileManager.default.createDirectory(atPath: homeDir + "/.ssh", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: homeDir + "/.lesshst", withDestinationPath: "/dev/null")
        try FileManager.default.createSymbolicLink(atPath: homeDir + "/hl", withDestinationPath: homeDir)
        var config = baseConfig(dir)
        config.homeDirectories = [homeDir]
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        // The daemon refuses both for an unprivileged peer (the link resolves to the home itself; NUL is invalid).
        for (id, p) in [("link-to-home", "~/hl"), ("nul", "~/\u{0}x")] {
            XCTAssertThrowsError(try core.upsert(rule: Rule(id: id, enabled: true, enforce: false, target: .pathPrefix(p),
                                                            subject: .anyNonOwner, access: .any, action: .deny),
                                                 peer: .inProcess, privileged: false))
        }
        // Defence in depth: even if such spellings reach the catalog (privileged edit) or the prefix list,
        // the mute plan never selects the home, /dev/null, / or a NUL spelling.
        var catalog = core.data.catalog
        let custom = catalog.categories.firstIndex { $0.id == "custom" }!
        catalog.categories[custom].paths.append("~/hl")
        catalog.categories[custom].enabled = true
        try core.update(catalog: catalog, peer: .inProcess)
        let c = core.analyzer.classifier
        XCTAssertTrue(c.mutePaths.contains(homeDir + "/hl"))
        let plan = NativeMutePlan.plan(prefixes: c.mutePaths + [homeDir + "/\u{0}x"], ancestors: c.ancestors,
                                       homes: c.normalizer.homeDirectories, resolve: RealpathSymlinkResolver().resolve)
        let prefixes = Set(plan.prefixes.map(\.path))
        XCTAssertTrue(prefixes.contains(homeDir + "/.ssh"))
        XCTAssertTrue(prefixes.contains(homeDir + "/.lesshst"))
        for selectsTooMuch in [homeDir, homeDir + "/", "/dev/null", "/"] {
            XCTAssertFalse(prefixes.contains(selectsTooMuch), selectsTooMuch)
        }
        XCTAssertFalse(prefixes.contains { $0.utf8.contains(0) })
        XCTAssertFalse(plan.literals.contains { $0.path.utf8.contains(0) })
    }
}

// MARK: - Denial backlog and live buffer (engine-runtime-8)

final class DenialBacklogRound2Tests: XCTestCase {
    func key(_ path: String, pid: Int32 = 601, rule: String? = "deny-ssh", fflag: UInt32 = 1) -> NativeDenialBacklog.Key {
        NativeDenialBacklog.Key(r2Activity(proc(pid, "/bin/cat"), .open, OperationSemantics.open(path: path, fflag: fflag)),
                                RuleDecision(verdict: .deny, reason: .explicitDeny, ruleID: rule))
    }

    func testEveryDenialIsQueuedWhileTheBacklogIsShort() {
        var b = NativeDenialBacklog()
        var keyBuilt = false
        for _ in 0..<NativeDenialBacklog.mergeThreshold {
            XCTAssertNotNil(b.admit { keyBuilt = true; return key(r2Key) })
        }
        XCTAssertFalse(keyBuilt, "no key work on the callback below the threshold")
        XCTAssertEqual(b.pending, NativeDenialBacklog.mergeThreshold)
        XCTAssertEqual(b.unrecorded, 0)
    }

    func testRepeatsPastTheThresholdMergeIntoTheQueuedOne() throws {
        var b = NativeDenialBacklog()
        let early = (0..<NativeDenialBacklog.mergeThreshold).compactMap { _ in b.admit { key(r2Key) } }
        // A process looping on the same denied open: one more queued, the rest merged and counted.
        let first = try XCTUnwrap(b.admit { key(r2Key) })
        for _ in 0..<500 { XCTAssertNil(b.admit { key(r2Key) }) }
        XCTAssertEqual(b.pending, NativeDenialBacklog.mergeThreshold + 1)
        XCTAssertEqual(b.unrecorded, 500)
        // Other denials (another path, process instance or rule) are still recorded.
        XCTAssertNotNil(b.admit { key("/Users/alice/.ssh/config") })
        XCTAssertNotNil(b.admit { key(r2Key, pid: 602) })
        XCTAssertNotNil(b.admit { key(r2Key, rule: "other") })
        // A denied write is not hidden behind a queued denied read of the same file.
        XCTAssertNotNil(b.admit { key(r2Key, fflag: 3) })
        XCTAssertNil(b.admit { key(r2Key, fflag: 3) })
        // Once the queued one is recorded, the next repeat is queued again.
        b.finish(first)
        XCTAssertNotNil(b.admit { key(r2Key) })
        XCTAssertNil(b.admit { key(r2Key) })
        early.forEach { b.finish($0) }
        XCTAssertEqual(b.pending, 5)
    }

    func testPastTheLimitDenialsAreOnlyCounted() throws {
        var b = NativeDenialBacklog()
        var tickets: [NativeDenialBacklog.Ticket] = []
        for i in 0..<NativeDenialBacklog.limit {
            tickets.append(try XCTUnwrap(b.admit { key("/Users/alice/.ssh/k\(i)") }))
        }
        XCTAssertNil(b.admit { key("/Users/alice/.ssh/new") })
        XCTAssertEqual(b.unrecorded, 1)
        XCTAssertEqual(b.pending, NativeDenialBacklog.limit)
        b.finish(tickets.removeLast())
        XCTAssertNotNil(b.admit { key("/Users/alice/.ssh/new") })
    }

    func testLiveBufferRingKeepsTheNewestInOrder() {
        let live = LiveBuffer(capacity: 5)
        XCTAssertNil(live.newest)
        live.append((1...3).map { r2Event($0) })
        XCTAssertEqual(live.after(nil, limit: 10, includeBenign: true).map(\.id), [1, 2, 3])
        live.append((4...8).map { r2Event($0, benign: $0 == 7) })
        XCTAssertEqual(live.after(nil, limit: 10, includeBenign: true).map(\.id), [4, 5, 6, 7, 8])
        XCTAssertEqual(live.newest?.id, 8)
        XCTAssertEqual(live.after(nil, limit: 10, includeBenign: false).map(\.id), [4, 5, 6, 8])
        XCTAssertEqual(live.after(5, limit: 10, includeBenign: true).map(\.id), [6, 7, 8])
        XCTAssertEqual(live.after(nil, limit: 2, includeBenign: false).map(\.id), [6, 8], "the newest matches, oldest first")
        XCTAssertEqual(live.after(nil, limit: 0, includeBenign: true).map(\.id), [])
        // A batch larger than the ring keeps its newest events.
        live.append((9...20).map { r2Event($0) })
        XCTAssertEqual(live.after(nil, limit: 10, includeBenign: true).map(\.id), [16, 17, 18, 19, 20])
        for id in 21...23 { live.append([r2Event(Int64(id))]) }
        XCTAssertEqual(live.after(nil, limit: 10, includeBenign: true).map(\.id), [19, 20, 21, 22, 23])
        XCTAssertEqual(live.newest?.id, 23)
        let none = LiveBuffer(capacity: 0)
        none.append([r2Event(1)])
        XCTAssertNil(none.newest)
    }
}

// MARK: - Kernel drops (docs-consistency-6)

final class KernelDropRound2Tests: XCTestCase {
    func testSequenceGapsCountMissingMessages() {
        var g = NativeSequenceGaps()
        for s: UInt64 in [10, 11, 12, 15, 16, 20] { g.note(s) }
        XCTAssertEqual(g.dropped, 2 + 3)
        // A new client starts again from a low number: not a drop.
        g.reset()
        g.note(0)
        g.note(1)
        XCTAssertEqual(g.dropped, 5)
        g.note(1)
        g.note(0)
        XCTAssertEqual(g.dropped, 5, "no negative or duplicate gaps")
    }

    func testKernelDropsDefaultToTheParserCount() throws {
        XCTAssertNil(FakeSource(canEnforce: false).kernelDroppedEvents)
        let dir = TempDir()
        let file = dir.path("seq.jsonl")
        try ([1, 2, 5, 6].map { exitLine($0) }.joined(separator: "\n") + "\n").write(toFile: file, atomically: false, encoding: .utf8)
        let source = ReplaySource(path: file)
        try source.start(sink: RecordingSink())
        XCTAssertTrue(source.waitUntilFinished())
        XCTAssertEqual(source.kernelDroppedEvents, 2)
        XCTAssertEqual(source.kernelDroppedEvents, source.parserStats?.droppedByKernel)
    }
}

// MARK: - Closes while enforcing (engine-runtime-3)

final class CloseWhileEnforcingRound2Tests: XCTestCase {
    /// The native source sends a modified close as `.afterAuth` while AUTH is subscribed and enforcement
    /// is live: it must neither use up an "allow once" nor turn the alert into "would block".
    func testModifiedCloseAfterAuthKeepsAllowOnceAndAlertKind() throws {
        let dir = TempDir()
        let core = try r2Core(dir)
        try core.setRules([Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                                access: .any, action: .deny, includePlatformBinaries: true)])
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        core.drainPolicyQueue()
        let vi = r2TerminalChild(core, proc(501, "/usr/bin/vim", platform: true))
        let open = r2Activity(vi, .open, OperationSemantics.open(path: r2Key, fflag: 3))
        let denied = core.enforcer.decide(open)
        XCTAssertEqual(denied.verdict, .deny)
        core.pipeline.receive(.file(open), context: .decided(denied))
        core.writer.flush()
        let blocked = try XCTUnwrap(core.store.alerts(AlertQuery()).first { $0.kind == .blocked })
        try core.apply(action: .allowOnce, toAlert: blocked.id, peer: .inProcess)

        // Variant: a modified close of an older fd lands between the click and the retry.
        let close = r2Activity(vi, .close, OperationSemantics.close(path: r2Key, modified: true), at: 101)
        core.pipeline.receive(.file(close), context: .afterAuth)
        let retry = r2Activity(vi, .open, OperationSemantics.open(path: r2Key, fflag: 3), at: 102)
        XCTAssertEqual(core.enforcer.decide(retry).verdict, .allow, "the close did not use up the allow once")

        // Normal flow: the retried open and its close are allowed accesses with a rule alert, never "would block".
        core.pipeline.receive(.file(retry), context: .afterAuth)
        core.pipeline.receive(.file(r2Activity(vi, .close, OperationSemantics.close(path: r2Key, modified: true), at: 103)),
                              context: .afterAuth)
        core.writer.flush()
        let events = try core.store.events(EventQuery(includeBenign: true, limit: 10, newestFirst: false))
        XCTAssertEqual(events.map(\.decision), [.denied, .allowed, .allowed, .allowed])
        let alerts = try core.store.alerts(AlertQuery())
        XCTAssertFalse(alerts.contains { $0.kind == .wouldBlock }, "\(alerts.map(\.kind))")
    }
}

// MARK: - Creates without an open (engine-runtime-7)

final class CreateEventsRound2Tests: XCTestCase {
    func testEsloggerSubscribesCreate() {
        XCTAssertTrue(EsloggerSource.eventNames(readdir: false).contains("create"))
        XCTAssertTrue(EsloggerSource.eventNames(readdir: true).contains("create"))
    }

    func testParserRecordsCreatesOfLinksDirectoriesAndNodesOnly() {
        let p = EsloggerParser()
        func activity(_ line: String) -> FileActivity? {
            if case .event(.file(let f)) = p.parse(line: line) { return f }
            return nil
        }
        let symlink = activity(createLine("/Users/alice/.ssh/authorized_keys", mode: 0o120755))
        XCTAssertEqual(symlink?.operation, .create)
        XCTAssertEqual(symlink?.targets.map(\.path), ["/Users/alice/.ssh/authorized_keys"])
        XCTAssertEqual(symlink?.targets.first?.access, .write)
        XCTAssertNotNil(activity(createLine("/Users/alice/.ssh/keys", mode: 0o040755)), "mkdir")
        XCTAssertNotNil(activity(createLine("/Users/alice/.ssh/fifo", mode: 0o010644)), "mkfifo")
        XCTAssertNotNil(activity(createLine("/Users/alice/.ssh/x", mode: nil)), "unknown type is kept")
        // A new regular file is recorded by its creating open.
        guard case .ignored = p.parse(line: createLine("/Users/alice/.ssh/id_new", mode: 0o100600)) else {
            return XCTFail("a regular-file create doubles the creating open")
        }
    }

    func testPrefilterTestsExistingFileCreatesByPrefix() {
        let filter = LinePrefilter(prefixes: ["/Users/alice/.ssh"])
        XCTAssertEqual(filter.verdict(createLine(#"\/Users\/alice\/.ssh\/authorized_keys"#, mode: 0o120755)), .parse)
        XCTAssertEqual(filter.verdict(createLine("/Users/alice/.ssh/authorized_keys", mode: 0o120755)), .parse)
        XCTAssertEqual(filter.verdict(createLine(#"\/Users\/alice\/Library\/Caches\/x.tmp"#, mode: 0o100644)), .drop,
                       "every file creation on the system is a create: not parsed unless it can matter")
        let newPath = #"{"schema_version":1,"process":{"audit_token":{"pid":501},"executable":{"path":"\/bin\/ln"}},"event":{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/Users\/alice"},"filename":".ssh","mode":448}}}}}"#
        XCTAssertEqual(filter.verdict(newPath), .parse, "dir + name: the prefix may not appear")
    }

    func testSymlinkCreateInAMonitoredDirectoryIsRecorded() throws {
        let dir = TempDir()
        let core = try r2Core(dir)
        let ln = r2TerminalChild(core, proc(501, "/bin/ln", platform: true))
        let create = r2Activity(ln, .create, OperationSemantics.create(ReportedPath("/Users/alice/.ssh/authorized_keys")))
        core.pipeline.receive(.file(create), context: .monitorOnly)
        core.writer.flush()
        let event = try XCTUnwrap(core.store.events(EventQuery(includeBenign: true)).first)
        XCTAssertEqual(event.operation, .create)
        XCTAssertEqual(event.categoryID, "ssh")
        XCTAssertEqual(event.access, .write)
    }
}
