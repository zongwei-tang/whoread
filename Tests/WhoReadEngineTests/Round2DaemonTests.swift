import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine

// Regression tests for review round 2, at DaemonCore / ServiceHandler level.

private let r2T = Date(timeIntervalSince1970: 1_760_000_000)
private let r2RootPeer = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)
private let r2AgentPeer = IPCPeer(pid: 4242, euid: 501, isTrustedCode: false)

private func r2Core(_ dir: TempDir, _ configure: (inout DaemonConfiguration) -> Void = { _ in }) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    configure(&config)
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

private func r2Handler(_ core: DaemonCore) -> ServiceHandler {
    let h = ServiceHandler(daemon: core, policy: .strict)
    h.consoleUID = { 501 }
    return h
}

private func r2Error(_ r: IPCResponse) -> IPCError? {
    if case .error(let e) = r { return e }
    return nil
}

private func r2Rule(_ id: String, _ target: RuleTarget = .category("ssh"), action: RuleAction = .deny) -> Rule {
    Rule(id: id, enabled: true, enforce: true, target: target, subject: .anyNonOwner, action: action, includePlatformBinaries: true)
}

private func r2Alert(id: Int64, kind: AlertKind = .criticalNonOwner, category: String = "ssh",
                     responsible: ResponsibleEntity = ResponsibleEntity(kind: .app, key: "app:/applications/x.app", displayName: "X"),
                     ruleID: String? = nil) -> Alert {
    let path = "/Users/alice/.ssh/id_ed25519"
    return Alert(id: id, kind: kind, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date().addingTimeInterval(600),
                 responsible: responsible, categoryID: category, severity: .critical, count: 1, accesses: .read, firstPath: path,
                 firstEventID: 1, lastEventID: 1, paths: [path], chain: [], agentID: nil, ruleID: ruleID)
}

private func r2Rows(_ core: DaemonCore, _ table: String) throws -> [(id: String, body: String)] {
    var out: [(String, String)] = []
    try SQLiteDatabase(path: core.config.databasePath).prepare("SELECT id, body FROM \(table) ORDER BY rowid").query { row in
        out.append((row.text(0) ?? "", String(decoding: row.blob(1), as: UTF8.self)))
    }
    return out
}

// MARK: - Rule-load failure (store-ipc-cli-1, engine-runtime-6)

final class RuleLoadFailureRound2Tests: XCTestCase {
    func testAfterARuleLoadFailureOnlyAnExplicitReplacementOverwritesTheRules() throws {
        let dir = TempDir()
        let future = #"{"id":"b","target":{"category":"ssh"},"subject":{"type":"teamOnly"},"action":"alert"}"#
        do {
            let core = try r2Core(dir)
            try core.setRules([r2Rule("a"), r2Rule("b", action: .alert)])
            // Rule b as a newer WhoRead would have written it.
            try SQLiteDatabase(path: core.config.databasePath).exec("UPDATE rules SET body = CAST('\(future)' AS BLOB) WHERE id = 'b';")
        }
        let core = try r2Core(dir)
        XCTAssertNotNil(core.status().rulesLoadError)
        XCTAssertTrue(core.rules.rules.isEmpty)
        let handler = r2Handler(core)
        try core.store.upsert([r2Alert(id: 1), r2Alert(id: 2, kind: .blocked, ruleID: "a")])

        // No single-rule change, from root or the app, rewrites the table from the empty stand-in.
        let c = r2Rule("c")
        let refused: [(IPCRequest, String)] = [
            (.upsertRule(c), "add a rule"), (.upsertRule(r2Rule("p", .pathPrefix("~/Documents/p"))), "add a path rule"),
            (.deleteRule(id: "a"), "delete"), (.alertAction(alertID: 1, action: .blockFromNowOn), "block from now on"),
            (.alertAction(alertID: 2, action: .allowOnce), "allow once"), (.alertAction(alertID: 2, action: .alwaysAllow), "always allow"),
        ]
        for (request, what) in refused {
            let e = r2Error(handler.handle(request, peer: r2RootPeer))
            XCTAssertEqual(e?.code, .invalid, what)
            XCTAssertTrue(e?.message.contains("rules replace") == true, "\(what): \(e?.message ?? "")")
        }
        XCTAssertThrowsError(try core.upsert(rule: c, peer: .inProcess)) { e in XCTAssertEqual((e as? IPCError)?.code, .invalid) }
        XCTAssertNil(core.data.catalog.category("custom")?.paths.first { $0 == "~/Documents/p" }, "the catalog was not changed either")
        XCTAssertEqual(try r2Rows(core, "rules").map(\.id), ["a", "b"])
        XCTAssertEqual(try r2Rows(core, "rules")[1].body, future, "untouched")
        XCTAssertTrue(core.enforcement.inactiveReasons.contains(.rulesFailedToLoad))

        // The explicit replacement: weakening, so root or the app only.
        XCTAssertEqual(handler.privilege(of: .replaceRules([c])), .weaken)
        XCTAssertEqual(r2Error(handler.handle(.replaceRules([c]), peer: r2AgentPeer))?.code, .notPermitted)
        guard case .rules(let replaced) = handler.handle(.replaceRules([c]), peer: r2RootPeer) else { return XCTFail("refused") }
        XCTAssertEqual(replaced.map(\.id), ["c"])
        XCTAssertNil(core.status().rulesLoadError)
        XCTAssertFalse(core.enforcement.inactiveReasons.contains(.rulesFailedToLoad))
        XCTAssertEqual(try core.store.loadRules()?.map(\.id), ["c"])
        let backup = try r2Rows(core, "rules_backup")
        XCTAssertEqual(backup.map(\.id), ["a", "b"], "every old row is kept")
        XCTAssertEqual(backup[1].body, future)
        // Single-rule changes work again.
        XCTAssertNil(r2Error(handler.handle(.upsertRule(r2Rule("d")), peer: r2RootPeer)))
        XCTAssertEqual(core.rules.rules.map(\.id), ["c", "d"])
    }

    func testAFailedReplacementLeavesTheStoredRulesAlone() throws {
        let dir = TempDir()
        let future = #"{"id":"future","target":{"category":"ssh"},"subject":{"type":"teamOnly"},"action":"deny"}"#
        do {
            let core = try r2Core(dir)
            try core.setRules([r2Rule("a")])
            try SQLiteDatabase(path: core.config.databasePath)
                .exec("INSERT INTO rules(id, position, body) VALUES('future', 1, CAST('\(future)' AS BLOB));")
        }
        let core = try r2Core(dir)
        XCTAssertNotNil(core.status().rulesLoadError)
        let db = try SQLiteDatabase(path: core.config.databasePath)
        try db.exec("CREATE TRIGGER fail_backup BEFORE INSERT ON rules_backup BEGIN SELECT RAISE(ABORT, 'disk full'); END;")
        var c = r2Rule("c")
        c.exceptions = [RuleException(subject: .anyNonOwner, expiresAt: Date().addingTimeInterval(60))]
        let handler = r2Handler(core)
        XCTAssertEqual(r2Error(handler.handle(.replaceRules([c]), peer: r2RootPeer))?.code, .internalError)
        XCTAssertNotNil(core.status().rulesLoadError, "still failed")
        XCTAssertTrue(core.enforcement.inactiveReasons.contains(.rulesFailedToLoad))
        try db.exec("DROP TRIGGER fail_backup;")
        // Maintenance would prune c's expired exception and save the list it has in memory.
        core.saveConsumableRules(now: Date().addingTimeInterval(3600))
        XCTAssertEqual(r2Error(handler.handle(.upsertRule(r2Rule("d")), peer: r2RootPeer))?.code, .invalid)
        XCTAssertEqual(try r2Rows(core, "rules").map(\.id), ["a", "future"])
    }

    func testAnEmptyReplacementIsKeptAcrossRestarts() throws {
        let dir = TempDir()
        let future = #"{"id":"b","target":{"category":"ssh"},"subject":{"type":"teamOnly"},"action":"alert"}"#
        do {
            let core = try r2Core(dir)
            try core.setRules([r2Rule("a"), r2Rule("b", action: .alert)])
            try SQLiteDatabase(path: core.config.databasePath).exec("UPDATE rules SET body = CAST('\(future)' AS BLOB) WHERE id = 'b';")
        }
        let core = try r2Core(dir)
        XCTAssertNotNil(core.status().rulesLoadError)
        XCTAssertNoThrow(try core.update(catalog: nil, peer: .inProcess), "catalog edits never touch the rules")
        XCTAssertEqual(try r2Rows(core, "rules").map(\.id), ["a", "b"])
        XCTAssertNil(r2Error(r2Handler(core).handle(.replaceRules([]), peer: r2RootPeer)))
        XCTAssertEqual(try r2Rows(core, "rules_backup").map(\.id), ["a", "b"])
        let restarted = try r2Core(dir)
        XCTAssertNil(restarted.status().rulesLoadError)
        XCTAssertTrue(restarted.rules.rules.isEmpty, "no templates in place of the explicit empty list")
    }

    func testReplaceRulesChecksTheListLikeUpsert() throws {
        let dir = TempDir()
        let core = try r2Core(dir)
        try core.setRules([r2Rule("keep")])
        let handler = r2Handler(core)
        func code(_ list: [Rule]) -> IPCError.Code? { r2Error(handler.handle(.replaceRules(list), peer: r2RootPeer))?.code }
        XCTAssertEqual(code([r2Rule("x", .category("gone"))]), .invalid, "unknown category")
        XCTAssertEqual(code([r2Rule("x"), r2Rule("x")]), .invalid, "duplicate ids")
        XCTAssertEqual(code((0...DaemonCore.maxRules).map { r2Rule("r\($0)") }), .invalid, "too many")
        XCTAssertEqual(code([r2Rule("x", .pathPrefix("~/a\u{0}b"))]), .invalid, "invalid rule")
        XCTAssertEqual(core.rules.rules.map(\.id), ["keep"])
        // Path rules are monitored, as with upsert.
        XCTAssertNil(code([r2Rule("secret", .pathPrefix("~/Documents/secret"))]))
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/Documents/secret/a.pdf")?.categoryID, "custom")
        XCTAssertEqual(core.rules.rules.map(\.id), ["secret"])
    }
}

// MARK: - Rule validation (store-ipc-cli-2, engine-runtime-2)

final class RuleValidationRound2Tests: XCTestCase {
    private func invalid(_ r: Rule, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try DaemonCore.validate(r), what, file: file, line: line) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid, file: file, line: line)
        }
    }

    // store-ipc-cli-2
    func testRuleDatesTheStoreCannotRoundTripAreRefused() throws {
        let ok = r2Rule("ok")
        var r = ok
        r.createdAt = Date(timeIntervalSince1970: 1e12); invalid(r, "5-digit year")
        r = ok; r.createdAt = Date(timeIntervalSince1970: -1); invalid(r, "before 1970")
        r = ok; r.expiresAt = Date(timeIntervalSince1970: 253_402_300_800); invalid(r, "year 10000")
        r = ok; r.exceptions = [RuleException(subject: .anyNonOwner, createdAt: Date(timeIntervalSince1970: 1e300))]; invalid(r, "huge")
        r = ok; r.exceptions = [RuleException(subject: .anyNonOwner, expiresAt: Date(timeIntervalSince1970: 1e12))]; invalid(r, "exception expiry")
        r = ok; r.createdAt = Date(timeIntervalSince1970: 0); r.expiresAt = Date(timeIntervalSince1970: 253_402_300_799)
        XCTAssertNoThrow(try DaemonCore.validate(r), "the edges of the range")

        // A raw request from the console user (a "strengthening" new alert rule) is refused before
        // anything encodes it, and the rules stay readable.
        let dir = TempDir()
        let core = try r2Core(dir)
        let handler = r2Handler(core)
        for date in ["1e12", "1e300"] {
            let raw = #"{"upsertRule":{"_0":{"id":"x1","target":{"category":"ssh"},"subject":{"type":"anyNonOwner"},"action":"alert","createdAt":"#
                + date + "}}}"
            let reply = try IPCCodec.decodeResponse(IPCCodec.serve(Data(raw.utf8), handler: handler, peer: r2AgentPeer))
            XCTAssertEqual(r2Error(reply)?.code, .invalid, date)
        }
        XCTAssertFalse(core.rules.rules.contains { $0.id == "x1" })
        // The rule list is for root and the app (privacy-1: rules made from alerts name apps and files).
        let client = InProcessClient(handler: handler, peer: r2RootPeer)
        XCTAssertNoThrow(try client.rules())
        XCTAssertNil(try r2Core(dir).status().rulesLoadError)
    }

    // engine-runtime-2
    func testControlCharactersInRuleAndCatalogPathsAreRefused() throws {
        let ok = r2Rule("ok", .pathPrefix("~/Café/notes"))
        XCTAssertNoThrow(try DaemonCore.validate(ok))
        for p in ["~/\u{0}x", "~/a\nb", "/Users/alice/a\u{7F}", "~/a\u{85}b"] {
            var r = ok
            r.target = .pathPrefix(p); invalid(r, p.debugDescription)
        }
        // Exception paths only refuse NUL: "allow once" copies event paths, which may name Finder's "Icon\r".
        var r = ok
        r.exceptions = [RuleException(subject: .anyNonOwner, pathPrefix: "/Users/alice/\u{0}x")]; invalid(r, "exception NUL")
        r.exceptions = [RuleException(subject: .anyNonOwner, pathPrefix: "/Users/alice/Documents/secret/Icon\r")]
        XCTAssertNoThrow(try DaemonCore.validate(r))

        let dir = TempDir()
        let core = try r2Core(dir)
        let handler = r2Handler(core)
        let before = core.data.catalog
        XCTAssertEqual(r2Error(handler.handle(.upsertRule(r2Rule("nul", .pathPrefix("~/\u{0}x"))), peer: r2AgentPeer))?.code, .invalid)
        XCTAssertEqual(core.data.catalog, before)
        var catalog = before
        let i = try XCTUnwrap(catalog.categories.firstIndex { $0.kind == .custom })
        catalog.categories[i].paths = ["~/\u{0}x"]
        catalog.categories[i].enabled = true
        XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess)) { e in XCTAssertEqual((e as? IPCError)?.code, .invalid) }
        XCTAssertEqual(r2Error(handler.handle(.updateCatalog(catalog), peer: r2RootPeer))?.code, .invalid)
        XCTAssertEqual(core.data.catalog, before)
        XCTAssertFalse(core.analyzer.classifier.mutePaths.contains("/Users/alice"))
    }
}

// MARK: - Path rules and the catalog (engine-runtime-1, engine-runtime-4)

final class PathRuleRound2Tests: XCTestCase {
    // engine-runtime-1. The home must exist on disk and lie outside /tmp (the normalizer maps /tmp to
    // /private/tmp, which Linux does not have), so it goes in the build directory.
    func testUnprivilegedPathRulesAreCheckedWhereTheyResolve() throws {
        let root = repoRoot.appendingPathComponent(".build/r2-homes-\(UUID().uuidString.prefix(8))")
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("alice").path
        let fm = FileManager.default
        try fm.createDirectory(atPath: home + "/real", withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: home + "/link", withDestinationPath: "/usr/lib")
        try fm.createSymbolicLink(atPath: home + "/inside", withDestinationPath: home + "/real")
        try fm.createSymbolicLink(atPath: home + "/self", withDestinationPath: home)
        try fm.createSymbolicLink(atPath: home + "/dangling", withDestinationPath: "/nonexistent-whoread-r2/x")

        let resolver = RealpathSymlinkResolver()
        let usrLib = try XCTUnwrap(resolver.resolve("/usr/lib"))
        XCTAssertEqual(DaemonCore.resolveExisting(home + "/link/none/x", resolver: resolver), usrLib + "/none/x")
        XCTAssertEqual(DaemonCore.resolveExisting(home + "/new/x", resolver: resolver), resolver.resolve(home)! + "/new/x")
        XCTAssertNil(DaemonCore.resolveExisting(home + "/dangling/x", resolver: resolver))

        let dir = TempDir()
        let core = try r2Core(dir) { $0.homeDirectories = [home] }
        let handler = r2Handler(core)
        let before = core.data.catalog
        for (i, p) in ["~/link", "~/link/none", "~/self", "~/dangling", "/usr/lib"].enumerated() {
            XCTAssertEqual(r2Error(handler.handle(.upsertRule(r2Rule("sys\(i)", .pathPrefix(p))), peer: r2AgentPeer))?.code,
                           .notPermitted, p)
        }
        XCTAssertEqual(core.data.catalog, before)
        XCTAssertNil(core.analyzer.classifier.classify(usrLib + "/libc.so"))
        for (i, p) in ["~/inside", "~/new/folder", "/Volumes/USB/secret"].enumerated() {
            XCTAssertNil(r2Error(handler.handle(.upsertRule(r2Rule("own\(i)", .pathPrefix(p))), peer: r2AgentPeer)), p)
        }
        XCTAssertNil(r2Error(handler.handle(.upsertRule(r2Rule("sys", .pathPrefix("~/link"))), peer: r2RootPeer)), "root may")
    }

    // engine-runtime-1: link chains and links to files or to the homes' parent are resolved too; a
    // home whose own path goes through a link still accepts its folders.
    func testUnprivilegedPathRuleChecksFollowLinkChainsAndHomesBehindLinks() throws {
        let root = repoRoot.appendingPathComponent(".build/r2-homes-\(UUID().uuidString.prefix(8))")
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default
        try fm.createDirectory(atPath: root.path + "/real/alice/Documents", withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: root.path + "/link", withDestinationPath: root.path + "/real")
        let home = root.path + "/link/alice"
        try fm.createSymbolicLink(atPath: home + "/b", withDestinationPath: "/usr/lib")
        try fm.createSymbolicLink(atPath: home + "/a", withDestinationPath: home + "/b")
        try fm.createSymbolicLink(atPath: home + "/f", withDestinationPath: "/etc/passwd")
        try fm.createSymbolicLink(atPath: home + "/up", withDestinationPath: root.path + "/real")

        let dir = TempDir()
        let core = try r2Core(dir) { $0.homeDirectories = [home] }
        let handler = r2Handler(core)
        for (i, p) in ["~/a", "~/a/x", "~/f", "~/up", "~/up/x"].enumerated() {
            XCTAssertEqual(r2Error(handler.handle(.upsertRule(r2Rule("sys\(i)", .pathPrefix(p))), peer: r2AgentPeer))?.code,
                           .notPermitted, p)
        }
        for (i, p) in ["~/Documents/x", "~/new"].enumerated() {
            XCTAssertNil(r2Error(handler.handle(.upsertRule(r2Rule("own\(i)", .pathPrefix(p))), peer: r2AgentPeer)), p)
        }
    }

    // engine-runtime-4
    func testCatalogEditsThatWouldOrphanPathRulesAreRefused() throws {
        let dir = TempDir()
        let core = try r2Core(dir)
        let secret = r2Rule("deny-secret", .pathPrefix("~/Documents/secret"))
        try core.upsert(rule: secret, peer: .inProcess)
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        core.drainPolicyQueue()
        core.tree.observe(proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", platform: true), at: r2T)
        let cat = proc(501, "/bin/cat", ppid: 100, platform: true)
        core.tree.observe(cat, at: r2T)
        let open = FileActivity(time: r2T.addingTimeInterval(1), operation: .open, process: cat,
                                targets: OperationSemantics.open(path: "/Users/alice/Documents/secret/taxes.pdf", fflag: 1))
        XCTAssertEqual(core.enforcer.decide(open).verdict, .deny)

        let custom = try XCTUnwrap(core.data.catalog.categories.firstIndex { $0.kind == .custom })
        var removed = core.data.catalog
        removed.categories[custom].paths.removeAll { $0 == "~/Documents/secret" }
        var disabled = core.data.catalog
        disabled.categories[custom].enabled = false
        for (catalog, what) in [(nil, "catalog reset"), (removed, "path removed"), (disabled, "Custom disabled")] as [(Catalog?, String)] {
            XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess), what) { e in
                XCTAssertEqual((e as? IPCError)?.code, .invalid, what)
                XCTAssertTrue((e as? IPCError)?.message.contains("deny-secret") == true, what)
            }
        }
        XCTAssertEqual(r2Error(r2Handler(core).handle(.resetCatalog, peer: r2RootPeer))?.code, .invalid)
        XCTAssertEqual(core.enforcer.decide(open).verdict, .deny, "still protected")

        // A path covered by a default category: disabling that category orphans it too.
        try core.upsert(rule: r2Rule("deny-keys", .pathPrefix("~/.ssh/keys")), peer: .inProcess)
        var sshOff = core.data.catalog
        sshOff.categories[try XCTUnwrap(sshOff.categories.firstIndex { $0.id == "ssh" })].enabled = false
        XCTAssertThrowsError(try core.update(catalog: sshOff, peer: .inProcess)) { e in
            XCTAssertTrue((e as? IPCError)?.message.contains("deny-keys") == true)
        }

        // Disabled rules, and rules that were not monitored before, do not block an edit.
        var off = secret
        off.enabled = false
        try core.setRules([off, r2Rule("uncovered", .pathPrefix("~/Elsewhere"))])
        XCTAssertNoThrow(try core.update(catalog: nil, peer: .inProcess))
        XCTAssertEqual(core.enforcer.decide(open).verdict, .allow)
    }
}

// MARK: - "Block from now on" (engine-runtime-9)

final class BlockFromNowOnRound2Tests: XCTestCase {
    func testBlockFromNowOnRulesAreValidatedLikeOtherRules() throws {
        let dir = TempDir()
        let core = try r2Core(dir)
        try core.setRules([])
        let handler = r2Handler(core)

        // (a) A long binary name: the generated name fits, so the rule can be edited later.
        for (id, name) in [(1, String(repeating: "x", count: 250)), (2, String(repeating: "é", count: 200))] as [(Int64, String)] {
            let who = ResponsibleEntity(kind: .app, key: "app:/applications/\(id).app", displayName: name)
            try core.store.upsert([r2Alert(id: id, responsible: who)])
            try core.apply(action: .blockFromNowOn, toAlert: id, peer: .inProcess)
            var rule = try XCTUnwrap(core.rules.rules.first { $0.subject == .responsible(key: who.key, teamID: nil, cdhash: nil, exceptOwners: true) })
            let ruleName = try XCTUnwrap(rule.name)
            XCTAssertLessThanOrEqual(ruleName.utf8.count, DaemonCore.maxNameBytes)
            XCTAssertTrue(ruleName.hasPrefix("Block " + name.prefix(20)))
            XCTAssertTrue(ruleName.hasSuffix("…"))
            rule.enabled = false
            XCTAssertNoThrow(try core.upsert(rule: rule, peer: .inProcess), "editable")
        }
        XCTAssertEqual(DaemonCore.truncated("short", maxBytes: 256), "short")
        XCTAssertEqual(DaemonCore.truncated("ééé", maxBytes: 6), "ééé")
        XCTAssertEqual(DaemonCore.truncated("éééé", maxBytes: 7), "éé…")

        // (b) An old alert on a category the catalog no longer has: no dangling rule that would block
        // every later catalog edit.
        try core.store.upsert([r2Alert(id: 3, category: "gone")])
        let count = core.rules.rules.count
        XCTAssertEqual(r2Error(handler.handle(.alertAction(alertID: 3, action: .blockFromNowOn), peer: r2AgentPeer))?.code, .invalid)
        XCTAssertEqual(core.rules.rules.count, count)
        XCTAssertNoThrow(try core.update(catalog: nil, peer: .inProcess))
    }
}
