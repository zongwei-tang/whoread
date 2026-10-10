import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine
#if canImport(Security)
import Security
#endif

// Regression tests for IPC access: what the console user (possibly an AI agent running the
// signed CLI) may read (privacy-1), how the app is recognised (guard-1), the unprivileged "trust off"
// (guard-2) and the release code-signing requirements (macos-2).

private let ipcT = Date(timeIntervalSince1970: 1_760_000_000)
/// A file in a folder TCC keeps from processes without Full Disk Access (the daemon has it).
private let mailFile = "/Users/alice/Library/Mail/V10/INBOX.mbox/Secret merger.emlx"
private let secret = "Hunter2pw"
private let rootPeer = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)
/// The team-signed CLI run by the console user, or by an AI agent as that user.
private let cliPeer = IPCPeer(pid: 4242, euid: 501, isTrustedCode: true)
private let appPeer = IPCPeer(pid: 777, euid: 501, isTrustedCode: true, isApp: true)

private func ipcCore(_ dir: TempDir) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

private func strict(_ core: DaemonCore) -> ServiceHandler {
    let h = ServiceHandler(daemon: core, policy: .strict)
    h.consoleUID = { 501 }
    return h
}

private func errorOf(_ r: IPCResponse) -> IPCError? {
    if case .error(let e) = r { return e }
    return nil
}

/// The reply as the peer receives it.
private func wire(_ r: IPCResponse) throws -> String {
    String(decoding: try IPCCodec.encode(r), as: UTF8.self)
}

/// Terminal → zsh -c "…" → cat, with the secret and the file in argv.
private func mailReader(_ core: DaemonCore) -> ProcessRecord {
    core.tree.observe(proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, platform: true),
                      at: ipcT)
    core.tree.observe(proc(500, "/bin/zsh", ppid: 100, platform: true,
                           argv: ["zsh", "-c", "cat '\(mailFile)' | MYSQL_PWD=\(secret) upload"]), at: ipcT)
    let cat = proc(501, "/bin/cat", ppid: 500, platform: true, argv: ["cat", mailFile])
    core.tree.observe(cat, at: ipcT)
    return cat
}

private func mailRead(_ p: ProcessRecord) -> FileActivity {
    FileActivity(time: ipcT.addingTimeInterval(1), operation: .open, process: p,
                 targets: OperationSemantics.open(path: mailFile, fflag: 1))
}

// MARK: - privacy-1

final class RecordedReadTests: XCTestCase {
    /// What the daemon recorded with Full Disk Access (paths, chains, argv) is for root and the app.
    func testTheConsoleUserCannotReadWhatTheDaemonRecorded() throws {
        let dir = TempDir()
        let core = try ipcCore(dir)
        core.pipeline.receive(.file(mailRead(mailReader(core))), context: .monitorOnly)
        core.writer.flush()
        let handler = strict(core)
        guard case .events(let stored) = handler.handle(.events(EventQuery(includeBenign: true)), peer: rootPeer) else {
            return XCTFail("root reads events")
        }
        XCTAssertEqual(stored.map(\.path), [mailFile], "the access was recorded")
        XCTAssertTrue(stored.first?.chain.contains { $0.argv?.contains(mailFile) == true } == true, "with the command lines")

        let recorded: [IPCRequest] = [
            .events(EventQuery(includeBenign: true)), .live(afterID: nil, limit: 100, includeBenign: true),
            .alerts(AlertQuery()), .summaries(since: nil), .dailyAggregates(since: nil), .baseline, .rules,
        ]
        for request in recorded {
            XCTAssertEqual(handler.privilege(of: request), .recorded, "\(request)")
            let reply = handler.handle(request, peer: cliPeer)
            let e = try XCTUnwrap(errorOf(reply), "\(request) was served to the console user")
            XCTAssertEqual(e.code, .notPermitted, "\(request)")
            XCTAssertTrue(e.message.contains("sudo"), "say plainly that sudo is needed: \(e.message)")
            XCTAssertFalse(try wire(reply).contains("Secret merger"))
            XCTAssertNil(errorOf(handler.handle(request, peer: rootPeer)), "root: \(request)")
            XCTAssertNil(errorOf(handler.handle(request, peer: appPeer)), "the app: \(request)")
        }
        // A peer that met only the client requirement is not the app, and an unverified one even less.
        XCTAssertEqual(errorOf(handler.handle(.events(EventQuery()), peer: IPCPeer(pid: 777, euid: 501, isTrustedCode: false, isApp: true)))?.code,
                       .notPermitted)
        // What stays open: the user's own configuration, status and the agent list (the CLI's
        // `settings set trust-apple off` and category names need them).
        for request: IPCRequest in [.hello(clientVersion: whoReadIPCVersion), .status, .settings, .catalog, .agents, .asks] {
            XCTAssertNil(errorOf(handler.handle(request, peer: cliPeer)), "\(request)")
        }
    }

    /// Questions stay listable (and deniable) by the console user, without the file or command lines.
    func testQuestionsShowTheConsoleUserNeitherTheFileNorCommandLines() throws {
        let dir = TempDir()
        let core = try ipcCore(dir)
        let cat = mailReader(core)
        let chain = core.tree.chain(for: cat, at: ipcT)
        var request = AskRequest(id: 0, key: AskKey(responsibleKey: "app:/system/applications/utilities/terminal.app", categoryID: "mail",
                                                    access: .read, chainAgents: []),
                                 responsible: ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app",
                                                                displayName: "Terminal"),
                                 severity: .high, path: mailFile, process: cat, chain: chain.reversed().map { ChainLink(node: $0) },
                                 agentID: nil, appleProgram: true, firstAt: ipcT, lastAt: ipcT)
        XCTAssertTrue(request.chain.contains { $0.argv?.joined(separator: " ").contains("Secret merger") == true })
        core.askBroker.noteAnsweringClient()
        guard case .held(let first) = core.askBroker.hold(request, budget: 60, respond: { _ in }) else { return XCTFail("not held") }
        request.key.categoryID = "messages"
        guard case .held(let second) = core.askBroker.hold(request, budget: 60, respond: { _ in }) else { return XCTFail("not held") }
        defer { core.askBroker.denyAll() }
        core.askBroker.drainRedaction()
        let handler = strict(core)

        let reply = handler.handle(.asks, peer: cliPeer)
        guard case .asks(let shown) = reply else { return XCTFail("\(reply)") }
        XCTAssertEqual(Set(shown.map(\.id)), [first, second], "every question is listed")
        for q in shown {
            XCTAssertEqual(q.path, ServiceHandler.hiddenPath)
            XCTAssertNil(q.process.argv)
            XCTAssertTrue(q.chain.allSatisfy { $0.argv == nil })
            XCTAssertEqual(q.responsible.displayName, "Terminal", "who is asking stays visible")
        }
        XCTAssertFalse(try wire(reply).contains("Secret merger"))
        XCTAssertFalse(try wire(reply).contains(secret))
        for peer in [rootPeer, appPeer] {
            guard case .asks(let full) = handler.handle(.asks, peer: peer) else { return XCTFail() }
            XCTAssertEqual(Set(full.map(\.path)), [mailFile])
        }
        // Denying answers with the remaining questions, also without their details.
        let denied = handler.handle(.answerAsk(id: first, action: .keepBlocking), peer: cliPeer)
        guard case .asks(let left) = denied else { return XCTFail("\(denied)") }
        XCTAssertEqual(left.map(\.id), [second])
        XCTAssertFalse(try wire(denied).contains("Secret merger"))
    }

    /// The reply to an unprivileged new rule is not the rule list (rules made from alerts name files).
    func testAnUnprivilegedNewRuleIsNotAnsweredWithEveryRule() throws {
        let dir = TempDir()
        let core = try ipcCore(dir)
        var deny = Rule(id: "deny-mail", enabled: true, enforce: true, target: .category("mail"), subject: .anyNonOwner,
                        action: .deny, includePlatformBinaries: true)
        // What "allow once" on a blocked access leaves for 10 minutes.
        deny.exceptions = [RuleException(subject: .anyNonOwner, pathPrefix: mailFile, categoryID: "mail", access: .read,
                                         expiresAt: Date().addingTimeInterval(600), remainingUses: 1)]
        try core.setRules([deny])
        let handler = strict(core)
        let added = Rule(id: "agent-adds", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                         action: .deny, includePlatformBinaries: true)
        let reply = handler.handle(.upsertRule(added), peer: cliPeer)
        XCTAssertNil(errorOf(reply), "adding a deny rule is open to the console user")
        XCTAssertFalse(try wire(reply).contains("Secret merger"))
        XCTAssertTrue(core.rules.rules.contains { $0.id == "agent-adds" })
        guard case .rules(let all) = handler.handle(.upsertRule(Rule(id: "root-adds", target: .category("ssh"), subject: .anyNonOwner,
                                                                      action: .alert)), peer: rootPeer) else {
            return XCTFail("root gets the rule list")
        }
        XCTAssertEqual(all.count, 3)
    }
}

// MARK: - guard-1

final class AppRecognitionTests: XCTestCase {
    #if os(macOS)
    /// Before: a peer accepted with only the client requirement (the CLI) was the app whenever the code
    /// holding its pid when a request was served met the app requirement. Now only the connection decides.
    func testAPeerAcceptedAsAClientIsNotTheAppWhateverItsPidLooksLike() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        // Requirements this very process meets, so a pid look-up says "the app".
        config.clientRequirement = "always"
        config.appRequirement = "always"
        XCTAssertTrue(SignedAppPeerVerifier(requirement: "always").isApp(pid: getpid()), "the pid look-up says: the app")
        let daemon = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        daemon.handler.consoleUID = { geteuid() }
        try daemon.core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        daemon.core.drainPolicyQueue()
        let client = IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true)
        XCTAssertFalse(daemon.handler.isPrivileged(client))
        let reply = daemon.handler.handle(.setEnforcement(enabled: false), peer: client)
        XCTAssertEqual(errorOf(reply)?.code, .notPermitted)
        XCTAssertTrue(daemon.core.currentSettings.enforcementEnabled, "the guard stays on")
        XCTAssertEqual(errorOf(daemon.handler.handle(.events(EventQuery()), peer: client))?.code, .notPermitted)
        // The connection the transport marked as the app's is.
        var app = client
        app.isApp = true
        XCTAssertTrue(daemon.handler.isPrivileged(app))
        XCTAssertNil(errorOf(daemon.handler.handle(.setEnforcement(enabled: false), peer: app)))
        XCTAssertFalse(daemon.core.currentSettings.enforcementEnabled)
    }

    /// The pid look-up checks what XPC will enforce on the app's connection (client requirement
    /// included): a "yes" for code that fails the client requirement would invalidate its connection.
    func testThePidLookUpChecksTheRequirementXPCWillInstall() {
        let both = XPCPeerPolicy(clientRequirement: "always", appRequirement: "always")
        XCTAssertEqual((both.appCandidate as? SignedAppPeerVerifier)?.requirementText, both.appConnectionRequirement)
        XCTAssertTrue(both.appCandidate.isApp(pid: getpid()))
        // This process meets the app requirement, not the client one.
        let split = XPCPeerPolicy(clientRequirement: #"identifier "com.example.whoread.cli""#, appRequirement: "always")
        XCTAssertTrue(SignedAppPeerVerifier(requirement: "always").isApp(pid: getpid()))
        XCTAssertFalse(split.appCandidate.isApp(pid: getpid()))
        XCTAssertTrue(XPCPeerPolicy(clientRequirement: nil, appRequirement: "always").appCandidate is NoAppPeers)
    }

    func testARequirementThatDoesNotParseIsNeverMet() {
        XCTAssertFalse(XPCPeerPolicy.parses("anchor apple generic and ((("))
        XCTAssertTrue(XPCPeerPolicy.parses("always"))
        // SecCodeCheckValidity with no requirement succeeds: the verifier must not fall through to that.
        XCTAssertFalse(SignedAppPeerVerifier(requirement: "anchor apple generic and (((").isApp(pid: getpid()))
    }

    /// Two requirements that parse alone can fail combined, as the app's connection gets them: a comment
    /// in the client one swallows the rest. That must be reported, and never handed to
    /// setCodeSigningRequirement (it raises on a malformed requirement), whatever the pid look-up says.
    func testRequirementsThatOnlyParseAloneAreReportedAndNeverInstalledCombined() {
        for client in [#"anchor apple generic // the CLI and the app"#, "anchor apple generic # the CLI and the app", "always;"] {
            XCTAssertTrue(XPCPeerPolicy.parses(client), client)
            let policy = XPCPeerPolicy(clientRequirement: client, appRequirement: "always")
            XCTAssertFalse(XPCPeerPolicy.parses("(\(client)) and (always)"), client)
            XCTAssertNil(policy.appConnectionRequirement, client)
            XCTAssertFalse(policy.recognisesApp, client)
            XCTAssertTrue(policy.appCandidate is NoAppPeers, client)
            XCTAssertEqual(policy.errors.count, 1, "logged, not silent: \(client)")
            for hint in [false, true] {
                guard case .accept(let installed?, let peer) = policy.decide(euid: 501, pid: 9, looksLikeApp: hint) else {
                    return XCTFail(client)
                }
                XCTAssertTrue(XPCPeerPolicy.parses(installed), installed)
                XCTAssertFalse(peer.isApp, client)
            }
        }
        // Requirements that combine are left alone.
        let fine = XPCPeerPolicy(clientRequirement: "anchor apple generic /* the CLI and the app */", appRequirement: "always")
        XCTAssertEqual(fine.errors, [])
        XCTAssertNotNil(fine.appConnectionRequirement)
    }
    #endif

    private let client = #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345""#
    private let app = #"identifier "com.example.whoread" and anchor apple generic"#

    func testTheAppIsOnlyTheConnectionWhoseMessagesXPCChecksAgainstTheAppRequirement() {
        let policy = XPCPeerPolicy(clientRequirement: client, appRequirement: app, parses: { _ in true })
        XCTAssertTrue(policy.errors.isEmpty)
        // Looks like the app: the app requirement (with the client one) is what XPC enforces on every message.
        guard case .accept(let both?, let appPeer) = policy.decide(euid: 501, pid: 77, looksLikeApp: true) else { return XCTFail() }
        XCTAssertEqual(both, "(\(client)) and (\(app))")
        XCTAssertTrue(appPeer.isApp && appPeer.isTrustedCode)
        XCTAssertEqual(appPeer.euid, 501)
        // Anything else: the client requirement only, never the app.
        XCTAssertEqual(policy.decide(euid: 501, pid: 78, looksLikeApp: false),
                       .accept(requirement: client, peer: IPCPeer(pid: 78, euid: 501, isTrustedCode: true)))
        // Root: any build, no requirement, and root needs no app flag.
        XCTAssertEqual(policy.decide(euid: 0, pid: 1, looksLikeApp: true),
                       .accept(requirement: nil, peer: IPCPeer(pid: 1, euid: 0, isTrustedCode: false)))
        // Every accepted peer that is the app has the app requirement installed.
        for euid: UInt32 in [0, 501] {
            for hint in [false, true] {
                if case .accept(let r, let p) = policy.decide(euid: euid, pid: 5, looksLikeApp: hint), p.isApp {
                    XCTAssertEqual(r, policy.appConnectionRequirement)
                }
            }
        }
    }

    func testWithoutAUsableClientRequirementTheAppIsNeverRecognised() {
        // Development build without requirements: anyone local connects, nobody is the app.
        let dev = XPCPeerPolicy(clientRequirement: nil, appRequirement: app, parses: { _ in true })
        XCTAssertFalse(dev.recognisesApp)
        XCTAssertEqual(dev.decide(euid: 501, pid: 9, looksLikeApp: true),
                       .accept(requirement: nil, peer: IPCPeer(pid: 9, euid: 501, isTrustedCode: false)))
        // A client requirement that does not parse would raise in setCodeSigningRequirement (the daemon
        // would die at the first connection) and must not become "no requirement": refuse non-root peers.
        let broken = XPCPeerPolicy(clientRequirement: "anchor (((", appRequirement: app, parses: { !$0.contains("(((") })
        XCTAssertEqual(broken.decide(euid: 501, pid: 9, looksLikeApp: true), .reject)
        XCTAssertEqual(broken.decide(euid: 0, pid: 1, looksLikeApp: false),
                       .accept(requirement: nil, peer: IPCPeer(pid: 1, euid: 0, isTrustedCode: false)), "root still gets in")
        XCTAssertEqual(broken.errors.count, 1)
        // An app requirement that does not parse: clients still work, the app is never recognised.
        let noApp = XPCPeerPolicy(clientRequirement: client, appRequirement: "identifier (((", parses: { !$0.contains("(((") })
        XCTAssertNil(noApp.appConnectionRequirement)
        XCTAssertEqual(noApp.decide(euid: 501, pid: 9, looksLikeApp: true),
                       .accept(requirement: client, peer: IPCPeer(pid: 9, euid: 501, isTrustedCode: true)))
        XCTAssertEqual(noApp.errors.count, 1)
    }

    func testAnAppRequirementThatAdmitsDebuggableBuildsIsReported() {
        XCTAssertEqual(XPCPeerPolicy(clientRequirement: client, appRequirement: app, parses: { _ in true }).warnings.count, 1)
        let pinned = app + " and certificate leaf[field.\(XPCPeerPolicy.developerIDLeafOID)] exists"
        XCTAssertTrue(XPCPeerPolicy(clientRequirement: client, appRequirement: pinned, parses: { _ in true }).warnings.isEmpty)
    }
}

// MARK: - guard-2

final class TrustOffRaceTests: XCTestCase {
    /// The console user's "trust off" was authorized against one snapshot of the settings and applied as
    /// a whole-object replace: a privileged change in between (a project root) was undone.
    func testTrustOffFromTheConsoleUserKeepsAPrivilegedChangeMadeMeanwhile() throws {
        let dir = TempDir()
        let core = try ipcCore(dir)
        let handler = strict(core)
        var on = core.currentSettings
        on.trustApplePrograms = true
        XCTAssertNil(errorOf(handler.handle(.updateSettings(on), peer: rootPeer)))
        // The agent's copy: the current settings with trust off. Authorized as strengthening.
        var stale = core.currentSettings
        stale.trustApplePrograms = false
        XCTAssertEqual(handler.privilege(of: .updateSettings(stale)), .strengthen)
        XCTAssertNil(handler.authorize(.updateSettings(stale), peer: cliPeer))
        // Root adds a project root before the agent's request is applied.
        var roots = core.currentSettings
        roots.projectRoots = ["~/code"]
        XCTAssertNil(errorOf(handler.handle(.updateSettings(roots), peer: rootPeer)))
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/code/app/.env")?.categoryID, "project-secrets")
        _ = try handler.dispatch(.updateSettings(stale), peer: cliPeer)
        XCTAssertFalse(core.currentSettings.trustApplePrograms, "trust is off")
        XCTAssertEqual(core.currentSettings.projectRoots, ["~/code"], "root's change is kept")
        XCTAssertEqual(core.analyzer.classifier.classify("/Users/alice/code/app/.env")?.categoryID, "project-secrets")
        // Sent with any other change, it is still refused outright.
        var more = core.currentSettings
        more.trustApplePrograms = true
        XCTAssertNil(errorOf(handler.handle(.updateSettings(more), peer: rootPeer)))
        more.trustApplePrograms = false
        more.projectRoots = []
        XCTAssertEqual(errorOf(handler.handle(.updateSettings(more), peer: cliPeer))?.code, .notPermitted)
        XCTAssertEqual(core.currentSettings.projectRoots, ["~/code"])
    }
}

// MARK: - macos-2

final class SigningRequirementTests: XCTestCase {
    struct Requirements {
        var client: String
        var app: String
        var releaseAnchor: String
        var debugAnchor: String
    }

    /// The requirement strings as Xcode/project.yml defines them, checked against Extension/Info.plist.
    func requirements() throws -> Requirements {
        let yml = try String(contentsOf: repoRoot.appendingPathComponent("Xcode/project.yml"), encoding: .utf8)
        let lines = yml.components(separatedBy: "\n")
        func quoted(_ line: String) -> String? {
            guard let a = line.firstIndex(of: "'"), let b = line.lastIndex(of: "'"), a < b else { return nil }
            return String(line[line.index(after: a)..<b])
        }
        func value(_ key: String) -> [(String, Int)] {
            lines.enumerated().compactMap { i, l in
                l.trimmingCharacters(in: .whitespaces).hasPrefix(key + ":") ? quoted(l).map { ($0, i) } : nil
            }
        }
        let client = try XCTUnwrap(value("WhoReadClientRequirement").first?.0)
        let app = try XCTUnwrap(value("WhoReadAppRequirement").first?.0)
        let anchors = value("WHOREAD_SIGNING_ANCHOR")
        XCTAssertEqual(anchors.count, 2, "a default and a Debug override")
        let debug = try XCTUnwrap(anchors.first { _, i in
            lines[..<i].last { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }?.trimmingCharacters(in: .whitespaces) == "Debug:"
        })
        let release = try XCTUnwrap(anchors.first { $0.1 != debug.1 })

        let plist = try Data(contentsOf: repoRoot.appendingPathComponent("Extension/Info.plist"))
        let info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: plist, format: nil) as? [String: Any])
        XCTAssertEqual(info["WhoReadClientRequirement"] as? String, client, "Extension/Info.plist matches project.yml")
        XCTAssertEqual(info["WhoReadAppRequirement"] as? String, app, "Extension/Info.plist matches project.yml")
        return Requirements(client: client, app: app, releaseAnchor: release.0, debugAnchor: debug.0)
    }

    /// Entitlements that let other processes of the user control the code: debugging, and injected libraries.
    static let controllable = ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation",
                               "com.apple.security.cs.allow-dyld-environment-variables"]
    static func refusing(_ entitlement: String) -> String { #"!(entitlement[""# + entitlement + #""] exists)"# }

    func expand(_ s: String, anchor: String, team: String = "ABCDE12345") -> String {
        s.replacingOccurrences(of: "$(WHOREAD_SIGNING_ANCHOR)", with: anchor)
            .replacingOccurrences(of: "$(BUNDLE_ID_PREFIX)", with: "com.example")
            .replacingOccurrences(of: "$(DEVELOPMENT_TEAM)", with: team)
    }

    func testReleaseRequirementsPinDeveloperIDAndDebugIsTheLabelledDevPath() throws {
        let r = try requirements()
        for clause in ["certificate 1[field.1.2.840.113635.100.6.2.6] exists",
                       "certificate leaf[field.\(XPCPeerPolicy.developerIDLeafOID)] exists"]
                        + SigningRequirementTests.controllable.map(SigningRequirementTests.refusing) {
            XCTAssertTrue(r.releaseAnchor.contains(clause), clause)
            XCTAssertFalse(r.debugAnchor.contains(clause), "Debug (dev path) admits Apple Development builds")
        }
        let release = XPCPeerPolicy(clientRequirement: expand(r.client, anchor: r.releaseAnchor),
                                    appRequirement: expand(r.app, anchor: r.releaseAnchor))
        XCTAssertEqual(release.errors, [], "both parse")
        XCTAssertEqual(release.warnings, [], "the release app requirement pins Developer ID")
        XCTAssertNotNil(release.appConnectionRequirement)
        let debug = XPCPeerPolicy(clientRequirement: expand(r.client, anchor: r.debugAnchor),
                                  appRequirement: expand(r.app, anchor: r.debugAnchor))
        XCTAssertEqual(debug.errors, [])
        XCTAssertEqual(debug.warnings.count, 1, "a Debug extension logs that it trusts debuggable builds")
        // Only the CLI and the app connect, never another binary of the team.
        let client = expand(r.client, anchor: r.releaseAnchor)
        XCTAssertTrue(client.hasPrefix(#"(identifier "com.example.whoread.cli" or identifier "com.example.whoread") and "#), client)
        XCTAssertTrue(expand(r.app, anchor: r.releaseAnchor).hasPrefix(#"identifier "com.example.whoread" and "#))
        // A build without a team: Extension/main.swift drops requirements with an empty team.
        for s in [r.client, r.app] {
            XCTAssertTrue(expand(s, anchor: r.releaseAnchor, team: "").contains(#"leaf[subject.OU] = """#))
        }
    }

    #if os(macOS)
    /// The release requirements refuse a build that other processes of the user could control: one
    /// carrying get-task-allow (what Debug builds have), or one that accepts injected libraries.
    func testTheReleaseAnchorRefusesControllableBuilds() throws {
        let r = try requirements()
        let dir = TempDir()
        func signedCopy(_ name: String, entitlement: String?) throws -> String {
            let path = dir.path(name)
            XCTAssertTrue(touch(path, try Data(contentsOf: URL(fileURLWithPath: "/usr/bin/true"))))
            chmod(path, 0o755)
            var args = ["--force", "--sign", "-"]
            if let entitlement {
                let plist = dir.path(name + ".entitlements")
                XCTAssertTrue(touch(plist, Data("""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                    <plist version="1.0"><dict><key>\(entitlement)</key><true/></dict></plist>
                    """.utf8)))
                args += ["--entitlements", plist]
            }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            p.arguments = args + [path]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try p.run()
            p.waitUntilExit()
            try XCTSkipUnless(p.terminationStatus == 0, "codesign could not sign a copy here")
            return path
        }
        func meets(_ path: String, _ text: String) throws -> Bool {
            var requirement: SecRequirement?
            XCTAssertEqual(SecRequirementCreateWithString(text as CFString, [], &requirement), errSecSuccess, text)
            let req = try XCTUnwrap(requirement, "an unparsed requirement would pass everything")
            var code: SecStaticCode?
            XCTAssertEqual(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code), errSecSuccess)
            return SecStaticCodeCheckValidity(try XCTUnwrap(code), [], req) == errSecSuccess
        }
        let clauses = SigningRequirementTests.controllable.map(SigningRequirementTests.refusing)
        let plain = try signedCopy("plain", entitlement: nil)
        for clause in clauses { XCTAssertTrue(try meets(plain, clause), clause) }
        for (i, entitlement) in SigningRequirementTests.controllable.enumerated() {
            let copy = try signedCopy("copy\(i)", entitlement: entitlement)
            XCTAssertFalse(try meets(copy, clauses[i]), entitlement)
            XCTAssertFalse(try meets(copy, expand(r.app, anchor: r.releaseAnchor)), entitlement)
        }
    }
    #endif
}
