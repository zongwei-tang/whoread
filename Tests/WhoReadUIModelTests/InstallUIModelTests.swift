import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

/// What the app says about its own installation in monitor-only mode (the dev LaunchDaemon with
/// eslogger, an ad hoc app the installer pinned by its code identity): `--self-check`, onboarding
/// without the system extension, the notice when the daemon does not recognise the app, the
/// enforcement switches, and open at login. Reads are checked against the daemon's real permission
/// table (ServiceHandler, strict).
final class InstallUIModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var handler: ServiceHandler!
    /// The app as the daemon sees one it does not recognise (rebuilt or replaced after installing).
    var unrecognised: IPCClient!
    /// The app the installer pinned.
    var recognised: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-install-ui-\(UUID().uuidString.prefix(6))")
        var c = DaemonConfiguration()
        c.dataDirectory = dir.path
        c.defaultsDirectory = repoRoot.appendingPathComponent("Data").path
        c.source = .replay
        c.replayPath = repoRoot.appendingPathComponent("Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl").path
        c.homeDirectories = ["/Users/alice"]
        c.seedProcesses = false
        core = try DaemonCore(config: c)
        try core.source.start(sink: core.pipeline)
        XCTAssertTrue((core.source as! ReplaySource).waitUntilFinished())
        core.writer.flush()
        handler = ServiceHandler(daemon: core, policy: .strict)
        handler.consoleUID = { geteuid() }
        unrecognised = InProcessClient(handler: handler, peer: IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true, isApp: false))
        recognised = InProcessClient(handler: handler, peer: IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true, isApp: true))
    }

    override func tearDownWithError() throws {
        core.askBroker.denyAll()
        try? FileManager.default.removeItem(at: dir)
    }

    /// Answers through `inner`, with its status changed by `change`.
    private func withStatus(_ inner: IPCClient, _ change: @escaping (inout DaemonStatus) -> Void) -> IPCClient {
        FixedClient { request in
            let reply = try inner.send(request)
            guard case .status(var s) = reply else { return reply }
            change(&s)
            return .status(s)
        }
    }

    /// The dev LaunchDaemon monitoring with eslogger, as on the user's Mac.
    private func eslogger(_ inner: IPCClient, enforcementEnabled: Bool = false) -> IPCClient {
        withStatus(inner) {
            $0.source = .eslogger
            $0.sourceRunning = true
            $0.sourceCanEnforce = false
            $0.enforcementEnabled = enforcementEnabled
            $0.killSwitchFilePresent = false
            $0.enforcementActive = false
            $0.enforcementInactiveReasons = enforcementEnabled ? [.sourceCannotEnforce] : [.disabledByUser, .sourceCannotEnforce]
        }
    }

    /// One tick of the app: the questions on their own connection, then status and history.
    private func poll(_ m: AppModel, _ client: IPCClient, full: Bool = true) {
        m.apply(asks: SnapshotFetcher.fetchAsks(client))
        m.apply(SnapshotFetcher.fetch(client, liveAfter: m.liveCursor, includeBenign: false, full: full, hello: true))
    }

    /// Records the requests it passes on.
    private final class Recording: IPCClient, @unchecked Sendable {
        let inner: IPCClient
        var requests: [String] = []
        init(_ inner: IPCClient) { self.inner = inner }
        func send(_ request: IPCRequest) throws -> IPCResponse {
            requests.append(String(String(describing: request).prefix { $0 != "(" }))
            return try inner.send(request)
        }
    }

    // MARK: - --self-check

    func testSelfCheckOfTheRecognisedAppPrintsThreeStatusLines() throws {
        let client = Recording(recognised)
        let r = SelfCheck.run(client, asRoot: false)
        XCTAssertEqual(r.lines, [
            "daemon: reachable (WhoRead \(WhoReadVersion.string), protocol \(whoReadIPCVersion))",
            "monitoring: stopped (source replay)",
            "app recognised: yes",
        ])
        XCTAssertEqual(r.outcome, .recognised)
        XCTAssertEqual(r.exitStatus, 0)
        // Exactly the three steps: the handshake, the status, one read only the app may make.
        XCTAssertEqual(client.requests, ["hello", "status", "rules"])
        XCTAssertEqual(SelfCheck.argument, "--self-check")

        let running = SelfCheck.run(eslogger(recognised), asRoot: false)
        XCTAssertEqual(running.lines[1], "monitoring: running (source eslogger)")
        XCTAssertEqual(running.exitStatus, 0)
    }

    func testSelfCheckNeverNamesAFileOrACommandLine() throws {
        // A rule, a question and the recorded alerts all name files; none of it may reach stdout.
        _ = try recognised.call(.upsertRule(Rule(name: "Block /Users/alice/.ssh/id_ed25519", target: .pathPrefix("/Users/alice/.ssh/id_ed25519"),
                                                 subject: .unsigned(path: "/opt/tool/secret-cli", cdhash: nil), action: .deny)))
        let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app", displayName: "Terminal",
                                         path: "/System/Applications/Utilities/Terminal.app")
        let q = AskRequest(id: 0, key: AskKey(responsibleKey: terminal.key, categoryID: "ssh", access: .read, chainAgents: []),
                           responsible: terminal, severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                           process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: [], agentID: nil,
                           appleProgram: false, firstAt: Date(), lastAt: Date())
        core.askBroker.noteAnsweringClient()
        guard case .held = core.askBroker.hold(q, budget: 60, respond: { _ in }) else { return XCTFail("not held") }
        XCTAssertFalse(try recognised.alerts(AlertQuery(limit: 10)).isEmpty, "the fixture recorded alerts")

        for client in [recognised!, unrecognised!] {
            let out = SelfCheck.run(client, asRoot: false).lines.joined(separator: "\n")
            for secret in ["/Users/alice", ".ssh", "id_ed25519", "secret-cli", "/bin/cat", "Terminal", "Block "] {
                XCTAssertFalse(out.contains(secret), "\(secret) in:\n\(out)")
            }
        }
    }

    func testSelfCheckOfAnAppTheDaemonDoesNotRecognise() {
        let r = SelfCheck.run(unrecognised, asRoot: false)
        XCTAssertEqual(r.lines.count, 3)
        XCTAssertTrue(r.lines[0].hasPrefix("daemon: reachable (WhoRead "))
        XCTAssertEqual(r.lines[2], "app recognised: no (the daemon does not take this program for the WhoRead app it was installed with: "
                       + "if the app was rebuilt or replaced after installing, run scripts/install.sh again)")
        XCTAssertEqual(r.outcome, .notRecognised)
        XCTAssertEqual(r.exitStatus, 2)
        // scripts/install.sh sets up only the dev LaunchDaemon.
        XCTAssertEqual(SelfCheck.run(unrecognised, viaExtension: true, asRoot: false).lines[2],
                       "app recognised: no (the system extension does not take this program for the signed WhoRead app)")
    }

    func testSelfCheckAsRootProvesNothingAboutTheApp() {
        // The daemon serves root whatever program asks: the read would succeed for any binary.
        let client = Recording(unrecognised)
        let r = SelfCheck.run(client, asRoot: true)
        XCTAssertTrue(r.lines[2].hasPrefix("app recognised: no (running as root"), r.lines[2])
        XCTAssertEqual(r.exitStatus, 2)
        XCTAssertEqual(client.requests, ["hello", "status"], "the read is not even made")
    }

    func testSelfCheckOfAStoppedSourceEscapesTheDaemonsWords() {
        let stopped = withStatus(recognised) {
            $0.source = .eslogger
            $0.sourceRunning = false
            $0.sourceError = "eslogger exited (status 1) after 0 s: ERROR\nES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED\u{1B}[31m"
            $0.sourceHint = "Full Disk Access is missing\u{202E}"
        }
        let r = SelfCheck.run(stopped, asRoot: false)
        XCTAssertEqual(r.lines[1], "monitoring: stopped (source eslogger): eslogger exited (status 1) after 0 s: ERROR\\u{a}"
                       + "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED\\u{1b}[31m [hint: Full Disk Access is missing\\u{202e}]")
        XCTAssertEqual(r.lines.count, 3, "one line each")
        XCTAssertFalse(r.lines.joined().contains { $0.isNewline }, "escaped: no line break inside a line")
        XCTAssertEqual(r.exitStatus, 0, "monitoring is reported, not judged")

        let hintOnly = withStatus(recognised) { $0.source = .eslogger; $0.sourceRunning = false; $0.sourceError = nil; $0.sourceHint = "h" }
        XCTAssertEqual(SelfCheck.run(hintOnly, asRoot: false).lines[1], "monitoring: stopped (source eslogger) [hint: h]")
        let bare = withStatus(recognised) { $0.sourceRunning = false; $0.sourceError = nil; $0.sourceHint = nil }
        XCTAssertEqual(SelfCheck.run(bare, asRoot: false).lines[1], "monitoring: stopped (source replay)")
        // The version is the daemon's word too.
        let odd = withStatus(recognised) { $0.version = "9.9\u{1B}]0;x\u{7}" }
        XCTAssertEqual(SelfCheck.run(odd, asRoot: false).lines[0], "daemon: reachable (WhoRead 9.9\\u{1b}]0;x\\u{7}, protocol \(whoReadIPCVersion))")
    }

    func testSelfCheckOfAnUnreachableOrIncompatibleDaemon() {
        func check(_ client: IPCClient, _ line: String, file: StaticString = #filePath, lineNumber: UInt = #line) {
            let r = SelfCheck.run(client, asRoot: false)
            XCTAssertEqual(r.lines, [line], file: file, line: lineNumber)
            XCTAssertEqual(r.exitStatus, 1, file: file, line: lineNumber)
        }
        check(FixedClient { _ in throw IPCError(.unavailable, "XPC: Couldn't communicate with a helper application.") },
              "daemon: unreachable (XPC: Couldn't communicate with a helper application.)")
        check(FixedClient { _ in throw IPCError(.unavailable, "no\nanswer") }, "daemon: unreachable (no\\u{a}answer)")
        check(FixedClient { _ in .error(IPCError(.versionMismatch, "client speaks protocol 3, daemon 4")) },
              "daemon: unreachable (protocol mismatch: client speaks protocol 3, daemon 4)")
        check(FixedClient { _ in .hello(serverVersion: whoReadIPCVersion + 1) },
              "daemon: unreachable (protocol mismatch: the daemon speaks protocol \(whoReadIPCVersion + 1), this app \(whoReadIPCVersion))")
        check(FixedClient { _ in .ok }, "daemon: unreachable (protocol mismatch: unexpected reply)")
        let garbled = FixedClient { request in
            if case .status = request { throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "new field")) }
            return try self.recognised.send(request)
        }
        check(garbled, "daemon: unreachable (protocol mismatch: unreadable reply)")
        // Another user than the one at the console: refused at the handshake.
        handler.consoleUID = { geteuid() &+ 1 }
        check(unrecognised, "daemon: unreachable (only root or the console user may talk to the WhoRead daemon)")
        handler.consoleUID = { geteuid() }

        // The daemon stops answering after the status: the app could not be checked, which is not a refusal.
        let silent = FixedClient { request in
            if case .rules = request { throw IPCError(.unavailable, "daemon did not answer within 10 s (com.whoread.daemon.xpc)") }
            return try self.recognised.send(request)
        }
        let r = SelfCheck.run(silent, asRoot: false)
        XCTAssertEqual(r.lines.count, 3)
        XCTAssertEqual(r.lines[2], "app recognised: no (could not be checked: daemon did not answer within 10 s (com.whoread.daemon.xpc))")
        XCTAssertEqual(r.exitStatus, 1)
    }

    // MARK: - Onboarding in monitor-only mode

    func testMonitorOnlyOnboardingHasNoExtensionStepAndNamesTheDaemon() throws {
        var status = core.status()
        status.source = .eslogger
        status.sourceRunning = true
        status.sourceError = nil
        let o = OnboardingModel()
        XCTAssertTrue(OnboardingModel.isMonitorOnly(status, connected: true, viaExtension: false))
        XCTAssertFalse(OnboardingModel.isMonitorOnly(status, connected: true, viaExtension: true))
        XCTAssertFalse(OnboardingModel.isMonitorOnly(status, connected: false, viaExtension: false))
        XCTAssertFalse(OnboardingModel.isMonitorOnly(nil, connected: true, viaExtension: false))

        // Not offered: it cannot work in this build, whatever this session tried.
        XCTAssertEqual(o.extensionStepState(status, connected: true, viaExtension: false, canInstallExtension: true), .notAvailable)
        XCTAssertEqual(OnboardingModel(extensionState: .failed("x")).extensionStepState(status, connected: true, viaExtension: false,
                                                                                        canInstallExtension: true),
                       .notAvailable)
        // Onboarding completes without it.
        XCTAssertEqual(o.fullDiskAccessState(status, connected: true), .done)
        XCTAssertTrue(o.isComplete(status, connected: true))

        for language in [Language.en, .zhHans] {
            let ext = OnboardingModel.extensionBody(monitorOnly: true, language)
            XCTAssertNotEqual(ext, L10n.t(.onbExtBody, language))
            XCTAssertTrue(OnboardingModel.fullDiskAccessBody(monitorOnly: true, language).contains("/usr/local/libexec/whoreadd"))
            XCTAssertNotEqual(OnboardingModel.daemonBody(monitorOnly: true, language), L10n.t(.onbDaemonBody, language))
        }
        XCTAssertTrue(OnboardingModel.extensionBody(monitorOnly: true, .en).contains("needs a signed release"))
        XCTAssertTrue(OnboardingModel.extensionBody(monitorOnly: true, .en).contains("monitors without blocking"))
        XCTAssertTrue(OnboardingModel.fullDiskAccessBody(monitorOnly: true, .en).contains("not this app"))
        // Elsewhere, the usual steps.
        XCTAssertEqual(OnboardingModel.fullDiskAccessBody(monitorOnly: false, .en), L10n.t(.onbFDABody, .en))
        XCTAssertEqual(OnboardingModel.extensionBody(monitorOnly: false, .zhHans), L10n.t(.onbExtBody, .zhHans))
        status.source = .replay
        XCTAssertEqual(o.extensionStepState(status, connected: true, viaExtension: false, canInstallExtension: true), .pending)

        // The app's model agrees, from the connection it reports.
        let m = AppModel(language: .en)
        poll(m, eslogger(recognised))
        XCTAssertTrue(m.monitorOnly)
        m.viaExtension = true
        XCTAssertFalse(m.monitorOnly)
    }

    func testTheDaemonPathIsWhereTheLaunchDaemonRunsIt() throws {
        let data = try Data(contentsOf: repoRoot.appendingPathComponent("packaging/com.whoread.daemon.plist"))
        let plist = try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        XCTAssertEqual((plist["ProgramArguments"] as? [String])?.first, OnboardingModel.daemonExecutablePath)
    }

    // MARK: - Not recognised by the background service

    func testNotRecognisedIsOnePersistentNoticeThatSaysHowToFixIt() throws {
        let m = AppModel(language: .en)
        poll(m, eslogger(unrecognised))
        XCTAssertTrue(m.notRecognised)
        let notice = try XCTUnwrap(m.notRecognisedText)
        XCTAssertEqual(notice, "WhoRead is not recognised by the background service, so it cannot show alerts, the live feed, "
                       + "the app, file and AI agent history or the rules here. Run scripts/install.sh again: this happens when "
                       + "the app was rebuilt or replaced after installing.")
        XCTAssertEqual(L10n.alternatives([], .en), "")
        XCTAssertEqual(L10n.alternatives(["a"], .en), "a")
        XCTAssertEqual(L10n.alternatives(["a", "b"], .en), "a or b")
        XCTAssertEqual(L10n.alternatives(["a", "b", "c"], .zhHans), "a、b、c")
        // eslogger holds no access: nothing about questions.
        XCTAssertFalse(notice.contains("Questions"))
        // One notice: not the limited view (which speaks of a signed app) as well.
        XCTAssertEqual(m.accessNotice, notice)
        // Not an error state: connected, the status and settings read, the mode as usual.
        XCTAssertNil(m.lastError)
        XCTAssertTrue(m.connected)
        XCTAssertNotNil(m.settings)
        XCTAssertNil(m.unreachableText)
        XCTAssertNil(m.connectionProblemText)
        XCTAssertNotEqual(m.menuBar.symbol, "exclamationmark.triangle")
        // Each tab's note points at it and names the command, not "the signed WhoRead app".
        for part in [SnapshotPart.alerts, .live, .summaries, .rules] {
            let note = try XCTUnwrap(m.unavailableNote(part))
            XCTAssertTrue(note.contains("does not recognise this app"), note)
            XCTAssertTrue(note.contains(L10n.partCommand(part)), note)
            XCTAssertFalse(note.contains("signed WhoRead app"), note)
        }
        XCTAssertNil(m.unavailableNote(.settings))

        // It stays, poll after poll (fast and full).
        for full in [false, true, false] {
            poll(m, eslogger(unrecognised), full: full)
            XCTAssertEqual(m.notRecognisedText, notice)
        }

        let zh = AppModel(language: .zhHans)
        poll(zh, eslogger(unrecognised))
        let zhNotice = try XCTUnwrap(zh.notRecognisedText)
        XCTAssertTrue(zhNotice.hasPrefix("WhoRead 未被后台服务识别"), zhNotice)
        XCTAssertTrue(zhNotice.contains("scripts/install.sh"))
        XCTAssertTrue(zhNotice.contains("告警、实时记录"), zhNotice)

        // Installed again: recognised, the notice and the notes gone.
        poll(m, eslogger(recognised))
        XCTAssertFalse(m.notRecognised)
        XCTAssertNil(m.notRecognisedText)
        XCTAssertNil(m.accessNotice)
        XCTAssertNil(m.unavailableNote(.alerts))
    }

    func testNotRecognisedWhereQuestionsCanStillArrive() throws {
        // A source that holds accesses (the native one, in a VM): questions still come, and can be denied.
        let m = AppModel(language: .en)
        poll(m, withStatus(unrecognised) { $0.sourceCanEnforce = true })
        let notice = try XCTUnwrap(m.notRecognisedText)
        XCTAssertTrue(notice.contains("Questions still arrive"), notice)
        XCTAssertTrue(notice.contains("sudo whoread asks"), notice)
        let zh = AppModel(language: .zhHans)
        poll(zh, withStatus(unrecognised) { $0.sourceCanEnforce = true })
        XCTAssertTrue(try XCTUnwrap(zh.notRecognisedText).contains("问题仍会出现"))
    }

    func testNotRecognisedThroughTheExtensionKeepsTheLimitedView() throws {
        let m = AppModel(language: .en)
        m.viaExtension = true
        poll(m, unrecognised)
        XCTAssertTrue(m.notRecognised)
        XCTAssertNil(m.notRecognisedText, "scripts/install.sh does not set up the system extension")
        let limited = try XCTUnwrap(m.limitedViewText)
        XCTAssertEqual(m.accessNotice, limited)
        XCTAssertTrue(try XCTUnwrap(m.unavailableNote(.alerts)).contains("signed WhoRead app"))
    }

    func testRefusalsThatAreNotAboutThisAppRaiseNoNotice() throws {
        // Another user came to the console between two reads: refused for that, not for the app's identity.
        var s = Snapshot()
        s.status = core.status()
        s.failures[.alerts] = IPCError(.notPermitted, "only root or the console user may talk to the WhoRead daemon")
        let m = AppModel(language: .en)
        m.apply(s)
        XCTAssertFalse(m.notRecognised)
        XCTAssertNil(m.notRecognisedText)
        // Refusals of what is open to the console user never come from the app's identity either.
        var t = Snapshot()
        t.status = core.status()
        t.failures[.settings] = IPCError(.notPermitted, "refused")
        let n = AppModel(language: .en)
        n.apply(t)
        XCTAssertFalse(n.notRecognised)

        // The daemon stops answering: not "not recognised", and the refusals kept from before say nothing.
        let gone = AppModel(language: .en)
        poll(gone, unrecognised)
        XCTAssertTrue(gone.notRecognised)
        var down = Snapshot()
        down.error = IPCError(.unavailable, "XPC: Couldn't communicate with a helper application.")
        gone.apply(down)
        XCTAssertFalse(gone.notRecognised)
        XCTAssertNil(gone.notRecognisedText)
        XCTAssertNil(gone.accessNotice)
    }

    func testUnreachableSaysTheDaemonMayBeRefusingARebuiltApp() throws {
        let m = AppModel(language: .en)
        XCTAssertNil(m.unreachableText, "nothing is known before the first poll")
        var down = Snapshot()
        down.error = IPCError(.unavailable, "XPC: Couldn't communicate with a helper application.")
        m.apply(down)
        // An app the client requirement no longer admits has its connection dropped by XPC: no answer.
        let text = try XCTUnwrap(m.unreachableText)
        XCTAssertTrue(text.contains("scripts/install.sh"), text)
        XCTAssertTrue(text.contains("rebuilt or replaced after installing"), text)
        XCTAssertTrue(text.contains("sudo launchctl print system/com.whoread.daemon"), text)
        m.viaExtension = true
        XCTAssertEqual(m.unreachableText, L10n.t(.errUnavailable, .en))
        // Answering again: nothing to say.
        poll(m, recognised)
        XCTAssertNil(m.unreachableText)
        let zh = AppModel(language: .zhHans)
        zh.apply(down)
        XCTAssertTrue(try XCTUnwrap(zh.unreachableText).contains("scripts/install.sh"))
    }

    // MARK: - The enforcement switches in monitor-only mode

    func testMonitorOnlyEnforcementSwitchCannotBeTurnedOnAndSaysWhy() throws {
        let m = AppModel(language: .en)
        poll(m, eslogger(recognised))
        XCTAssertTrue(m.monitorOnly)
        XCTAssertFalse(m.enforcementSwitchOn)
        XCTAssertFalse(m.enforcementSwitchUsable, "nothing could block")
        let why = try XCTUnwrap(m.blockingUnavailableText)
        XCTAssertTrue(why.contains("eslogger"), why)
        XCTAssertTrue(why.contains("signed release"), why)
        XCTAssertNotEqual(L10n.t(.blockingUnavailableNote, .zhHans), why)

        // Switched on before (the setting is kept): it can always be turned off.
        poll(m, eslogger(recognised, enforcementEnabled: true))
        XCTAssertTrue(m.enforcementSwitchOn)
        XCTAssertTrue(m.enforcementSwitchUsable)
        XCTAssertNotNil(m.blockingUnavailableText)

        // Not monitor-only: the switch works as before, without the note.
        let native = AppModel(language: .en)
        poll(native, withStatus(recognised) { $0.source = .native; $0.sourceCanEnforce = true })
        XCTAssertFalse(native.monitorOnly)
        XCTAssertTrue(native.enforcementSwitchUsable)
        XCTAssertNil(native.blockingUnavailableText)
        m.viaExtension = true
        XCTAssertNil(m.blockingUnavailableText)
    }

    // MARK: - Open at login

    private final class FakeLoginItem: LoginItemService {
        var status: LoginItemStatus
        var registerError: Error?
        var unregisterError: Error?
        /// What registering leads to.
        var registered: LoginItemStatus = .enabled
        var calls: [String] = []

        init(_ status: LoginItemStatus) { self.status = status }

        func register() throws {
            calls.append("register")
            if let registerError { throw registerError }
            status = registered
        }

        /// Unregistering throws `unregisterError` and still takes the login item away.
        var removedDespiteError = false

        func unregister() throws {
            calls.append("unregister")
            if let unregisterError {
                if removedDespiteError { status = .notRegistered }
                throw unregisterError
            }
            status = .notRegistered
        }

        func openSystemSettingsLoginItems() { calls.append("settings") }
    }

    /// The flag as UserDefaults would keep it across launches.
    private final class Flag {
        var value = false
    }

    private func makeItem(_ service: FakeLoginItem, _ flag: Flag) -> OpenAtLogin {
        OpenAtLogin(service: service, isHandled: { flag.value }, markHandled: { flag.value = true })
    }

    private static func failure(_ text: String) -> NSError {
        NSError(domain: "SMAppServiceErrorDomain", code: 3, userInfo: [NSLocalizedDescriptionKey: text])
    }

    func testTheFirstLaunchRegistersOnceAndNeverOverridesTheUser() {
        let service = FakeLoginItem(.notRegistered)
        let flag = Flag()
        let first = makeItem(service, flag)
        first.appLaunched()
        XCTAssertEqual(service.calls, ["register"])
        XCTAssertTrue(flag.value)
        XCTAssertTrue(first.isOn)
        XCTAssertNil(first.note(.en))

        // The user turns it off in System Settings: macOS then reports it as waiting for approval.
        service.status = .requiresApproval
        let second = makeItem(service, flag)
        second.appLaunched()
        XCTAssertEqual(service.calls, ["register"], "not registered again")
        XCTAssertFalse(second.isOn)
        XCTAssertEqual(second.note(.en), L10n.t(.loginItemNeedsApproval, .en))
        // Removed altogether: not registered again either.
        service.status = .notRegistered
        makeItem(service, flag).appLaunched()
        XCTAssertEqual(service.calls, ["register"])
    }

    func testAFirstLaunchLeavesALoginItemThatAlreadyExists() {
        // An earlier copy registered it, and the user turned it off in System Settings.
        let service = FakeLoginItem(.requiresApproval)
        let flag = Flag()
        makeItem(service, flag).appLaunched()
        XCTAssertEqual(service.calls, [])
        XCTAssertTrue(flag.value)
        let enabled = FakeLoginItem(.enabled)
        let other = Flag()
        makeItem(enabled, other).appLaunched()
        XCTAssertEqual(enabled.calls, [])
        XCTAssertTrue(other.value)
    }

    func testAFailedFirstRegistrationIsTriedAgainAtTheNextLaunch() throws {
        let service = FakeLoginItem(.notRegistered)
        service.registerError = Self.failure("The operation couldn\u{2019}t be completed.\nInvalid signature")
        let flag = Flag()
        let first = makeItem(service, flag)
        first.appLaunched()
        XCTAssertEqual(service.calls, ["register"])
        XCTAssertFalse(flag.value, "nothing was registered that the user could have turned off")
        XCTAssertFalse(first.isOn)
        let note = try XCTUnwrap(first.note(.en))
        XCTAssertTrue(note.hasPrefix("Open at login could not be changed: "), note)
        XCTAssertTrue(note.contains("\\u{a}Invalid signature"), "the system's words, escaped: \(note)")

        service.registerError = nil
        let second = makeItem(service, flag)
        second.appLaunched()
        XCTAssertEqual(service.calls, ["register", "register"])
        XCTAssertTrue(flag.value)
        XCTAssertTrue(second.isOn)
    }

    func testTheSwitchRegistersUnregistersAndSendsTheUserToSystemSettings() throws {
        let service = FakeLoginItem(.enabled)
        let flag = Flag()
        let login = makeItem(service, flag)
        login.refresh()
        XCTAssertTrue(login.isOn)

        login.set(false)
        XCTAssertEqual(service.calls, ["unregister"])
        XCTAssertFalse(login.isOn)
        XCTAssertTrue(flag.value, "the user decides from now on: no launch registers it again")
        login.appLaunched()
        XCTAssertEqual(service.calls, ["unregister"])

        login.set(true)
        XCTAssertEqual(service.calls, ["unregister", "register"])
        XCTAssertTrue(login.isOn)

        // Turned off in System Settings: only the user can allow it again, there.
        service.status = .requiresApproval
        login.refresh()
        XCTAssertFalse(login.isOn)
        login.set(true)
        XCTAssertEqual(service.calls, ["unregister", "register", "settings"])
        XCTAssertNil(login.failure)

        // Registered, but macOS asks for approval first: System Settings opens, once.
        let pending = FakeLoginItem(.notRegistered)
        pending.registered = .requiresApproval
        let other = makeItem(pending, Flag())
        other.set(true)
        XCTAssertEqual(pending.calls, ["register", "settings"])
        XCTAssertEqual(other.note(.zhHans), L10n.t(.loginItemNeedsApproval, .zhHans))
        other.openSystemSettings()
        XCTAssertEqual(pending.calls, ["register", "settings", "settings"])
    }

    func testOnlyAFailureThatChangedNothingIsShown() throws {
        // "Already registered" and "not registered" leave it as asked: nothing to say.
        let enabled = FakeLoginItem(.enabled)
        enabled.registerError = Self.failure("already registered")
        let on = makeItem(enabled, Flag())
        on.set(true)
        XCTAssertTrue(on.isOn)
        XCTAssertNil(on.note(.en))
        let off = FakeLoginItem(.notRegistered)
        off.unregisterError = Self.failure("not found")
        let none = makeItem(off, Flag())
        none.set(false)
        XCTAssertNil(none.note(.en))

        // A switch that did not move says why, in the UI language; the next change that works clears it.
        let broken = FakeLoginItem(.notRegistered)
        broken.registerError = Self.failure("Operation not permitted")
        let login = makeItem(broken, Flag())
        login.set(true)
        XCTAssertFalse(login.isOn)
        XCTAssertEqual(login.note(.en), "Open at login could not be changed: Operation not permitted")
        XCTAssertEqual(login.note(.zhHans), "无法更改「登录时打开」：Operation not permitted")
        broken.registerError = nil
        login.set(true)
        XCTAssertTrue(login.isOn)
        XCTAssertNil(login.note(.en))
    }

    func testUninstallTakesTheLoginItemBackAndALaterInstallRegistersAgain() {
        for status in [LoginItemStatus.enabled, .requiresApproval] {
            let service = FakeLoginItem(status)
            let flag = Flag()
            flag.value = true
            let item = makeItem(service, flag)
            XCTAssertTrue(item.uninstall(forgetHandled: { flag.value = false }), "\(status)")
            XCTAssertEqual(service.calls, ["unregister"], "\(status)")
            XCTAssertEqual(service.status, .notRegistered)
            XCTAssertFalse(flag.value, "a later install counts as a first launch")
            // Installed again: its first launch registers it.
            makeItem(service, flag).appLaunched()
            XCTAssertEqual(service.calls, ["unregister", "register"], "\(status)")
        }
        // Nothing registered: nothing to take back, and still forgotten.
        for status in [LoginItemStatus.notRegistered, .notFound] {
            let service = FakeLoginItem(status)
            let flag = Flag()
            flag.value = true
            XCTAssertTrue(makeItem(service, flag).uninstall(forgetHandled: { flag.value = false }))
            XCTAssertEqual(service.calls, [])
            XCTAssertFalse(flag.value)
        }
    }

    func testAnUninstallThatMacOSRefusesSaysWhyAndKeepsTheFlag() {
        let service = FakeLoginItem(.enabled)
        service.unregisterError = Self.failure("Operation not permitted")
        let flag = Flag()
        flag.value = true
        let item = makeItem(service, flag)
        XCTAssertFalse(item.uninstall(forgetHandled: { flag.value = false }))
        XCTAssertTrue(flag.value, "still registered: not a first launch next time")
        XCTAssertEqual(item.note(.en), "Open at login could not be changed: Operation not permitted")
        // An error that still took it away counts as done.
        let gone = FakeLoginItem(.enabled)
        gone.unregisterError = Self.failure("not found")
        gone.removedDespiteError = true
        let goneFlag = Flag()
        goneFlag.value = true
        let goneItem = makeItem(gone, goneFlag)
        XCTAssertTrue(goneItem.uninstall(forgetHandled: { goneFlag.value = false }))
        XCTAssertFalse(goneFlag.value)
        XCTAssertNil(goneItem.note(.en))
        XCTAssertEqual(OpenAtLogin.unregisterArgument, "--unregister-login-item",
                       "scripts/uninstall.sh passes this argument")
    }
}
