import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

/// What the app says about its own setup while the dev LaunchDaemon cannot be reached, does not recognise
/// the app, or runs the native source, and the names of the rules that answers save. Reads and refusals
/// come from the daemon's real permission table (ServiceHandler, strict), as in InstallUIModelTests.
final class SetupUIModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var handler: ServiceHandler!
    /// The app as a dev daemon sees it when it accepts the connection but does not take it for the app: one
    /// installed without pinned requirements, or a wrong guess when the connection was accepted.
    var unrecognised: IPCClient!
    /// The app the daemon recognises.
    var recognised: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-setup-ui-\(UUID().uuidString.prefix(6))")
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

    /// The dev LaunchDaemon monitoring with eslogger, as scripts/install.sh sets it up.
    private func eslogger(_ inner: IPCClient) -> IPCClient {
        withStatus(inner) {
            $0.source = .eslogger
            $0.sourceRunning = true
            $0.sourceCanEnforce = false
        }
    }

    /// The dev LaunchDaemon with the native source (a VM with SIP disabled), which can hold accesses.
    private func native(_ inner: IPCClient) -> IPCClient {
        withStatus(inner) {
            $0.source = .native
            $0.sourceRunning = true
            $0.sourceCanEnforce = true
        }
    }

    /// One tick of the app: the questions on their own connection, then status and history.
    private func poll(_ m: AppModel, _ client: IPCClient, full: Bool = true) {
        m.apply(asks: SnapshotFetcher.fetchAsks(client))
        m.apply(SnapshotFetcher.fetch(client, liveAfter: m.liveCursor, includeBenign: false, full: full, hello: true))
    }

    private static let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app",
                                                    displayName: "Terminal", path: "/System/Applications/Utilities/Terminal.app")

    /// A question holding an access to the test vault, as the native source opens one (Terminal → zsh → cat).
    private func openQuestion(access: AccessSet = .read) throws -> Int64 {
        let q = AskRequest(id: 0, key: AskKey(responsibleKey: Self.terminal.key, categoryID: "test-vault", access: access, chainAgents: []),
                           responsible: Self.terminal, severity: .critical, path: "/Users/alice/WhoReadTestVault/notes/setup-check.txt",
                           process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: [], agentID: nil,
                           appleProgram: false, firstAt: Date(), lastAt: Date())
        core.askBroker.noteAnsweringClient()
        guard case .held(let id) = core.askBroker.hold(q, budget: 60, respond: { _ in }) else {
            XCTFail("not held")
            return 0
        }
        return id
    }

    /// The daemon's refusal of `request` from `client` (nil when it was taken).
    private func refusal(_ request: IPCRequest, _ client: IPCClient) -> IPCError? {
        do {
            _ = try client.call(request)
            return nil
        } catch let e as IPCError {
            return e
        } catch {
            XCTFail("\(error)")
            return nil
        }
    }

    // MARK: - onboarding-daemon-down-extension-flow

    func testABuildThatCannotInstallTheExtensionKeepsTheMonitorOnlyStepsWhileTheDaemonIsDown() throws {
        let o = OnboardingModel()
        var seen = core.status()
        seen.source = .eslogger
        seen.sourceRunning = true
        seen.sourceError = nil
        // Not answering: before the first answer (no status yet), and after one (its status is kept). A
        // daemon that is not running, restarting, or refusing this app all look like this to the app.
        for status in [nil, seen] as [DaemonStatus?] {
            XCTAssertEqual(o.extensionStepState(status, connected: false, viaExtension: false, canInstallExtension: false), .notAvailable,
                           "no Install button: this build cannot install the extension")
            XCTAssertTrue(OnboardingModel.showsMonitorOnly(status, connected: false, viaExtension: false, canInstallExtension: false))
        }
        // Whatever this session's own request did.
        for state in [OnboardingModel.StepState.waiting, .failed("x"), .needsRestart, .done] {
            XCTAssertEqual(OnboardingModel(extensionState: state).extensionStepState(nil, connected: false, viaExtension: false,
                                                                                    canInstallExtension: false), .notAvailable, "\(state)")
        }
        // Answering: the same steps, so they do not change with every daemon restart.
        XCTAssertEqual(o.extensionStepState(seen, connected: true, viaExtension: false, canInstallExtension: false), .notAvailable)
        XCTAssertTrue(OnboardingModel.showsMonitorOnly(seen, connected: true, viaExtension: false, canInstallExtension: false))

        // As the app sees it: answering, then the daemon restarts (kickstarted by scripts/install.sh while it
        // waits for Full Disk Access) and the app gets no answer for a while.
        let m = AppModel(language: .en)
        poll(m, eslogger(recognised))
        XCTAssertTrue(m.connected)
        var down = Snapshot()
        down.error = IPCError(.unavailable, "XPC: Couldn't communicate with a helper application.")
        m.apply(down)
        XCTAssertFalse(m.connected)
        let monitorOnly = OnboardingModel.showsMonitorOnly(m.status, connected: m.connected, viaExtension: m.viaExtension,
                                                           canInstallExtension: false)
        XCTAssertTrue(monitorOnly)
        // Full Disk Access for the daemon's executable (not "turn on WhoRead"), and no promise to ask.
        XCTAssertEqual(OnboardingModel.fullDiskAccessBody(monitorOnly: monitorOnly, .en),
                       L10n.f(.onbFDABodyDaemonFormat, OnboardingModel.daemonExecutablePath, language: .en))
        XCTAssertEqual(OnboardingModel.daemonBody(monitorOnly: monitorOnly, .zhHans), L10n.t(.onbDaemonBodyMonitorOnly, .zhHans))
        XCTAssertEqual(OnboardingModel.extensionBody(monitorOnly: monitorOnly, .en), L10n.t(.onbExtNotAvailableBody, .en))

        // A build that can install the extension: the extension's steps until the daemon says otherwise.
        XCTAssertEqual(o.extensionStepState(nil, connected: false, viaExtension: false, canInstallExtension: true), .pending)
        XCTAssertFalse(OnboardingModel.showsMonitorOnly(nil, connected: false, viaExtension: false, canInstallExtension: true))
        XCTAssertFalse(OnboardingModel.showsMonitorOnly(seen, connected: false, viaExtension: false, canInstallExtension: true))
        XCTAssertTrue(OnboardingModel.showsMonitorOnly(seen, connected: true, viaExtension: false, canInstallExtension: true))
        XCTAssertFalse(OnboardingModel.showsMonitorOnly(seen, connected: true, viaExtension: true, canInstallExtension: true))
    }

    func testABuildThatCannotInstallTheExtensionShowsTheNativeDevDaemonAsDoingItsJob() {
        // The native source of the dev daemon (a VM with SIP disabled) monitors and blocks as the extension
        // would: the usual steps, also while it restarts (its status is kept).
        let o = OnboardingModel()
        var status = core.status()
        status.source = .native
        status.sourceRunning = true
        status.sourceCanEnforce = true
        for connected in [true, false] {
            XCTAssertEqual(o.extensionStepState(status, connected: connected, viaExtension: false, canInstallExtension: false), .done,
                           "connected: \(connected)")
            XCTAssertFalse(OnboardingModel.showsMonitorOnly(status, connected: connected, viaExtension: false, canInstallExtension: false),
                           "it can block: not \"This build does not block\"")
        }
    }

    // MARK: - selfcheck-rebuilt-app-unreachable

    func testSelfCheckOfAProgramTheDevDaemonMayBeRefusingSaysSo() {
        // The installer pins the app's code identity in the daemon's client requirement: XPC drops each
        // connection of a rebuilt or replaced app, which reaches the app as no answer at the handshake.
        let refused = FixedClient { _ in throw IPCError(.unavailable, "XPC: Couldn't communicate with a helper application.") }
        let r = SelfCheck.run(refused, asRoot: false)
        XCTAssertEqual(r.lines, ["daemon: unreachable (XPC: Couldn't communicate with a helper application.; if com.whoread.daemon is "
                                 + "running, it may be refusing this program: run scripts/install.sh again, which is needed when the app "
                                 + "was rebuilt or replaced after installing)"])
        XCTAssertEqual(r.outcome, .unreachable)
        XCTAssertEqual(r.exitStatus, 1)
        // Through the system extension: scripts/install.sh does not set that up.
        XCTAssertEqual(SelfCheck.run(refused, viaExtension: true, asRoot: false).lines,
                       ["daemon: unreachable (XPC: Couldn't communicate with a helper application.)"])

        // Not when the daemon answered the handshake: another user at the screen, another protocol, or no
        // answer after the handshake (the daemon took this program's messages).
        handler.consoleUID = { geteuid() &+ 1 }
        XCTAssertEqual(SelfCheck.run(unrecognised, asRoot: false).lines,
                       ["daemon: unreachable (only root or the console user may talk to the WhoRead daemon)"])
        handler.consoleUID = { geteuid() }
        XCTAssertEqual(SelfCheck.run(FixedClient { _ in .error(IPCError(.versionMismatch, "client speaks protocol 3, daemon 4")) },
                                     asRoot: false).lines,
                       ["daemon: unreachable (protocol mismatch: client speaks protocol 3, daemon 4)"])
        let silent = FixedClient { request in
            if case .status = request { throw IPCError(.unavailable, "daemon did not answer within 10 s (com.whoread.daemon.xpc)") }
            return try self.recognised.send(request)
        }
        XCTAssertEqual(SelfCheck.run(silent, asRoot: false).lines,
                       ["daemon: unreachable (daemon did not answer within 10 s (com.whoread.daemon.xpc))"])
    }

    // MARK: - notice-native-dev-daemon-install-sh

    func testNotRecognisedByTheNativeDevDaemonSaysToInstallItAsItWasInstalled() throws {
        // scripts/install.sh installs the eslogger source and needs Xcode, which the test VM does not have:
        // following it would fail there, or replace the native source.
        let m = AppModel(language: .en)
        poll(m, native(unrecognised))
        XCTAssertTrue(m.notRecognised)
        let notice = try XCTUnwrap(m.notRecognisedText)
        XCTAssertFalse(notice.contains("scripts/install.sh"), notice)
        XCTAssertTrue(notice.contains("sudo scripts/install-dev-daemon.sh native --app"), notice)
        XCTAssertTrue(notice.hasPrefix("WhoRead is not recognised by the background service, so it cannot show alerts"), notice)
        // The native source holds accesses: questions still arrive.
        XCTAssertTrue(notice.contains("Questions still arrive"), notice)

        let zh = AppModel(language: .zhHans)
        poll(zh, native(unrecognised))
        let zhNotice = try XCTUnwrap(zh.notRecognisedText)
        XCTAssertFalse(zhNotice.contains("scripts/install.sh"), zhNotice)
        XCTAssertTrue(zhNotice.contains("sudo scripts/install-dev-daemon.sh native --app"), zhNotice)
        XCTAssertTrue(zhNotice.hasPrefix("WhoRead 未被后台服务识别"), zhNotice)

        // The self-check says the same.
        let r = SelfCheck.run(native(unrecognised), asRoot: false)
        XCTAssertEqual(r.exitStatus, 2)
        XCTAssertEqual(r.lines.count, 3)
        XCTAssertFalse(r.lines[2].contains("scripts/install.sh"), r.lines[2])
        XCTAssertTrue(r.lines[2].hasPrefix("app recognised: no (the daemon does not take this program for the WhoRead app it was "
                                           + "installed with: "), r.lines[2])
        XCTAssertTrue(r.lines[2].contains("sudo scripts/install-dev-daemon.sh native --app"), r.lines[2])

        // With eslogger, the advice stays scripts/install.sh.
        let es = AppModel(language: .en)
        poll(es, eslogger(unrecognised))
        XCTAssertTrue(try XCTUnwrap(es.notRecognisedText).contains("Run scripts/install.sh again"))
        XCTAssertTrue(try XCTUnwrap(SelfCheck.run(eslogger(unrecognised), asRoot: false).lines.last).contains("run scripts/install.sh again"))
    }

    // MARK: - not-recognised-action-errors-signed-app

    func testRefusedChangesPointAtTheNoticeWhileTheDevDaemonDoesNotRecogniseTheApp() throws {
        let m = AppModel(language: .en)
        poll(m, eslogger(unrecognised))
        XCTAssertNotNil(m.notRecognisedText)

        // Pause monitoring (menu bar), Save in Settings: changes that weaken protection, refused.
        let pause = try XCTUnwrap(refusal(.setPaused(true), unrecognised))
        XCTAssertEqual(pause.code, .notPermitted)
        var settings = try XCTUnwrap(m.settings)
        settings.retentionDays += 1
        let save = try XCTUnwrap(refusal(.updateSettings(settings), unrecognised))
        // Always allow on an alert, and allow once on a question.
        let alert = try XCTUnwrap(try recognised.alerts(AlertQuery(limit: 10)).first)
        let always = try XCTUnwrap(refusal(.alertAction(alertID: alert.id, action: .alwaysAllow), unrecognised))
        let id = try openQuestion()
        let allow = try XCTUnwrap(refusal(.answerAsk(id: id, action: .allowOnce), unrecognised))

        let texts = [m.actionError(pause), m.actionError(save),
                     m.alertActionError(always, alertID: alert.id, action: .alwaysAllow, kind: alert.kind),
                     m.answerError(allow, askID: id, action: .allowOnce)]
        for text in texts {
            // A dev install has no "signed WhoRead app": the notice on top says what is wrong and what fixes it.
            XCTAssertFalse(text.contains("signed WhoRead app"), text)
            XCTAssertTrue(text.contains("the background service does not recognise this app (see the notice about it)"), text)
        }
        // The Terminal commands stay.
        XCTAssertTrue(texts[2].hasSuffix("In Terminal: sudo whoread alert \(alert.id) always-allow"), texts[2])
        XCTAssertTrue(texts[3].contains("The question is still open."), texts[3])
        XCTAssertTrue(texts[3].hasSuffix("In Terminal: sudo whoread ask \(id) allow-once"), texts[3])

        let zh = AppModel(language: .zhHans)
        poll(zh, eslogger(unrecognised))
        for text in [zh.actionError(pause), zh.alertActionError(always, alertID: alert.id, action: .alwaysAllow, kind: alert.kind),
                     zh.answerError(allow, askID: id, action: .allowOnce)] {
            XCTAssertFalse(text.contains("已签名的 WhoRead 应用"), text)
            XCTAssertTrue(text.contains("后台服务没有识别出这个应用（见相关提示）"), text)
        }

        // Refusals that are not about this app keep their words: another user at the screen, and the
        // daemon's own reason for a change that strengthens protection.
        let other = IPCError(.notPermitted, "only root or the console user may talk to the WhoRead daemon")
        XCTAssertEqual(m.actionError(other), L10n.t(.errNotConsoleUser, .en))
        XCTAssertEqual(m.answerError(other, askID: id, action: .allowOnce), L10n.t(.errNotConsoleUser, .en))
        let rules = IPCError(.notPermitted, "the stored rules could not be loaded; only root or the WhoRead app may replace them")
        XCTAssertEqual(m.alertActionError(rules, alertID: alert.id, action: .blockFromNowOn, kind: alert.kind),
                       L10n.f(.errDaemonFormat, rules.message, language: .en))
        XCTAssertEqual(m.answerError(rules, askID: id, action: .keepBlocking), L10n.f(.errDaemonFormat, rules.message, language: .en))

        // No notice, no change: the app recognised, or the system extension (its limited view speaks of the
        // signed app, which a release has).
        let ok = AppModel(language: .en)
        poll(ok, eslogger(recognised))
        XCTAssertEqual(ok.actionError(pause), L10n.message(for: pause, .en))
        let ext = AppModel(language: .en)
        ext.viaExtension = true
        poll(ext, unrecognised)
        XCTAssertNotNil(ext.limitedViewText)
        XCTAssertEqual(ext.actionError(pause), L10n.message(for: pause, .en))
        XCTAssertEqual(ext.alertActionError(always, alertID: alert.id, action: .alwaysAllow, kind: alert.kind),
                       L10n.alertActionError(always, alertID: alert.id, action: .alwaysAllow, kind: alert.kind, .en))
        XCTAssertEqual(ext.answerError(allow, askID: id, action: .allowOnce), L10n.answerError(allow, askID: id, action: .allowOnce, .en))
    }

    // MARK: - fda-step-stale-entry

    func testTheMonitorOnlyFullDiskAccessStepHasTheInstallersSteps() throws {
        // scripts/install.sh: remove the entry an earlier install left (a rebuilt whoreadd is another program
        // to macOS), add whoreadd, and when that is not enough, /usr/bin/eslogger too.
        let script = try String(contentsOf: repoRoot.appendingPathComponent("scripts/install.sh"), encoding: .utf8)
        XCTAssertTrue(script.contains("If whoreadd is in the list already (from an earlier install), select it and click - first."))
        XCTAssertTrue(script.contains("add /usr/bin/eslogger the same way and switch it on too"))
        XCTAssertTrue(script.contains("如果列表里已经有 whoreadd（以前装过），先选中它，点 - 删掉。"))

        for language in [Language.en, .zhHans] {
            let body = OnboardingModel.fullDiskAccessBody(monitorOnly: true, language)
            let remove = try XCTUnwrap(body.range(of: "−"), "\(language): no step to remove the old entry: \(body)")
            let add = try XCTUnwrap(body.range(of: "+"), body)
            XCTAssertLessThan(remove.lowerBound, add.lowerBound, "\(language): the old entry goes first: \(body)")
            XCTAssertTrue(body.contains(OnboardingModel.daemonExecutablePath), body)
            XCTAssertTrue(body.contains("/usr/bin/eslogger"), "\(language): \(body)")
        }
        XCTAssertTrue(OnboardingModel.fullDiskAccessBody(monitorOnly: true, .en).contains("If whoreadd is in the list already"))
        XCTAssertTrue(OnboardingModel.fullDiskAccessBody(monitorOnly: true, .zhHans).contains("如果列表里已经有 whoreadd"))
    }

    // MARK: - app-9: answer rules in the UI language

    func testTheRulesAnswersSaveAreNamedInTheUILanguage() throws {
        // Saved by the daemon in English (DaemonCore.answerRuleEdit): allow once, always allow a write, and
        // always allow both.
        let once = try openQuestion(access: .read)
        let write = try openQuestion(access: .write)
        let both = try openQuestion(access: .readWrite)
        _ = try recognised.call(.answerAsk(id: once, action: .allowOnce))
        _ = try recognised.call(.answerAsk(id: write, action: .alwaysAllow))
        _ = try recognised.call(.answerAsk(id: both, action: .alwaysAllow))

        let zh = AppModel(language: .zhHans)
        poll(zh, recognised)
        let vault = try XCTUnwrap(zh.catalog?.catalog.category("test-vault")?.name)
        let answers = zh.rules.filter { $0.template == RuleTemplates.askAnswer }
        XCTAssertEqual(answers.count, 3)
        func rule(_ access: RuleAccess) throws -> Rule { try XCTUnwrap(answers.first { $0.access == access }, "\(access)") }
        let read = try rule(.read), written = try rule(.write), any = try rule(.any)
        // What the daemon calls them.
        XCTAssertEqual(read.name, "Allow Terminal to read \(vault.en) (10 minutes)")
        XCTAssertEqual(written.name, "Allow Terminal to write \(vault.en)")
        XCTAssertEqual(any.name, "Allow Terminal to use \(vault.en)")

        XCTAssertEqual(zh.ruleName(read), "允许 Terminal 读取 \(vault.zhHans)（10 分钟）")
        XCTAssertEqual(zh.ruleName(written), "允许 Terminal 写入 \(vault.zhHans)")
        XCTAssertEqual(zh.ruleName(any), "允许 Terminal 使用 \(vault.zhHans)")
        // In English, as saved.
        let en = AppModel(language: .en)
        poll(en, recognised)
        for r in [read, written, any] { XCTAssertEqual(en.ruleName(r), r.name) }

        // A name the user gave, or one that no longer fits the rule, is shown as it is.
        var renamed = written
        renamed.name = "Terminal may write the vault"
        XCTAssertEqual(zh.ruleName(renamed), "Terminal may write the vault")
        var otherAccess = written
        otherAccess.access = .read
        XCTAssertEqual(zh.ruleName(otherAccess), written.name)
        // The app's part is the name it gave itself: escaped, as everywhere.
        var odd = read
        odd.name = "Allow Term\u{202E}inal to read \(vault.en) (10 minutes)"
        XCTAssertEqual(zh.ruleName(odd), "允许 Term\\u{202e}inal 读取 \(vault.zhHans)（10 分钟）")
    }
}
