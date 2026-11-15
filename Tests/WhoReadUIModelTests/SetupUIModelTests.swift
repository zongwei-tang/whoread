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
}
