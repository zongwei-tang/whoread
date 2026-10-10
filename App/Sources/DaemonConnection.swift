// NOT YET COMPILED (see WhoReadApp.swift).
import AppKit
import Foundation
import Observation
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

/// Talks to the daemon over XPC, polls it, and applies snapshots to the model on the main thread.
@MainActor
@Observable
final class DaemonConnection {
    static let shared = DaemonConnection()

    let model = AppModel()
    var onboarding = OnboardingModel()
    var lastActionError: String?
    private(set) var machServiceName: String
    @ObservationIgnored private var client: XPCClient
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var timerInterval: TimeInterval = 0
    @ObservationIgnored private var schedule = PollSchedule()
    @ObservationIgnored private var inFlight = false
    /// A full refresh was asked for while a poll was running: run it right after.
    @ObservationIgnored private var pendingFull = false
    /// Send `.hello` with the next poll: first poll, reconnect, new daemon instance.
    @ObservationIgnored private var needsHello = true
    @ObservationIgnored private var daemonRestarts = 0
    @ObservationIgnored private var registeredLanguage: Language?
    @ObservationIgnored private let planner = NotificationPlanner(
        notifiedUncleanStop: UserDefaults.standard.string(forKey: DaemonConnection.notifiedUncleanStopKey))
    /// The unclean stop already notified: the daemon reports it while that instance runs, and a
    /// relaunch must not repeat the notice.
    private static let notifiedUncleanStopKey = "NotifiedUncleanStop"
    /// Question banners left by a previous run of the app are withdrawn after the first poll.
    @ObservationIgnored private var staleAsksWithdrawn = false
    @ObservationIgnored private let queue = DispatchQueue(label: "whoread.app.ipc")

    init() {
        // Not `client = XPCClient(machServiceName: machServiceName)`: with @Observable that reads
        // self before every stored property is initialized.
        let name = DaemonConnection.resolveServiceName()
        machServiceName = name
        client = XPCClient(machServiceName: name)
    }

    /// The system extension's Mach service from Info.plist (nil when the build has none).
    static var extensionServiceName: String? {
        guard let s = Bundle.main.object(forInfoDictionaryKey: "WhoReadMachServiceName") as? String, !s.isEmpty, !s.hasPrefix(".") else {
            return nil
        }
        return s
    }

    /// The running daemon writes its service name; otherwise the app's Info.plist (system
    /// extension), otherwise the dev LaunchDaemon default. The written name counts only when root
    /// alone could have written it: a name someone else left there could lead the app to another
    /// service (daemonfs-3).
    static func resolveServiceName() -> String {
        if let name = try? TrustedFile.machServiceName(inDataDirectory: WhoReadPaths.dataDirectory) {
            return name
        }
        return extensionServiceName ?? WhoReadPaths.machServiceName
    }

    /// The daemon answers on the system extension's service.
    var connectedViaExtension: Bool { machServiceName == DaemonConnection.extensionServiceName }

    func start() {
        poll(full: true)
        armTimer()
    }

    /// Polls every second, every 250 ms while questions are open; re-armed when that changes.
    private func armTimer() {
        let interval = model.pollInterval
        guard timer == nil || interval != timerInterval else { return }
        timer?.invalidate()
        timerInterval = interval
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.timerFired() }
        }
    }

    private func timerFired() {
        // Until settings arrive, every poll is full: notifications are planned only with settings.
        switch schedule.kind(now: Date(), openAsks: model.asks.count, needsFull: model.settings == nil) {
        case .full: poll(full: true)
        // Only between successful polls: a handshake or an error is left to the fast poll.
        case .asks where !needsHello && model.lastError == nil: pollAsks()
        case .fast, .asks: poll(full: false)
        }
    }

    func poll(full: Bool) {
        guard !inFlight else {
            if full { pendingFull = true }
            return
        }
        let full = full || pendingFull
        pendingFull = false
        inFlight = true
        if full { schedule.fullStarted(at: Date()) } else { schedule.fastStarted(at: Date()) }
        let client = self.client
        let cursor = model.liveCursor
        let benign = model.showSystemNoise
        let hello = needsHello
        queue.async {
            let snapshot = SnapshotFetcher.fetch(client, liveAfter: cursor, includeBenign: benign, full: full, hello: hello)
            Task { @MainActor in
                self.inFlight = false
                self.received(snapshot)
                if self.pendingFull { self.poll(full: true) }
            }
        }
    }

    /// Only the open questions (the 250 ms ticks between fast polls): answered ones disappear and
    /// their banners are withdrawn without fetching the alerts four times a second.
    private func pollAsks() {
        guard !inFlight else { return }
        inFlight = true
        let client = self.client
        queue.async {
            let asks = SnapshotFetcher.fetchAsks(client)
            Task { @MainActor in
                self.inFlight = false
                if let asks {
                    self.model.apply(response: .asks(asks))
                    self.planAsks()
                    self.armTimer()
                }
                if self.pendingFull { self.poll(full: true) }
            }
        }
    }

    private func received(_ snapshot: Snapshot) {
        if snapshot.error?.code == .unavailable {
            needsHello = true
            // Re-resolve: the system extension may have started after us.
            let name = DaemonConnection.resolveServiceName()
            if name != machServiceName {
                machServiceName = name
                client.invalidate()
                client = XPCClient(machServiceName: name)
            }
        } else if snapshot.handshake != nil {
            needsHello = false
        } else if snapshot.error?.code == .versionMismatch, model.versionProblem == nil {
            // An answer this app cannot read, from a daemon it has not greeted (replaced between
            // two polls): the handshake gives the reason in words instead of a decoder dump.
            needsHello = true
        }
        model.apply(snapshot)
        if model.daemonRestarts != daemonRestarts {
            // Another daemon instance (maybe another version): handshake again.
            daemonRestarts = model.daemonRestarts
            needsHello = true
        }
        L10n.current = model.language
        if registeredLanguage != model.language {
            // Notification buttons follow the language chosen in Settings.
            registeredLanguage = model.language
            NotificationManager.shared.registerCategories(language: model.language)
        }
        armTimer()
        guard snapshot.error == nil else { return }
        if let status = model.status { planNotices(status) }
        planAsks()
        if let settings = model.settings {
            for n in planner.plan(model.alerts, settings: settings.notifications, formatter: model.formatter) {
                NotificationManager.shared.post(n)
            }
        }
    }

    private func planNotices(_ status: DaemonStatus) {
        for notice in planner.plan(status: status, language: model.language) {
            NotificationManager.shared.post(notice, tab: .settings)
        }
        let defaults = UserDefaults.standard
        guard defaults.string(forKey: DaemonConnection.notifiedUncleanStopKey) != planner.notifiedUncleanStop else { return }
        if let stop = planner.notifiedUncleanStop {
            defaults.set(stop, forKey: DaemonConnection.notifiedUncleanStopKey)
        } else {
            defaults.removeObject(forKey: DaemonConnection.notifiedUncleanStopKey)
        }
    }

    /// One banner per open question; banners of questions no longer open are withdrawn.
    private func planAsks() {
        // The daemon lists at most 200 questions; a capped reply must not withdraw banners.
        let complete = model.asks.count < 200 && (model.status?.pendingAsks ?? 0) <= model.asks.count
        let plan = planner.plan(asks: model.asks, formatter: model.formatter, complete: complete, agentName: model.agentName)
        NotificationManager.shared.remove(asks: plan.remove)
        for n in plan.post { NotificationManager.shared.post(n) }
        if complete && !staleAsksWithdrawn {
            staleAsksWithdrawn = true
            NotificationManager.shared.removeDeliveredAsks(keeping: Set(model.asks.map { NotificationPlanner.askIdentifier($0.id) }))
        }
    }

    /// Runs a request off the main thread, applies the daemon's answer, then refreshes.
    /// `failed` describes a refusal (default: `L10n.message(for:)`) and may act on it.
    private func run(_ work: @escaping @Sendable (XPCClient) throws -> IPCResponse,
                     failed: ((IPCError) -> String)? = nil, then: (() -> Void)? = nil) {
        let client = self.client
        queue.async {
            var response: IPCResponse?
            var failure: IPCError?
            do { response = try work(client) } catch let e as IPCError { failure = e } catch { failure = IPCError(.internalError, "\(error)") }
            Task { @MainActor in
                if let failure {
                    self.lastActionError = failed?(failure) ?? L10n.message(for: failure)
                } else {
                    self.lastActionError = nil
                    if let response { self.model.apply(response: response) }
                    then?()
                }
                self.poll(full: true)
            }
        }
    }

    func perform(_ request: IPCRequest, then: (() -> Void)? = nil) {
        run({ try $0.call(request) }, then: then)
    }

    /// `fromNotification`: the user answered a banner, so explain there if "block from now on"
    /// saved a rule that cannot block right now.
    func act(on alert: Int64, _ action: AlertAction, fromNotification: Bool = false) {
        perform(.alertAction(alertID: alert, action: action)) {
            guard fromNotification, action == .blockFromNowOn, let caveat = self.model.enforcementCaveat else { return }
            NotificationManager.shared.post(SystemNotice(identifier: "whoread.rule-not-blocking-\(alert)",
                                                         title: L10n.t(.notifRuleNotBlockingTitle), body: caveat), tab: .rules)
        }
    }

    /// Answers an ask-mode question. Allowing needs the signed app (or root): an unsigned build is
    /// refused, and the error says how to allow from Terminal instead. `fromNotification`: the user
    /// answered a banner, so a refusal is posted as a notice too (the menu may not be open).
    func answer(ask id: Int64, _ action: AlertAction, fromNotification: Bool = false) {
        run({ try $0.call(.answerAsk(id: id, action: action)) }, failed: { e in
            let text = L10n.answerError(e, askID: id, action: action)
            if fromNotification {
                NotificationManager.shared.post(SystemNotice(identifier: "whoread.ask-failed-\(id)",
                                                             title: L10n.t(.notifAskFailedTitle), body: text), tab: .alerts)
            }
            return text
        })
    }

    /// The "trust all Apple programs" switch: its own request on the daemon's current settings (not
    /// part of the Settings draft). Turning it on weakens protection: root or the signed app only.
    func setTrustApplePrograms(_ on: Bool) {
        run { client in
            var s = try client.settings()
            s.trustApplePrograms = on
            return try client.call(.updateSettings(s))
        }
    }

    func markAllRead() { perform(.markAlertsRead(ids: nil)) }
    func setPaused(_ paused: Bool) { perform(.setPaused(paused)) }
    /// Applied to the daemon's current rule, fetched right before saving (as catalog edits are):
    /// the engine changes exceptions and use counts on its own, and the model's copy can be up to
    /// 10 s old. `then` runs only if the daemon accepted the rule.
    func save(rule: Rule, then: (() -> Void)? = nil) {
        run({ client in
            let current = try client.rules().first { $0.id == rule.id }
            return try client.call(.upsertRule(rule.keepingDaemonState(of: current)))
        }, then: then)
    }

    /// The rule row's switch: flips `enabled` on the daemon's current copy, nothing else.
    func setEnabled(_ on: Bool, rule id: String) {
        run { client in
            guard var r = try client.rules().first(where: { $0.id == id }) else { throw IPCError(.notFound, "no rule \(id)") }
            r.enabled = on
            return try client.call(.upsertRule(r))
        }
    }
    func delete(rule id: String) { perform(.deleteRule(id: id)) }
    /// `then` runs only if the daemon accepted the settings. "Trust all Apple programs" has its own
    /// switch (and answer): it is taken from the daemon's settings fetched right before saving, as
    /// the model's copy can be up to 10 s old and must not switch it back on (or off).
    func save(settings: Settings, then: (() -> Void)? = nil) {
        run({ client in
            var s = settings
            s.trustApplePrograms = try client.settings().trustApplePrograms
            return try client.call(.updateSettings(s))
        }, then: then)
    }

    /// Catalog edits are applied to the catalog fetched right before saving (read-modify-write
    /// on the IPC queue), never to the model's copy, which can be up to 10 s old.
    func edit(catalog edits: [CatalogEdit]) {
        run { client in
            let current = try client.catalog().catalog
            return try client.call(.updateCatalog(current.applying(edits)))
        }
    }

    func setEnforcement(_ on: Bool) {
        if on { return enableEnforcement() }
        // Turning it off must always work, and at once: its own connection with a short timeout
        // (never queued behind a poll). If the daemon refuses (app not verified) or does not
        // answer, fall back to the kill-switch file, created with administrator rights.
        let name = machServiceName
        DispatchQueue.global(qos: .userInitiated).async {
            let c = XPCClient(machServiceName: name, timeout: 2)
            let refused: Bool
            do { _ = try c.call(.setEnforcement(enabled: false)); refused = false } catch { refused = true }
            c.invalidate()
            Task { @MainActor in
                if refused { self.engageKillSwitchWithAdminRights() }
                self.poll(full: true)
            }
        }
    }

    private func enableEnforcement() {
        if model.status?.killSwitchFilePresent == true {
            // The UI's own fallback (or `whoread kill-switch engage`) left the file: remove it.
            guard runAsAdministrator("/bin/rm -f '\(DaemonConnection.quoted(WhoReadPaths.killSwitchFile))'") else { return }
        }
        perform(.setEnforcement(enabled: true))
    }

    /// Kill switch #3 (file) from the UI: asks for an administrator password via AppleScript.
    func engageKillSwitchWithAdminRights() {
        _ = runAsAdministrator("/usr/bin/touch '\(DaemonConnection.quoted(WhoReadPaths.killSwitchFile))'")
    }

    private static func quoted(_ path: String) -> String { path.replacingOccurrences(of: "'", with: "") }

    /// Returns false (and sets `lastActionError`, unless the user cancelled) on failure.
    private func runAsAdministrator(_ command: String) -> Bool {
        var error: NSDictionary?
        NSAppleScript(source: "do shell script \"\(command)\" with administrator privileges")?.executeAndReturnError(&error)
        guard let error else { return true }
        // -128: the user cancelled the password prompt.
        if (error[NSAppleScript.errorNumber] as? Int) != -128 {
            lastActionError = L10n.f(.errAdminFormat, (error[NSAppleScript.errorMessage] as? String) ?? "\(error)")
        }
        return false
    }

    func openFullDiskAccessSettings() {
        for s in OnboardingModel.fullDiskAccessURLs {
            if let url = URL(string: s), NSWorkspace.shared.open(url) { return }
        }
    }
}
