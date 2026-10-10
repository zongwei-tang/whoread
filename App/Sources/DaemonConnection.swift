// NOT YET COMPILED (see WhoReadApp.swift).
import AppKit
import Foundation
import Observation
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

/// Talks to the daemon over XPC, polls it, and applies snapshots to the model on the main thread.
///
/// Two connections, each with its own queue and timer. The questions' connection reads the open
/// questions (every second, every 250 ms while any is open) and carries the answers. The other one
/// polls the status and history and carries every other change. The daemon serves each connection's
/// messages one at a time, so a slow history read (a store busy writing a burst of events) never
/// delays a question or an answer, and a refused one never hides them.
@MainActor
@Observable
final class DaemonConnection {
    static let shared = DaemonConnection()

    let model = AppModel()
    var onboarding = OnboardingModel()
    var lastActionError: String?
    private(set) var machServiceName: String
    /// Status, history and every change other than answers.
    @ObservationIgnored private var client: XPCClient
    /// The open questions and the answers to them.
    @ObservationIgnored private var askClient: XPCClient
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var askTimer: Timer?
    @ObservationIgnored private var askTimerInterval: TimeInterval = 0
    @ObservationIgnored private var schedule = PollSchedule()
    @ObservationIgnored private var inFlight = false
    @ObservationIgnored private var askInFlight = false
    /// Reopen a connection the daemon did not take for the app (a wrong guess when it was accepted).
    @ObservationIgnored private var recovery = ConnectionRecovery()
    @ObservationIgnored private var askRecovery = ConnectionRecovery()
    /// Whether the daemon serves the current questions' connection as the app (nil: not known yet).
    @ObservationIgnored private var askClientServedAsApp: Bool?
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
    @ObservationIgnored private let askQueue = DispatchQueue(label: "whoread.app.asks")

    init() {
        // Not `client = XPCClient(machServiceName: machServiceName)`: with @Observable that reads
        // self before every stored property is initialized.
        let name = DaemonConnection.resolveServiceName()
        machServiceName = name
        client = XPCClient(machServiceName: name)
        askClient = XPCClient(machServiceName: name)
    }

    /// The system extension's Mach service from Info.plist (nil when the build has none).
    static var extensionServiceName: String? {
        guard let s = Bundle.main.object(forInfoDictionaryKey: "WhoReadMachServiceName") as? String, !s.isEmpty, !s.hasPrefix(".") else {
            return nil
        }
        return s
    }

    /// The running daemon writes its service name; otherwise the app's Info.plist (system
    /// extension), otherwise the dev LaunchDaemon default.
    static func resolveServiceName() -> String {
        if let s = try? String(contentsOfFile: WhoReadPaths.dataDirectory + "/mach-service", encoding: .utf8) {
            let name = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if !name.isEmpty { return name }
        }
        return extensionServiceName ?? WhoReadPaths.machServiceName
    }

    /// The daemon answers on the system extension's service.
    var connectedViaExtension: Bool { machServiceName == DaemonConnection.extensionServiceName }

    func start() {
        pollAsks()
        poll(full: true)
        armTimers()
    }

    /// Status and history every second; the questions every second, every 250 ms while any is open
    /// (that timer is re-armed when it changes).
    private func armTimers() {
        if timer == nil {
            timer = Timer.scheduledTimer(withTimeInterval: PollSchedule.idleInterval, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.timerFired() }
            }
        }
        let interval = model.pollInterval
        guard askTimer == nil || interval != askTimerInterval else { return }
        askTimer?.invalidate()
        askTimerInterval = interval
        askTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollAsks() }
        }
    }

    private func timerFired() {
        // Until settings arrive, every poll is full: notifications are planned only with settings.
        poll(full: schedule.kind(now: Date(), needsFull: model.settings == nil) == .full)
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

    /// The open questions, on their own connection: answered ones disappear and their banners are
    /// withdrawn within a quarter second, whatever the status and history poll is doing.
    private func pollAsks() {
        guard !askInFlight else { return }
        askInFlight = true
        let client = askClient
        let check = askClientServedAsApp == nil
        askQueue.async {
            let poll = SnapshotFetcher.fetchAsks(client)
            // Once per connection, before any question needs an "allow" on it; only after a read that
            // was answered (a daemon that does not answer would make an answer queued here wait twice).
            var served: Bool?
            if check, case .asks = poll { served = SnapshotFetcher.isServedAsApp(client) }
            Task { @MainActor in
                self.askInFlight = false
                if let served, client === self.askClient { self.askClientServedAsApp = served }
                self.received(asks: poll)
            }
        }
    }

    private func received(asks poll: AskPoll) {
        model.apply(asks: poll)
        if case .failed(let e) = poll {
            // Banners stay: the questions may still be open, and a refused answer says so.
            if e.code == .unavailable {
                // The next message may reach a new daemon instance: a new decision whether this is the app.
                askClientServedAsApp = nil
                reresolveService()
            }
            // A reply this app cannot read: the next poll's handshake gives the reason in words.
            if e.code == .versionMismatch, model.versionProblem == nil { needsHello = true }
        } else {
            planAsks()
            // Paths hidden, or the check refused: the daemon did not take this connection for the app.
            let refused = model.asksPathsHidden || askClientServedAsApp == false
            if askRecovery.shouldReconnect(now: Date(), refused: refused) { reconnect(questions: true) }
        }
        armTimers()
    }

    /// Re-resolves the service: the system extension may have started after us.
    private func reresolveService() {
        let name = DaemonConnection.resolveServiceName()
        guard name != machServiceName else { return }
        machServiceName = name
        reconnect(questions: false)
        reconnect(questions: true)
    }

    /// A new connection (a new decision whether it is the app). The old one is closed after what
    /// was already queued on it: an answer or a change in flight is not cut off.
    private func reconnect(questions: Bool) {
        let fresh = XPCClient(machServiceName: machServiceName)
        let old: XPCClient
        if questions {
            old = askClient
            askClient = fresh
            askClientServedAsApp = nil
            askQueue.async { old.invalidate() }
        } else {
            old = client
            client = fresh
            queue.async { old.invalidate() }
        }
    }

    private func received(_ snapshot: Snapshot) {
        if snapshot.error?.code == .unavailable {
            needsHello = true
            reresolveService()
        } else if snapshot.handshake != nil {
            needsHello = false
        } else if model.versionProblem == nil,
                  snapshot.error?.code == .versionMismatch || snapshot.failures.values.contains(where: { $0.code == .versionMismatch }) {
            // An answer this app cannot read, from a daemon it has not greeted (replaced between
            // two polls): the handshake gives the reason in words instead of a decoder dump.
            needsHello = true
        }
        model.apply(snapshot)
        if model.daemonRestarts != daemonRestarts {
            // Another daemon instance (maybe another version): handshake again, and check again whether
            // it takes the questions' connection for the app.
            daemonRestarts = model.daemonRestarts
            needsHello = true
            askClientServedAsApp = nil
        }
        L10n.current = model.language
        if registeredLanguage != model.language {
            // Notification buttons follow the language chosen in Settings.
            registeredLanguage = model.language
            NotificationManager.shared.registerCategories(language: model.language)
        }
        armTimers()
        // History refused: the daemon did not take this connection for the app (or this is not the
        // signed app; then the retries back off to every 10 minutes).
        if recovery.shouldReconnect(now: Date(), refused: snapshot.refusedRecordedRead) { reconnect(questions: false) }
        guard snapshot.error == nil else { return }
        if let status = model.status { planNotices(status) }
        if let settings = model.settings {
            // Only alerts read by this poll (nil when refused or failed): the first read seeds.
            for n in planner.plan(snapshot.alerts, settings: settings.notifications, formatter: model.formatter,
                                  agentName: model.agentName) {
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
        // Before the first full poll, category and AI agent names are not known yet: such banners are
        // replaced once they are.
        let plan = planner.plan(asks: model.asks, formatter: model.formatter, complete: complete, agentName: model.agentName,
                                namesKnown: model.catalog != nil && model.agents != nil)
        NotificationManager.shared.remove(asks: plan.remove)
        for n in plan.post { NotificationManager.shared.post(n) }
        if complete && !staleAsksWithdrawn {
            staleAsksWithdrawn = true
            NotificationManager.shared.removeDeliveredAsks(keeping: Set(model.asks.map { NotificationPlanner.askIdentifier($0.id) }))
        }
    }

    /// Runs a request off the main thread, applies the daemon's answer, then refreshes.
    /// `failed` describes a refusal (default: `L10n.message(for:)`) and may act on it. `questions`: on
    /// the questions' connection (an answer), never queued behind a history read.
    private func run(_ work: @escaping @Sendable (XPCClient) throws -> IPCResponse, questions: Bool = false,
                     failed: ((IPCError) -> String)? = nil, then: (() -> Void)? = nil) {
        let client = questions ? askClient : self.client
        (questions ? askQueue : queue).async {
            var response: IPCResponse?
            var failure: IPCError?
            do {
                response = try work(client)
            } catch let e as IPCError {
                failure = e
            } catch let e as DecodingError {
                // A reply in a shape this app does not know: another version, not a refusal.
                failure = SnapshotFetcher.ipcError(e)
            } catch {
                failure = IPCError(.internalError, "\(error)")
            }
            Task { @MainActor in
                if let failure {
                    self.lastActionError = failed?(failure) ?? L10n.message(for: failure)
                } else {
                    self.lastActionError = nil
                    if let response { self.model.apply(response: response) }
                    then?()
                }
                if questions { self.pollAsks() }
                self.poll(full: true)
            }
        }
    }

    func perform(_ request: IPCRequest, then: (() -> Void)? = nil) {
        run({ try $0.call(request) }, then: then)
    }

    /// `fromNotification`: the user answered a banner, so explain there if "block from now on"
    /// saved a rule that cannot block right now. A question's alert is answered like the question, on
    /// the questions' connection.
    func act(on alert: Int64, _ action: AlertAction, fromNotification: Bool = false) {
        let kind = model.alerts.first { $0.id == alert }?.kind
        run({ try $0.call(.alertAction(alertID: alert, action: action)) }, questions: kind == .ask, failed: { e in
            // The rule limit, an answer applied but not saved, no reply: said as such, not "refused".
            let text = L10n.alertActionError(e, alertID: alert, action: action, kind: kind)
            if fromNotification {
                NotificationManager.shared.post(SystemNotice(identifier: "whoread.alert-failed-\(alert)",
                                                             title: L10n.t(.notifAskFailedTitle), body: text), tab: .alerts)
            }
            return text
        }) {
            guard fromNotification, action == .blockFromNowOn, let caveat = self.model.enforcementCaveat else { return }
            NotificationManager.shared.post(SystemNotice(identifier: "whoread.rule-not-blocking-\(alert)",
                                                         title: L10n.t(.notifRuleNotBlockingTitle), body: caveat), tab: .rules)
        }
    }

    /// Answers an ask-mode question, on the questions' connection (never queued behind a history
    /// read). Allowing needs the signed app (or root): an unrecognised build is refused, and the error
    /// says how to allow from Terminal instead. `fromNotification`: the user answered a banner, so a
    /// refusal is posted as a notice too (the menu may not be open).
    func answer(ask id: Int64, _ action: AlertAction, fromNotification: Bool = false) {
        let client = askClient
        askQueue.async {
            var response: IPCResponse?
            var failure: IPCError?
            do { response = try client.call(.answerAsk(id: id, action: action)) } catch { failure = SnapshotFetcher.ipcError(error) }
            Task { @MainActor in
                if let failure {
                    let text = L10n.answerError(failure, askID: id, action: action)
                    self.lastActionError = text
                    // Allowing refused: this connection may not have been taken for the app.
                    if failure.code == .notPermitted, AskAnswers.isAllow(action),
                       self.askRecovery.shouldReconnect(now: Date(), refused: true) {
                        self.reconnect(questions: true)
                    }
                    if fromNotification {
                        NotificationManager.shared.post(SystemNotice(identifier: "whoread.ask-failed-\(id)",
                                                                     title: L10n.t(.notifAskFailedTitle), body: text), tab: .alerts)
                    }
                } else {
                    self.lastActionError = nil
                    if let response {
                        // The questions still open: the answered one's banner is withdrawn now.
                        self.model.apply(response: response)
                        self.planAsks()
                    }
                }
                self.pollAsks()
                // An answer saves a rule (or a setting) and settles alerts.
                self.poll(full: true)
            }
        }
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
        run({ try RuleSave.save(rule, with: $0) }, then: then)
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
