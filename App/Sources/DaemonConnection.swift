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
    @ObservationIgnored private var tick = 0
    @ObservationIgnored private var inFlight = false
    /// A full refresh was asked for while a poll was running: run it right after.
    @ObservationIgnored private var pendingFull = false
    /// Send `.hello` with the next poll: first poll, reconnect, new daemon instance.
    @ObservationIgnored private var needsHello = true
    @ObservationIgnored private var daemonRestarts = 0
    @ObservationIgnored private var registeredLanguage: Language?
    @ObservationIgnored private let planner = NotificationPlanner()
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
        poll(full: true)
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.timerFired() }
        }
    }

    private func timerFired() {
        tick += 1
        // Until settings arrive, every poll is full: notifications are planned only with settings.
        poll(full: tick % 10 == 0 || model.settings == nil)
    }

    func poll(full: Bool) {
        guard !inFlight else {
            if full { pendingFull = true }
            return
        }
        let full = full || pendingFull
        pendingFull = false
        inFlight = true
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
        guard snapshot.error == nil else { return }
        if let status = model.status {
            for notice in planner.plan(status: status, language: model.language) {
                NotificationManager.shared.post(notice, tab: .settings)
            }
        }
        if let settings = model.settings {
            for n in planner.plan(model.alerts, settings: settings.notifications, formatter: model.formatter) {
                NotificationManager.shared.post(n)
            }
        }
    }

    /// Runs a request off the main thread, applies the daemon's answer, then refreshes.
    private func run(_ work: @escaping @Sendable (XPCClient) throws -> IPCResponse, then: (() -> Void)? = nil) {
        let client = self.client
        queue.async {
            var response: IPCResponse?
            var failure: IPCError?
            do { response = try work(client) } catch let e as IPCError { failure = e } catch { failure = IPCError(.internalError, "\(error)") }
            Task { @MainActor in
                if let failure {
                    self.lastActionError = L10n.message(for: failure)
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

    func markAllRead() { perform(.markAlertsRead(ids: nil)) }
    func setPaused(_ paused: Bool) { perform(.setPaused(paused)) }
    func save(rule: Rule) { perform(.upsertRule(rule)) }
    func delete(rule id: String) { perform(.deleteRule(id: id)) }
    /// `then` runs only if the daemon accepted the settings.
    func save(settings: Settings, then: (() -> Void)? = nil) { perform(.updateSettings(settings), then: then) }
    func restartLearning() { perform(.restartLearning) }

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
        let status = model.status
        if status?.killSwitchFilePresent == true {
            // The UI's own fallback (or `whoread kill-switch engage`) left the file: remove it.
            guard runAsAdministrator("/bin/rm -f '\(DaemonConnection.quoted(WhoReadPaths.killSwitchFile))'") else { return }
        }
        if let status, status.enforcementEnabled, status.latencyTripReason != nil {
            // Still switched on but tripped: switching it off and on again re-arms it.
            run { client in
                _ = try? client.call(.setEnforcement(enabled: false))
                return try client.call(.setEnforcement(enabled: true))
            }
        } else {
            perform(.setEnforcement(enabled: true))
        }
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
