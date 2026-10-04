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
    @ObservationIgnored private let planner = NotificationPlanner()
    @ObservationIgnored private let queue = DispatchQueue(label: "whoread.app.ipc")

    init() {
        machServiceName = DaemonConnection.resolveServiceName()
        client = XPCClient(machServiceName: machServiceName)
    }

    /// The running daemon writes its service name; otherwise the app's Info.plist (system
    /// extension), otherwise the dev LaunchDaemon default.
    static func resolveServiceName() -> String {
        if let s = try? String(contentsOfFile: WhoReadPaths.dataDirectory + "/mach-service", encoding: .utf8) {
            let name = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if !name.isEmpty { return name }
        }
        if let s = Bundle.main.object(forInfoDictionaryKey: "WhoReadMachServiceName") as? String, !s.isEmpty, !s.hasPrefix(".") {
            return s
        }
        return WhoReadPaths.machServiceName
    }

    func start() {
        poll(full: true)
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.timerFired() }
        }
    }

    private func timerFired() {
        tick += 1
        poll(full: tick % 10 == 0)
    }

    func poll(full: Bool) {
        guard !inFlight else { return }
        inFlight = true
        let client = self.client
        let cursor = model.liveCursor
        let benign = model.showSystemNoise
        queue.async {
            let snapshot = SnapshotFetcher.fetch(client, liveAfter: cursor, includeBenign: benign, full: full)
            Task { @MainActor in
                self.inFlight = false
                if snapshot.error?.code == .unavailable {
                    // Re-resolve: the system extension may have started after us.
                    let name = DaemonConnection.resolveServiceName()
                    if name != self.machServiceName {
                        self.machServiceName = name
                        self.client.invalidate()
                        self.client = XPCClient(machServiceName: name)
                    }
                }
                self.model.apply(snapshot)
                L10n.current = self.model.language
                if let settings = self.model.settings {
                    for n in self.planner.plan(self.model.alerts, settings: settings.notifications, formatter: self.model.formatter) {
                        NotificationManager.shared.post(n)
                    }
                }
            }
        }
    }

    /// Runs a request off the main thread, then refreshes.
    func perform(_ request: IPCRequest, then: (() -> Void)? = nil) {
        let client = self.client
        queue.async {
            var failure: IPCError?
            do { _ = try client.call(request) } catch let e as IPCError { failure = e } catch { failure = IPCError(.internalError, "\(error)") }
            Task { @MainActor in
                if let failure {
                    self.lastActionError = failure.code == .notPermitted ? L10n.t(.errNotPermitted) : failure.message
                } else {
                    self.lastActionError = nil
                    then?()
                }
                self.poll(full: true)
            }
        }
    }

    func act(on alert: Int64, _ action: AlertAction) { perform(.alertAction(alertID: alert, action: action)) }
    func markAllRead() { perform(.markAlertsRead(ids: nil)) }
    func setPaused(_ paused: Bool) { perform(.setPaused(paused)) }
    func save(rule: Rule) { perform(.upsertRule(rule)) }
    func delete(rule id: String) { perform(.deleteRule(id: id)) }
    func save(settings: Settings) { perform(.updateSettings(settings)) }
    func save(catalog: Catalog) { perform(.updateCatalog(catalog)) }
    func restartLearning() { perform(.restartLearning) }

    func setEnforcement(_ on: Bool) {
        if on { return perform(.setEnforcement(enabled: true)) }
        // Turning it off must always work: if the daemon refuses (app not verified), fall back
        // to the kill-switch file, created with administrator rights.
        let client = self.client
        queue.async {
            let refused: Bool
            do { _ = try client.call(.setEnforcement(enabled: false)); refused = false } catch { refused = true }
            Task { @MainActor in
                if refused { self.engageKillSwitchWithAdminRights() }
                self.poll(full: true)
            }
        }
    }

    /// Kill switch #3 (file) from the UI: asks for an administrator password via AppleScript.
    func engageKillSwitchWithAdminRights() {
        let path = WhoReadPaths.killSwitchFile.replacingOccurrences(of: "'", with: "")
        let source = "do shell script \"/usr/bin/touch '\(path)'\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        if let error { lastActionError = "\(error)" }
    }

    func openFullDiskAccessSettings() {
        for s in OnboardingModel.fullDiskAccessURLs {
            if let url = URL(string: s), NSWorkspace.shared.open(url) { return }
        }
    }
}
