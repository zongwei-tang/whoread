// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

/// The menu bar popover: state, open questions (first), quick switches, unread alerts.
struct MenuBarView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if let problem = model.versionProblem {
                Text(L10n.f(.errVersionMismatchFormat, problem)).font(.caption).foregroundStyle(.red)
            }
            Divider()
            if model.connected, let status = model.liveStatus {
                if !model.asks.isEmpty {
                    openAsks
                    Divider()
                }
                quickToggles(status)
                Divider()
                recentAlerts
            } else if model.connected {
                // The daemon answers but its state cannot be read (another version): no stale
                // switches, but enforcement can still be turned off.
                if model.versionProblem == nil, let e = model.lastError {
                    Text(L10n.message(for: e)).font(.caption).foregroundStyle(.red)
                }
                Button(L10n.t(.killSwitchAdmin)) { connection.engageKillSwitchWithAdminRights() }
                    .font(.caption)
                if let err = connection.lastActionError {
                    Text(err).font(.caption).foregroundStyle(.red)
                }
            } else {
                Text(L10n.t(.errUnavailable)).foregroundStyle(.secondary)
                Button(L10n.t(.openSetup)) {
                    NavigationState.shared.showOnboarding = true
                    open(.live)
                }
            }
            Divider()
            HStack {
                Button(L10n.t(.openWindow)) { open(.live) }
                Spacer()
                Button(L10n.t(.quit)) { NSApp.terminate(nil) }
            }
        }
        .padding(12)
        .frame(width: 380)
        .onAppear { NavigationState.shared.openMainWindow = { openWindow(id: "main") } }
    }

    private var header: some View {
        HStack {
            Image(systemName: model.menuBar.symbol).font(.title2)
            VStack(alignment: .leading) {
                Text(L10n.t(.appName)).font(.headline)
                Text(model.menuBar.title).foregroundStyle(.secondary)
            }
            Spacer()
            if model.unreadCount > 0 {
                Text(L10n.f(.unreadAlertsFormat, model.unreadCount)).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private func quickToggles(_ status: DaemonStatus) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle(L10n.t(.pauseMonitoring), isOn: Binding(
                get: { status.monitoringPaused },
                set: { connection.setPaused($0) }))
            // Shows what is in effect: off after the kill-switch file. Never switched off automatically.
            Toggle(L10n.t(.enforcement), isOn: Binding(
                get: { model.enforcementSwitchOn },
                set: { connection.setEnforcement($0) }))
            if let inactive = model.enforcementInactiveText {
                Text(inactive).font(.caption).foregroundStyle(.orange)
            }
            if let slow = model.slowResponsesText {
                Text(slow).font(.caption).foregroundStyle(.orange)
            }
            if let dropped = model.kernelDropsText {
                Text(dropped).font(.caption).foregroundStyle(.orange)
            }
            if status.enforcementActive {
                Button(L10n.t(.killSwitchAdmin)) { connection.engageKillSwitchWithAdminRights() }
                    .font(.caption)
            }
            // Shown with the questions while any is open (a refused answer).
            if model.asks.isEmpty, let err = connection.lastActionError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
        }
    }

    /// Questions waiting for an answer, those about to be denied first, with the answers as buttons.
    private var openAsks: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.t(.asksTitle)).font(.subheadline.weight(.semibold))
            ForEach(Array(model.asksByUrgency.prefix(3))) { ask in
                AskRow(ask: ask)
            }
            if model.asks.count > 3 {
                Button(L10n.f(.asksMoreFormat, model.asks.count - 3)) { open(.alerts) }
                    .buttonStyle(.link).font(.caption)
            }
            if let err = connection.lastActionError {
                Text(err).font(.caption).foregroundStyle(.red).textSelection(.enabled)
            }
        }
    }

    private var recentAlerts: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.t(.recentAlerts)).font(.subheadline.weight(.semibold))
            let alerts = model.alerts.prefix(5)
            if alerts.isEmpty {
                Text(L10n.t(.noAlerts)).foregroundStyle(.secondary)
            }
            ForEach(Array(alerts)) { alert in
                Button {
                    open(.alerts)
                } label: {
                    HStack(alignment: .top) {
                        Circle().fill(alert.status == .unread ? Color.red : Color.clear).frame(width: 6, height: 6).padding(.top, 5)
                        Text(model.formatter.headline(alert)).lineLimit(2).multilineTextAlignment(.leading)
                    }
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func open(_ tab: Tab) {
        NavigationState.shared.tab = tab
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
