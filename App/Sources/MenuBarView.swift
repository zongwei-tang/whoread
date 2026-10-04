// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadUIModel

/// The menu bar popover: state, unread alerts, quick switches.
struct MenuBarView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            if model.connected, let status = model.status {
                quickToggles(status)
                Divider()
                recentAlerts
            } else {
                Text(L10n.t(.errUnavailable)).foregroundStyle(.secondary)
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
    }

    private var header: some View {
        HStack {
            Image(systemName: model.menuBar.symbol).font(.title2)
            VStack(alignment: .leading) {
                Text(L10n.t(.appName)).font(.headline)
                Text(model.menuBar.title).foregroundStyle(.secondary)
                if let s = model.status, s.learning {
                    Text(L10n.f(.learningUntilFormat, s.learningEndsAt.formatted(date: .abbreviated, time: .omitted)))
                        .font(.caption).foregroundStyle(.secondary)
                }
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
            Toggle(L10n.t(.enforcement), isOn: Binding(
                get: { status.enforcementEnabled },
                set: { connection.setEnforcement($0) }))
            if status.enforcementEnabled && !status.enforcementActive {
                Text(L10n.f(.enforcementInactiveFormat, status.enforcementInactiveReasons.map(\.rawValue).joined(separator: ", ")))
                    .font(.caption).foregroundStyle(.orange)
            }
            if status.enforcementActive {
                Button(L10n.t(.killSwitchAdmin)) { connection.engageKillSwitchWithAdminRights() }
                    .font(.caption)
            }
            if let err = connection.lastActionError {
                Text(err).font(.caption).foregroundStyle(.red)
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
