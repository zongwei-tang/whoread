import AppKit
import SwiftUI
import WhoReadUIModel

/// FDA → system extension → monitoring running. Each step re-checks live (the model polls the
/// daemon every second). Monitor-only mode (the dev daemon with eslogger, and any build that cannot
/// install the extension): the extension step is not available, and Full Disk Access goes to the
/// daemon's executable, not to this app.
struct OnboardingView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var pathCopied = false

    var body: some View {
        let o = connection.onboarding
        let viaExtension = connection.connectedViaExtension
        // Decided by this build first: one without the extension's service (scripts/install.sh's ad hoc
        // build) can never install it, so its steps do not change while the daemon restarts or refuses it.
        let canInstall = DaemonConnection.extensionServiceName != nil
        let monitorOnly = OnboardingModel.showsMonitorOnly(model.status, connected: model.connected, viaExtension: viaExtension,
                                                           canInstallExtension: canInstall)
        // Detected from the connection too, so an extension approved before this launch shows as done.
        let ext = o.extensionStepState(model.status, connected: model.connected, viaExtension: viaExtension,
                                       canInstallExtension: canInstall)
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.t(.onbTitle)).font(.largeTitle.weight(.semibold))
            Text(L10n.t(.onbIntro)).foregroundStyle(.secondary)
            step(1, L10n.t(.onbExtTitle), OnboardingModel.extensionBody(monitorOnly: monitorOnly), state: ext) {
                if ext != .needsRestart {
                    Button(L10n.t(.onbExtButton)) { SystemExtensionManager.shared.activate() }
                }
                if ext == .waiting {
                    Text(L10n.t(.onbExtApprove)).font(.caption).foregroundStyle(.secondary)
                    Button(L10n.t(.onbOpenLoginItems)) {
                        if let url = URL(string: OnboardingModel.loginItemsExtensionsURL) { NSWorkspace.shared.open(url) }
                    }
                }
            }
            step(2, L10n.t(.onbFDATitle), OnboardingModel.fullDiskAccessBody(monitorOnly: monitorOnly),
                 state: o.fullDiskAccessState(model.status, connected: model.connected)) {
                Button(L10n.t(.onbFDAButton)) { connection.openFullDiskAccessSettings() }
                if monitorOnly {
                    // For the + sheet's ⌘⇧G field.
                    Button(L10n.t(.onbCopyPath)) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(OnboardingModel.daemonExecutablePath, forType: .string)
                        pathCopied = true
                    }
                    if pathCopied {
                        Text(L10n.t(.onbCopied)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            step(3, L10n.t(.onbDaemonTitle), OnboardingModel.daemonBody(monitorOnly: monitorOnly),
                 state: o.daemonState(model.status, connected: model.connected)) {
                EmptyView()
            }
            HStack {
                Spacer()
                Button(o.isComplete(model.status, connected: model.connected) ? L10n.t(.onbAllSet) : L10n.t(.close)) { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 560)
    }

    @ViewBuilder
    func step<Actions: View>(_ n: Int, _ title: String, _ body: String, state: OnboardingModel.StepState,
                             @ViewBuilder actions: () -> Actions) -> some View {
        HStack(alignment: .top, spacing: 12) {
            stateIcon(state).font(.title2).frame(width: 28)
            VStack(alignment: .leading, spacing: 6) {
                Text("\(n). \(title)").font(.headline)
                Text(body).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                if case .failed(let reason) = state {
                    Text(L10n.f(.onbFailedFormat, reason)).font(.caption).foregroundStyle(.red)
                }
                if state == .needsRestart {
                    Text(L10n.t(.onbRestartRequired)).font(.caption).foregroundStyle(.orange)
                }
                // Nothing to do for a step that is done, or one this installation cannot do.
                if state != .done && state != .notAvailable { HStack { actions() } }
            }
        }
    }

    @ViewBuilder
    func stateIcon(_ s: OnboardingModel.StepState) -> some View {
        switch s {
        case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .waiting: ProgressView().controlSize(.small)
        case .pending: Image(systemName: "circle").foregroundStyle(.secondary)
        case .needsRestart: Image(systemName: "arrow.clockwise.circle.fill").foregroundStyle(.orange)
        case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        case .notAvailable: Image(systemName: "minus.circle").foregroundStyle(.secondary)
        }
    }
}
