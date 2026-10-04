// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadUIModel

/// FDA → system extension → monitoring running. Each step re-checks live (the model polls the
/// daemon every second).
struct OnboardingView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let o = connection.onboarding
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.t(.onbTitle)).font(.largeTitle.weight(.semibold))
            Text(L10n.t(.onbIntro)).foregroundStyle(.secondary)
            step(1, L10n.t(.onbExtTitle), L10n.t(.onbExtBody), state: o.extensionState) {
                Button(L10n.t(.onbExtButton)) { SystemExtensionManager.shared.activate() }
                if o.extensionState == .waiting {
                    Text(L10n.t(.onbExtApprove)).font(.caption).foregroundStyle(.secondary)
                    Button(L10n.t(.onbFDAButton)) {
                        if let url = URL(string: OnboardingModel.loginItemsExtensionsURL) { NSWorkspace.shared.open(url) }
                    }
                }
            }
            step(2, L10n.t(.onbFDATitle), L10n.t(.onbFDABody), state: o.fullDiskAccessState(model.status, connected: model.connected)) {
                Button(L10n.t(.onbFDAButton)) { connection.openFullDiskAccessSettings() }
            }
            step(3, L10n.t(.onbDaemonTitle), L10n.t(.onbDaemonBody), state: o.daemonState(model.status, connected: model.connected)) {
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
                Text(body).font(.callout).foregroundStyle(.secondary)
                if case .failed(let reason) = state {
                    Text(L10n.f(.onbFailedFormat, reason)).font(.caption).foregroundStyle(.red)
                }
                if state != .done { HStack { actions() } }
            }
        }
    }

    @ViewBuilder
    func stateIcon(_ s: OnboardingModel.StepState) -> some View {
        switch s {
        case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .waiting: ProgressView().controlSize(.small)
        case .pending: Image(systemName: "circle").foregroundStyle(.secondary)
        case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        }
    }
}
