// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadUIModel

struct SettingsView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @State private var draft: Settings?
    @State private var newRoot = ""

    var body: some View {
        Group {
            if let base = model.settings {
                let binding = Binding(get: { draft ?? base }, set: { draft = $0 })
                form(binding, base: base)
            } else {
                ProgressView()
            }
        }
    }

    @ViewBuilder
    func form(_ s: Binding<Settings>, base: Settings) -> some View {
        Form {
            Section(L10n.t(.setMonitoredPaths)) {
                ForEach(model.catalog?.catalog.categories ?? [], id: \.id) { c in
                    HStack {
                        Toggle(c.name.resolve(model.language), isOn: Binding(
                            get: { c.enabled },
                            set: { on in
                                guard var catalog = model.catalog?.catalog,
                                      let i = catalog.categories.firstIndex(where: { $0.id == c.id }) else { return }
                                catalog.categories[i].enabled = on
                                connection.save(catalog: catalog)
                            }))
                        Spacer()
                        SeverityBadge(severity: c.severity)
                        Text((model.catalog?.detected[c.id] ?? false) ? L10n.t(.detected) : L10n.t(.notDetected))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .help(c.paths.joined(separator: "\n"))
                }
            }
            Section(L10n.t(.setProjectRoots)) {
                Text(L10n.t(.setProjectRootsNote)).font(.caption).foregroundStyle(.secondary)
                ForEach(s.wrappedValue.projectRoots, id: \.self) { root in
                    HStack {
                        Text(root)
                        Spacer()
                        Button(L10n.t(.remove)) { s.wrappedValue.projectRoots.removeAll { $0 == root } }
                    }
                }
                HStack {
                    TextField("~/code", text: $newRoot)
                    Button(L10n.t(.add)) {
                        guard !newRoot.isEmpty else { return }
                        s.wrappedValue.projectRoots.append(newRoot)
                        newRoot = ""
                    }
                }
            }
            Section(L10n.t(.setLearning)) {
                Stepper(value: s.learningDays, in: 0...90, step: 1) {
                    Text("\(L10n.t(.setLearningDays)): \(Int(s.wrappedValue.learningDays))")
                }
                Button(L10n.t(.setRestartLearning)) { connection.restartLearning() }
                Stepper(value: s.coalesceMinutes, in: 1...240, step: 1) {
                    Text("\(L10n.t(.setCoalesce)): \(Int(s.wrappedValue.coalesceMinutes))")
                }
            }
            Section(L10n.t(.setRetention)) {
                Stepper(value: s.retentionDays, in: 1...365) { Text("\(L10n.t(.setRetentionDays)): \(s.wrappedValue.retentionDays)") }
                Stepper(value: s.detailDays, in: 1...365) { Text("\(L10n.t(.setDetailDays)): \(s.wrappedValue.detailDays)") }
                Toggle(L10n.t(.setReaddir), isOn: s.readdirEnabled)
            }
            Section(L10n.t(.setNotifications)) {
                Toggle(L10n.t(.setNotificationsEnabled), isOn: s.notifications.enabled)
                Picker(L10n.t(.setMinSeverity), selection: s.notifications.minimumSeverity) {
                    ForEach(Severity.allCases, id: \.self) { Text(L10n.severity($0)).tag($0) }
                }
                Toggle(L10n.t(.setNotifyWouldBlock), isOn: s.notifications.notifyWouldBlock)
            }
            Section(L10n.t(.setEnforcement)) {
                Toggle(L10n.t(.setEnforcementMaster), isOn: Binding(
                    get: { model.status?.enforcementEnabled ?? false },
                    set: { connection.setEnforcement($0) }))
                Text(L10n.t(.setEnforcementNote)).font(.caption).foregroundStyle(.secondary)
                Stepper(value: s.latencyP99ThresholdMs, in: 1...1000, step: 5) {
                    Text("\(L10n.t(.setLatency)): \(Int(s.wrappedValue.latencyP99ThresholdMs))")
                }
            }
            Section(L10n.t(.setLanguage)) {
                Picker(L10n.t(.setLanguage), selection: s.language) {
                    Text(L10n.t(.setLanguageSystem)).tag(Language?.none)
                    Text("English").tag(Language?.some(.en))
                    Text("简体中文").tag(Language?.some(.zhHans))
                }
            }
            HStack {
                if let err = connection.lastActionError { Text(err).font(.caption).foregroundStyle(.red) }
                Spacer()
                Button(L10n.t(.revert)) { draft = nil }.disabled(draft == nil)
                Button(L10n.t(.save)) {
                    if let d = draft { connection.save(settings: d) }
                    draft = nil
                }
                .keyboardShortcut(.defaultAction)
                .disabled(draft == nil || draft == base)
            }
        }
        .formStyle(.grouped)
    }
}
