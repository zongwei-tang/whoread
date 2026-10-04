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
            // Catalog edits are saved at once (read-modify-write on the daemon's current catalog);
            // they are not part of the Save button's draft.
            Section(L10n.t(.setMonitoredPaths)) {
                Text(L10n.t(.setMonitoredPathsNote)).font(.caption).foregroundStyle(.secondary)
                ForEach(model.catalog?.catalog.categories ?? [], id: \.id) { c in
                    CategoryEditor(category: c, detected: model.catalog?.detected[c.id] ?? false)
                }
                NewCategoryForm()
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
                        guard let root = CatalogEdit.validPath(newRoot) else { return }
                        if !s.wrappedValue.projectRoots.contains(root) { s.wrappedValue.projectRoots.append(root) }
                        newRoot = ""
                    }
                    .disabled(CatalogEdit.validPath(newRoot) == nil)
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
                // Its own request, not part of the draft. Shows what is in effect.
                Toggle(L10n.t(.setEnforcementMaster), isOn: Binding(
                    get: { model.enforcementSwitchOn },
                    set: { connection.setEnforcement($0) }))
                if let inactive = model.enforcementInactiveText {
                    Text(inactive).font(.caption).foregroundStyle(.orange)
                }
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
                    guard let d = draft else { return }
                    // Enforcement and pause come from the daemon's current state, not the draft;
                    // the draft is kept if the daemon refuses.
                    connection.save(settings: model.preparedForSave(d)) { draft = nil }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(draft.map { model.preparedForSave($0) == base } ?? true)
            }
        }
        .formStyle(.grouped)
    }
}

/// One catalog category: on/off, severity and paths (brief §1: users can add, edit and delete).
struct CategoryEditor: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    let category: CategorySpec
    let detected: Bool
    @State private var expanded = false
    @State private var newPath = ""

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            Picker(L10n.t(.colSeverity), selection: Binding(
                get: { category.severity },
                set: { connection.edit(catalog: [.setSeverity(categoryID: category.id, $0)]) })) {
                ForEach(Severity.allCases, id: \.self) { Text(L10n.severity($0)).tag($0) }
            }
            if CatalogEdit.pathsEditable(category) {
                ForEach(category.paths, id: \.self) { path in
                    HStack {
                        Text(path).textSelection(.enabled)
                        Spacer()
                        Button(L10n.t(.remove)) { connection.edit(catalog: [.removePath(categoryID: category.id, path)]) }
                    }
                }
                HStack {
                    TextField(L10n.t(.catPathPlaceholder), text: $newPath)
                    Button(L10n.t(.add)) {
                        connection.edit(catalog: [.addPath(categoryID: category.id, newPath)])
                        newPath = ""
                    }
                    .disabled(CatalogEdit.validPath(newPath) == nil)
                }
                if !newPath.isEmpty && CatalogEdit.validPath(newPath) == nil {
                    Text(L10n.t(.catInvalidPath)).font(.caption).foregroundStyle(.red)
                }
            } else {
                Text(L10n.t(.catPathsManaged)).font(.caption).foregroundStyle(.secondary)
            }
            if CatalogEdit.isUserCategory(category) {
                Button(L10n.t(.catDeleteCategory), role: .destructive) {
                    connection.edit(catalog: [.deleteCategory(id: category.id)])
                }
            }
        } label: {
            HStack {
                Toggle(category.name.resolve(model.language), isOn: Binding(
                    get: { category.enabled },
                    set: { connection.edit(catalog: [.setEnabled(categoryID: category.id, $0)]) }))
                Spacer()
                SeverityBadge(severity: category.severity)
                Text(detected ? L10n.t(.detected) : L10n.t(.notDetected)).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// "Add category": a user category (kind custom) with a name, a severity and a first path.
struct NewCategoryForm: View {
    @Environment(DaemonConnection.self) private var connection
    @State private var name = ""
    @State private var path = ""
    @State private var severity: Severity = .high

    private var nameOK: Bool { !name.trimmingCharacters(in: .whitespaces).isEmpty }
    private var pathOK: Bool { path.trimmingCharacters(in: .whitespaces).isEmpty || CatalogEdit.validPath(path) != nil }

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField(L10n.t(.catNewCategoryName), text: $name)
                TextField(L10n.t(.catPathPlaceholder), text: $path)
                Picker(L10n.t(.colSeverity), selection: $severity) {
                    ForEach(Severity.allCases, id: \.self) { Text(L10n.severity($0)).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Button(L10n.t(.catAddCategory)) {
                    connection.edit(catalog: [.addCategory(id: CatalogEdit.newCategoryID(), name: name, severity: severity, path: path)])
                    name = ""
                    path = ""
                }
                .disabled(!nameOK || !pathOK)
            }
            if !pathOK {
                Text(L10n.t(.catInvalidPath)).font(.caption).foregroundStyle(.red)
            }
        }
    }
}
