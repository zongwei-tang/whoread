// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadUIModel

struct RulesView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @State private var editing: RuleDraft?

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Button(L10n.t(.addRule)) { editing = RuleDraft() }
                Menu(L10n.t(.templates)) {
                    ForEach(RuleTemplates.all, id: \.id) { t in
                        Button(model.ruleName(t)) { editing = RuleDraft(template: t) }
                    }
                }
                .fixedSize()
                Spacer()
            }
            if let caveat = model.enforcementCaveat {
                Text(caveat).font(.caption).foregroundStyle(.orange)
            }
            if let err = connection.lastActionError { Text(err).font(.caption).foregroundStyle(.red) }
            List(model.rules) { rule in
                RuleRow(rule: rule) { editing = RuleDraft(rule: rule) }
            }
        }
        .sheet(item: Binding(get: { editing.map(IdentifiedDraft.init) }, set: { editing = $0?.draft })) { item in
            RuleEditor(draft: item.draft) { result in
                if let rule = result { connection.save(rule: rule) }
                editing = nil
            }
        }
    }
}

struct IdentifiedDraft: Identifiable {
    var draft: RuleDraft
    var id: String { draft.id ?? "new" }
}

struct RuleRow: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    let rule: Rule
    let edit: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            Toggle("", isOn: Binding(get: { rule.enabled }, set: { on in
                var r = rule
                r.enabled = on
                connection.save(rule: r)
            })).labelsHidden()
            VStack(alignment: .leading, spacing: 2) {
                Text(model.ruleName(rule)).font(.body.weight(.medium))
                Text(describe(rule)).font(.caption).foregroundStyle(.secondary)
                if !rule.exceptions.isEmpty {
                    Text(L10n.f(.ruleExceptionsFormat, rule.exceptions.count)).font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if rule.action == .deny {
                Text(rule.enforce ? L10n.t(.ruleEnforce) : L10n.t(.ruleDryRun))
                    .font(.caption).foregroundStyle(rule.enforce ? .red : .orange)
            }
            Button(action: edit) { Image(systemName: "pencil") }.buttonStyle(.borderless)
            Button(role: .destructive) { connection.delete(rule: rule.id) } label: { Image(systemName: "trash") }
                .buttonStyle(.borderless)
        }
    }

    func describe(_ r: Rule) -> String {
        let action: String
        switch r.action {
        case .allow: action = L10n.t(.actionAllow)
        case .deny: action = L10n.t(.actionDeny)
        case .alert: action = L10n.t(.actionAlert)
        }
        let target: String
        switch r.target {
        case .category(let id): target = model.categoryName(id)
        case .severityAtLeast(let s): target = L10n.t(.targetSeverity) + " " + L10n.severity(s)
        case .pathPrefix(let p): target = p
        }
        let subject: String
        switch r.subject {
        case .signed(let sid, _): subject = sid
        case .unsigned(let p, _): subject = p
        case .responsible(let k, _, _, _): subject = k.replacingOccurrences(of: "app:", with: "").replacingOccurrences(of: "agent:", with: "")
        case .anyNonOwner: subject = L10n.t(.subjectAnyNonOwner)
        case .agentAncestor(let ids, _): subject = ids.map { $0.map(model.agentName).joined(separator: ", ") } ?? L10n.t(.subjectAgentChain)
        }
        let access: String
        switch r.access {
        case .read: access = L10n.t(.accessRead)
        case .write: access = L10n.t(.accessWrite)
        case .any: access = L10n.t(.accessAny)
        }
        return "\(action) · \(access) · \(target) · \(subject)"
    }
}

struct RuleEditor: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @State var draft: RuleDraft
    let done: (Rule?) -> Void

    var body: some View {
        Form {
            // Rules from a template keep its localized name until the user types one.
            TextField(L10n.t(.ruleName), text: $draft.name,
                      prompt: Text(L10n.templateName(draft.original?.template) ?? L10n.t(.ruleName)))
            Section(L10n.t(.ruleTarget)) {
                Picker(L10n.t(.ruleTarget), selection: $draft.targetKind) {
                    Text(L10n.t(.targetCategory)).tag(RuleDraft.TargetKind.category)
                    Text(L10n.t(.targetSeverity)).tag(RuleDraft.TargetKind.severity)
                    Text(L10n.t(.targetPath)).tag(RuleDraft.TargetKind.path)
                }
                switch draft.targetKind {
                case .category:
                    Picker(L10n.t(.targetCategory), selection: $draft.categoryID) {
                        ForEach(model.catalog?.catalog.categories ?? [], id: \.id) { c in Text(c.name.resolve(model.language)).tag(c.id) }
                    }
                case .severity:
                    Picker(L10n.t(.targetSeverity), selection: $draft.severity) {
                        ForEach(Severity.allCases, id: \.self) { s in Text(L10n.severity(s)).tag(s) }
                    }
                case .path:
                    TextField("~/.ssh/id_ed25519", text: $draft.pathPrefix)
                    // Only monitored paths reach the rule engine: say so, and offer to monitor it.
                    if draft.validationError() != .ruleErrPath, !model.isMonitored(pathPrefix: draft.pathPrefix) {
                        Text(L10n.t(.rulePathNotMonitored)).font(.caption).foregroundStyle(.orange)
                        if CatalogEdit.validPath(draft.pathPrefix) != nil {
                            Button(L10n.t(.ruleMonitorPath)) { connection.edit(catalog: [.monitorPath(draft.pathPrefix)]) }
                        }
                    }
                }
            }
            Section(L10n.t(.ruleSubject)) {
                Picker(L10n.t(.ruleSubject), selection: $draft.subjectKind) {
                    Text(L10n.t(.subjectAgentChain)).tag(RuleDraft.SubjectKind.agentChain)
                    Text(L10n.t(.subjectAnyNonOwner)).tag(RuleDraft.SubjectKind.anyNonOwner)
                    Text(L10n.t(.subjectApp)).tag(RuleDraft.SubjectKind.app)
                    Text(L10n.t(.subjectSigned)).tag(RuleDraft.SubjectKind.signed)
                    Text(L10n.t(.subjectUnsigned)).tag(RuleDraft.SubjectKind.unsigned)
                }
                switch draft.subjectKind {
                case .signed:
                    TextField(L10n.t(.ruleSigningID), text: $draft.signingID)
                    TextField(L10n.t(.ruleTeamID), text: $draft.teamID).disabled(draft.signedWithoutTeam)
                    Toggle(L10n.t(.ruleNoTeamID), isOn: $draft.signedWithoutTeam)
                case .unsigned:
                    TextField(L10n.t(.ruleProgramPath), text: $draft.unsignedPath, prompt: Text(verbatim: "/path/to/program"))
                    TextField(L10n.t(.ruleCdhash), text: $draft.cdhash)
                case .app:
                    Picker(L10n.t(.subjectApp), selection: Binding(get: { draft.appKey }, set: { draft.selectApp($0) })) {
                        ForEach(model.appRows) { r in Text(r.name).tag(r.id) }
                    }
                    Toggle(L10n.t(.exceptOwners), isOn: $draft.appExceptOwners)
                case .agentChain:
                    Toggle(L10n.t(.exceptOwners), isOn: $draft.exceptOwners)
                    ForEach(model.agents?.agents ?? []) { a in
                        Toggle(a.name.resolve(model.language), isOn: Binding(
                            get: { draft.agentIDs.contains(a.id) },
                            set: { draft.setAgent(a.id, selected: $0) }))
                    }
                    Text(L10n.t(.ruleAgentsNote)).font(.caption).foregroundStyle(.secondary)
                case .anyNonOwner:
                    Toggle(L10n.t(.includePlatformBinaries), isOn: $draft.includePlatformBinaries)
                }
            }
            Section {
                Picker(L10n.t(.ruleAccess), selection: $draft.access) {
                    Text(L10n.t(.accessRead)).tag(RuleAccess.read)
                    Text(L10n.t(.accessWrite)).tag(RuleAccess.write)
                    Text(L10n.t(.accessAny)).tag(RuleAccess.any)
                }
                Picker(L10n.t(.ruleAction), selection: $draft.action) {
                    Text(L10n.t(.actionDeny)).tag(RuleAction.deny)
                    Text(L10n.t(.actionAlert)).tag(RuleAction.alert)
                    Text(L10n.t(.actionAllow)).tag(RuleAction.allow)
                }
                Toggle(L10n.t(.ruleEnabled), isOn: $draft.enabled)
                if draft.action == .deny {
                    Toggle(L10n.t(.ruleEnforce), isOn: $draft.enforce)
                }
            }
            HStack {
                if let err = draft.validationError() { Text(L10n.t(err)).font(.caption).foregroundStyle(.red) }
                Spacer()
                Button(L10n.t(.cancel)) { done(nil) }
                Button(L10n.t(.save)) { done(draft.build()) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(draft.validationError() != nil)
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 520, minHeight: 520)
        .padding()
    }
}
