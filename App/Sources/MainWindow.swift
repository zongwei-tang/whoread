// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadUIModel

struct MainWindow: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    @State private var nav = NavigationState.shared

    var body: some View {
        TabView(selection: $nav.tab) {
            LiveView().tabItem { Label(Tab.live.title, systemImage: Tab.live.symbol) }.tag(Tab.live)
            AlertsView().tabItem { Label(Tab.alerts.title, systemImage: Tab.alerts.symbol) }.tag(Tab.alerts)
                .badge(model.unreadCount)
            AppsView().tabItem { Label(Tab.apps.title, systemImage: Tab.apps.symbol) }.tag(Tab.apps)
            FilesView().tabItem { Label(Tab.files.title, systemImage: Tab.files.symbol) }.tag(Tab.files)
            AgentsView().tabItem { Label(Tab.agents.title, systemImage: Tab.agents.symbol) }.tag(Tab.agents)
            RulesView().tabItem { Label(Tab.rules.title, systemImage: Tab.rules.symbol) }.tag(Tab.rules)
            SettingsView().tabItem { Label(Tab.settings.title, systemImage: Tab.settings.symbol) }.tag(Tab.settings)
        }
        .padding(8)
        .safeAreaInset(edge: .top) {
            if let problem = model.versionProblem {
                Text(L10n.f(.errVersionMismatchFormat, problem))
                    .font(.callout).foregroundStyle(.red).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12)
            }
        }
        .sheet(isPresented: $nav.showOnboarding) { OnboardingView() }
        .onAppear {
            if !connection.onboarding.isComplete(model.status, connected: model.connected) { nav.showOnboarding = true }
        }
        .toolbar {
            ToolbarItem(placement: .status) {
                Label(model.menuBar.title, systemImage: model.menuBar.symbol).labelStyle(.titleAndIcon)
            }
        }
    }
}

struct LiveView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: AnalyzedEvent.ID?

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading) {
            HStack {
                TextField(L10n.t(.search), text: $model.searchText).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                Toggle(L10n.t(.showSystemNoise), isOn: $model.showSystemNoise)
                Spacer()
                Button(model.feedPaused ? L10n.t(.resumeFeed) : L10n.t(.pauseFeed)) { model.feedPaused.toggle() }
            }
            if model.liveRows.isEmpty {
                ContentUnavailableView(L10n.t(.liveEmpty), systemImage: "checkmark.shield")
            } else {
                Table(model.liveRows, selection: $selection) {
                    TableColumn(L10n.t(.colTime)) { e in Text(e.time.formatted(date: .omitted, time: .standard)).monospacedDigit() }
                        .width(min: 70, ideal: 80)
                    TableColumn(L10n.t(.colApp)) { e in Text(e.responsible.displayName) }.width(min: 90, ideal: 120)
                    TableColumn(L10n.t(.colOperation)) { e in Text(L10n.operation(e.operation) + " · " + L10n.access(e.access)) }
                        .width(min: 80, ideal: 110)
                    TableColumn(L10n.t(.colPath)) { e in Text(model.abbreviate(e.path)).lineLimit(1).truncationMode(.middle) }
                    TableColumn(L10n.t(.colCategory)) { e in
                        HStack { SeverityBadge(severity: e.severity); Text(model.categoryName(e.categoryID)) }
                    }.width(min: 140, ideal: 200)
                    TableColumn(L10n.t(.colChain)) { e in ChainText(chain: e.chain, responsible: e.responsible) }
                    TableColumn(L10n.t(.colDecision)) { e in DecisionBadge(event: e) }.width(min: 70, ideal: 90)
                }
            }
        }
        // Process identity of the selected access (brief §1: pid, path, signing ID, team ID, platform flag).
        .inspector(isPresented: Binding(get: { selection != nil }, set: { if !$0 { selection = nil } })) {
            if let e = model.live.events.first(where: { $0.id == selection }) {
                EventDetail(event: e)
            }
        }
    }
}

struct EventDetail: View {
    @Environment(AppModel.self) private var model
    let event: AnalyzedEvent

    var body: some View {
        let p = event.process
        Form {
            Section(L10n.t(.detTitle)) {
                LabeledContent(L10n.t(.colPath), value: model.abbreviate(event.path))
                if let other = event.secondaryPath {
                    LabeledContent(L10n.t(.detOtherPath), value: model.abbreviate(other))
                }
                LabeledContent(L10n.t(.colOperation), value: L10n.operation(event.operation) + " · " + L10n.access(event.access))
                LabeledContent(L10n.t(.colCategory), value: model.categoryName(event.categoryID))
                LabeledContent(L10n.t(.colDecision)) { DecisionBadge(event: event) }
                LabeledContent(L10n.t(.detResponsible), value: event.responsible.displayName)
                if let agent = event.agentID {
                    LabeledContent(L10n.t(.colAgent), value: model.agentName(agent))
                }
            }
            Section(L10n.t(.detProcess)) {
                LabeledContent(L10n.t(.detPID), value: String(p.pid))
                LabeledContent(L10n.t(.detExecutable), value: p.executablePath)
                LabeledContent(L10n.t(.ruleSigningID), value: p.signingID ?? "—")
                LabeledContent(L10n.t(.ruleTeamID), value: p.teamID ?? "—")
                LabeledContent(L10n.t(.detCdhash), value: p.cdhash ?? "—")
                LabeledContent(L10n.t(.detPlatformBinary), value: p.isPlatformBinary ? L10n.t(.yes) : L10n.t(.no))
                if let argv = p.argv {
                    LabeledContent(L10n.t(.detArguments), value: argv.joined(separator: " "))
                }
            }
            Section(L10n.t(.colChain)) {
                ForEach(Array(event.chain.enumerated()), id: \.offset) { _, link in
                    Text(verbatim: "\(link.name) (\(link.pid))").help(link.path)
                }
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
        .inspectorColumnWidth(min: 260, ideal: 320)
    }
}

struct AlertsView: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading) {
            HStack {
                Toggle(L10n.t(.unreadOnly), isOn: $model.alertsUnreadOnly)
                Spacer()
                Button(L10n.t(.markAllRead)) { connection.markAllRead() }.disabled(model.unreadCount == 0)
            }
            if let err = connection.lastActionError { Text(err).foregroundStyle(.red).font(.caption) }
            if model.visibleAlerts.isEmpty {
                ContentUnavailableView(L10n.t(.alertsEmpty), systemImage: "bell.slash")
            } else {
                List(model.visibleAlerts) { alert in
                    AlertRow(alert: alert)
                }
            }
        }
    }
}

struct AlertRow: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    let alert: Alert

    var body: some View {
        let f = model.formatter
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle().fill(alert.status == .unread ? Color.red : Color.clear).frame(width: 7, height: 7)
                Text(f.kindTitle(alert.kind)).font(.caption.weight(.semibold))
                SeverityBadge(severity: alert.severity)
                Spacer()
                Text(alert.updatedAt.shortTime).font(.caption).foregroundStyle(.secondary)
            }
            Text(f.headline(alert)).font(.body.weight(.medium))
            Text(f.chainLine(alert.chain)).font(.caption).foregroundStyle(.secondary)
            if alert.paths.count > 1 {
                Text(L10n.t(.pathsSeen) + ": " + alert.paths.map(model.abbreviate).joined(separator: ", "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            if alert.status != .resolved {
                HStack {
                    ForEach(alert.availableActions, id: \.self) { action in
                        Button(f.actionTitle(action)) { connection.act(on: alert.id, action) }
                            .help(action == .blockFromNowOn ? (model.enforcementCaveat ?? "") : "")
                    }
                }
            } else if let r = alert.resolution {
                Text("✓ " + f.actionTitle(r)).font(.caption).foregroundStyle(.secondary)
                // The rule is saved, but nothing is blocked while enforcement is not active.
                if r == .blockFromNowOn, let caveat = model.enforcementCaveat {
                    Text(caveat).font(.caption).foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct AppsView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        if model.appRows.isEmpty {
            ContentUnavailableView(L10n.t(.appsEmpty), systemImage: "app.dashed")
        } else {
            Table(model.appRows) {
                TableColumn(L10n.t(.colApp)) { r in Text(r.name) }
                TableColumn(L10n.t(.colKind)) { r in Text(L10n.kind(r.kind)) }.width(min: 70, ideal: 80)
                TableColumn(L10n.t(.colCategories)) { r in Text(r.categories.joined(separator: ", ")).lineLimit(2) }
                TableColumn(L10n.t(.colFirstSeen)) { r in Text(r.firstSeen.shortTime) }
                TableColumn(L10n.t(.colLastSeen)) { r in Text(r.lastSeen.shortTime) }
                TableColumn(L10n.t(.colCount)) { r in Text("\(r.count)").monospacedDigit() }.width(min: 50, ideal: 60)
            }
        }
    }
}

struct FilesView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Table(model.fileRows) {
            TableColumn(L10n.t(.colCategory)) { r in Text(r.name) }
            TableColumn(L10n.t(.colSeverity)) { r in SeverityBadge(severity: r.severity) }.width(min: 70, ideal: 80)
            TableColumn(L10n.t(.colStatus)) { r in
                Text(r.detected ? L10n.t(.detected) : L10n.t(.notDetected)).foregroundStyle(r.detected ? .primary : .secondary)
            }.width(min: 80, ideal: 90)
            TableColumn(L10n.t(.colApps)) { r in Text(r.apps.joined(separator: ", ")).lineLimit(2) }
            TableColumn(L10n.t(.colLastSeen)) { r in Text(r.lastSeen?.shortTime ?? "—") }
            TableColumn(L10n.t(.colCount)) { r in Text("\(r.count)").monospacedDigit() }.width(min: 50, ideal: 60)
        }
    }
}

struct AgentsView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        if model.agentRows.isEmpty {
            ContentUnavailableView(L10n.t(.agentsEmpty), systemImage: "sparkles")
        } else {
            Table(model.agentRows) {
                TableColumn(L10n.t(.colAgent)) { r in Text(r.name) }
                TableColumn(L10n.t(.colCategories)) { r in Text(r.categories.joined(separator: ", ")).lineLimit(2) }
                TableColumn(L10n.t(.colBlocked)) { r in Text("\(r.blocked)").foregroundStyle(r.blocked > 0 ? .red : .primary) }
                    .width(min: 60, ideal: 70)
                TableColumn(L10n.t(.colLastSeen)) { r in Text(r.lastSeen.shortTime) }
                TableColumn(L10n.t(.colCount)) { r in Text("\(r.count)").monospacedDigit() }.width(min: 50, ideal: 60)
            }
        }
    }
}
