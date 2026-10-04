// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadUIModel

// SwiftUI also exports `Alert` (legacy alert struct) and `Settings` (the settings scene, unused
// here). App-module aliases shadow both, so the bare names mean WhoRead's types in every file.
typealias Alert = WhoReadCore.Alert
typealias Settings = WhoReadCore.Settings

enum Tab: String, CaseIterable, Identifiable {
    case live, alerts, apps, files, agents, rules, settings
    var id: String { rawValue }

    var title: String {
        switch self {
        case .live: return L10n.t(.tabLive)
        case .alerts: return L10n.t(.tabAlerts)
        case .apps: return L10n.t(.tabApps)
        case .files: return L10n.t(.tabFiles)
        case .agents: return L10n.t(.tabAgents)
        case .rules: return L10n.t(.tabRules)
        case .settings: return L10n.t(.tabSettings)
        }
    }

    var symbol: String {
        switch self {
        case .live: return "waveform.path.ecg"
        case .alerts: return "bell"
        case .apps: return "app.badge"
        case .files: return "folder.badge.questionmark"
        case .agents: return "sparkles"
        case .rules: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        }
    }
}

@MainActor
@Observable
final class NavigationState {
    static let shared = NavigationState()
    var tab: Tab = .live
    var showOnboarding = false
    /// `openWindow(id: "main")`, captured from a view (only views get that action). The main
    /// window is usually closed in a menu bar app, and activating the app does not reopen it.
    @ObservationIgnored var openMainWindow: (@MainActor () -> Void)?

    func show(tab: Tab) {
        self.tab = tab
        openMainWindow?()
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct SeverityBadge: View {
    let severity: Severity
    var body: some View {
        Text(L10n.severity(severity))
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
    var color: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        }
    }
}

struct DecisionBadge: View {
    let event: AnalyzedEvent
    var body: some View {
        let text = L10n.decision(event)
        let color: Color = event.decision == .denied ? .red : (event.decision == .wouldDeny ? .orange : (event.isBenign ? .secondary : .primary))
        Text(text).font(.caption).foregroundStyle(color)
    }
}

/// "Claude Code → zsh → cat", trimmed to the responsible app, with the full chain in a tooltip.
struct ChainText: View {
    let chain: [ChainLink]
    let responsible: ResponsibleEntity
    var body: some View {
        Text(chain.displayString(responsible: responsible))
            .lineLimit(1)
            .truncationMode(.middle)
            .help(chain.map { link in
                link.name + (link.argv.map { " " + $0.dropFirst().joined(separator: " ") } ?? "")
            }.joined(separator: "\n→ "))
    }
}

extension Date {
    var shortTime: String { formatted(date: .abbreviated, time: .standard) }
}
