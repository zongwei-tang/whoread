// NOT YET COMPILED (see WhoReadApp.swift).
import SwiftUI
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

/// One open ask-mode question with its answers (menu bar popover, Alerts tab).
struct AskRow: View {
    @Environment(DaemonConnection.self) private var connection
    @Environment(AppModel.self) private var model
    let ask: AskRequest

    var body: some View {
        let f = model.formatter
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                SeverityBadge(severity: ask.severity)
                Text(model.categoryName(ask.key.categoryID)).font(.caption).foregroundStyle(.secondary)
                Spacer()
                deadline
            }
            Text(f.headline(ask.asAlert)).font(.body.weight(.medium)).multilineTextAlignment(.leading)
            // Where the program really is and who signed it: the name above is its own choice.
            if let identity = model.identityLine(ask.asAlert) {
                Text(identity).font(.caption).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
            }
            // The answer covers the app only as driven by this agent: say so, the headline may not.
            if let agents = ask.agentsLine(model.language, agentName: model.agentName) {
                Text(agents).font(.caption.weight(.semibold)).foregroundStyle(.orange)
            }
            Text(f.chainLine(ask.chain)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            // Allowing needs the signed app or root; denying is open to the console user.
            HStack {
                ForEach(AskAnswers.allowActions(for: ask), id: \.self) { action in
                    Button(L10n.askActionTitle(action)) { connection.answer(ask: ask.id, action) }
                }
            }
            HStack {
                ForEach(AskAnswers.denyActions, id: \.self) { action in
                    Button(L10n.askActionTitle(action), role: .destructive) { connection.answer(ask: ask.id, action) }
                }
            }
        }
        .controlSize(.small)
        .padding(.vertical, 2)
    }

    /// When the held access is denied if nobody answers; nothing held: the answer is for next time.
    @ViewBuilder
    private var deadline: some View {
        // One `now`: a second Date() could already be past `by` (a range with lower > upper traps).
        let now = Date()
        if let by = ask.answerBy, by > now {
            HStack(spacing: 4) {
                Text(L10n.t(.askDeniedIn))
                Text(timerInterval: now...by, countsDown: true).monospacedDigit()
            }
            .font(.caption).foregroundStyle(.orange)
        } else {
            Text(L10n.t(.askNotHeld)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        }
    }
}
