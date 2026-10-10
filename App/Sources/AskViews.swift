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
            // A path the daemon hides from this app reads as such.
            Text(f.headline(ask.displayAlert(model.language))).font(.body.weight(.medium)).multilineTextAlignment(.leading)
            // Where the program really is and who signed it: the name above is its own choice.
            if let identity = model.identityLine(ask.asAlert) {
                Text(identity).font(.caption).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
            }
            // The answer covers the app only as driven by this agent: say so, the headline may not.
            if let agents = ask.agentsLine(model.language, agentName: model.agentName) {
                Text(agents).font(.caption.weight(.semibold)).foregroundStyle(.orange)
            }
            // What allowing covers: the app (every program run in it), not only the program that asked.
            Text(ask.allowCoverageLine(f, agentName: model.agentName)).font(.caption).fixedSize(horizontal: false, vertical: true)
            Text(f.chainLine(ask.chain)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            // Allowing needs the signed app or root; denying is open to the console user. "Always allow"
            // and "always deny" name what they cover.
            AnswerButtons(actions: AskAnswers.allowActions(for: ask), title: { model.answerTitle($0, for: ask) }) {
                connection.answer(ask: ask.id, $0)
            }
            AnswerButtons(actions: AskAnswers.denyActions, role: .destructive, title: { model.answerTitle($0, for: ask) }) {
                connection.answer(ask: ask.id, $0)
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

/// Answer buttons in a row, or one under the other when their titles do not fit (the titles of
/// "always allow" and "always deny" name the app and the category).
struct AnswerButtons: View {
    let actions: [AlertAction]
    var role: ButtonRole?
    let title: (AlertAction) -> String
    var help: (AlertAction) -> String = { _ in "" }
    let answer: (AlertAction) -> Void

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack { buttons }
            VStack(alignment: .leading, spacing: 4) { buttons }
        }
    }

    private var buttons: some View {
        ForEach(actions, id: \.self) { action in
            Button(role: role) { answer(action) } label: {
                Text(title(action)).multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
            }
            .help(help(action))
        }
    }
}
