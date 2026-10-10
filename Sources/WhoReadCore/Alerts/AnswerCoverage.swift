import Foundation

/// What an answer to a question (or to an alert) covers, in words, for the app, the notifications and
/// the CLI (docs/ASK_MODE.md "Answers").
///
/// An answer becomes a rule on the app, AI agent or program the access is charged to (`Attributor`),
/// × category × access × the AI agents in the chain. So "always allow" for Terminal covers every
/// program run inside Terminal; for an AI agent outside an app (a CLI agent), every program it runs;
/// for a program outside any app, the Apple programs it starts (a program that is not Apple's is
/// charged to itself, and asked about on its own). The allow rule matches a chain only when every AI
/// agent in it was in the chain answered (`Rule.chainAgents`): none, or only those.
extension AlertFormatter {
    /// "Terminal (any program run in it)": the app, AI agent or program an answer is about, and what
    /// is charged to it.
    public func answerSubject(_ r: ResponsibleEntity) -> String {
        let name = DisplayText.name(r.displayName)
        let zh = language == .zhHans
        switch r.kind {
        case .app:
            return zh ? "\(name)（及在其中运行的任何程序）" : "\(name) (any program run in it)"
        // An AI agent that is an app (Cursor, the Claude app): its path is the bundle.
        case .agent where r.path?.lowercased().hasSuffix(".app") ?? false:
            return zh ? "\(name)（及在其中运行的任何程序）" : "\(name) (any program run in it)"
        case .agent:
            return zh ? "\(name)（及它运行的任何程序）" : "\(name) (any program it runs)"
        case .binary:
            return zh ? "\(name)（及它启动的苹果程序）" : "\(name) (and the Apple programs it starts)"
        }
    }

    /// The same without a name, for notification buttons (registered once per kind, not per question):
    /// "this app (any program run in it)".
    public func answerSubject(kind: ResponsibleEntity.Kind) -> String {
        let zh = language == .zhHans
        switch kind {
        case .app: return zh ? "此应用（及在其中运行的任何程序）" : "this app (any program run in it)"
        case .agent: return zh ? "此 AI agent（及它运行的任何程序）" : "this AI agent (any program it runs)"
        case .binary: return zh ? "此程序（及它启动的苹果程序）" : "this program (and the Apple programs it starts)"
        }
    }

    /// "Always allow Terminal (any program run in it) to read SSH keys".
    public func alwaysAllowTitle(_ r: ResponsibleEntity, categoryID: String, access: AccessSet) -> String {
        let category = categoryText(categoryID)
        return language == .zhHans
            ? "始终允许 \(answerSubject(r))\(verbZH(access)) \(category)"
            : "Always allow \(answerSubject(r)) to \(verbEN(access)) \(category)"
    }

    /// "Always allow this app (any program run in it)".
    public func alwaysAllowTitle(kind: ResponsibleEntity.Kind) -> String {
        language == .zhHans ? "始终允许" + answerSubject(kind: kind) : "Always allow " + answerSubject(kind: kind)
    }

    /// The deny rule of "always deny" (a question) or "block from now on" (an alert): the same app, AI
    /// agent or program, on the whole category, read and write, in every chain.
    /// "Always deny Terminal (any program run in it) any access to SSH keys".
    public func alwaysDenyTitle(_ r: ResponsibleEntity, categoryID: String, kind: AlertKind) -> String {
        let category = categoryText(categoryID)
        let subject = answerSubject(r)
        switch (language, kind) {
        case (.zhHans, .ask): return "始终拒绝 \(subject)访问 \(category)"
        case (.en, .ask): return "Always deny \(subject) any access to \(category)"
        case (.zhHans, _): return "以后拦截 \(subject)访问 \(category)"
        case (.en, _): return "Block \(subject) from \(category) from now on"
        }
    }

    /// "Always deny this app (any program run in it)" / "Block this app (any program run in it) from now on".
    public func alwaysDenyTitle(kind: ResponsibleEntity.Kind, alertKind: AlertKind) -> String {
        let subject = answerSubject(kind: kind)
        switch (language, alertKind) {
        case (.zhHans, .ask): return "始终拒绝" + subject
        case (.en, .ask): return "Always deny " + subject
        case (.zhHans, _): return "以后拦截" + subject
        case (.en, _): return "Block \(subject) from now on"
        }
    }

    /// What allowing covers: "Terminal (any program run in it) reading SSH keys, only when the chain has
    /// no AI agent". `chainAgents`: the AI agents in the chain answered (ids); `agentName` names them.
    public func allowCoverage(_ r: ResponsibleEntity, categoryID: String, access: AccessSet, chainAgents: [String],
                              agentName: (String) -> String = { $0 }) -> String {
        let category = categoryText(categoryID)
        let agents = Array(Set(chainAgents)).sorted().map { DisplayText.name(agentName($0)) }
        if language == .zhHans {
            let when = agents.isEmpty ? "调用链中没有 AI agent" : "调用链中除 \(agents.joined(separator: "、")) 外没有其他 AI agent"
            return "\(answerSubject(r))\(verbZH(access)) \(category)，仅限\(when) 时"
        }
        let when = agents.isEmpty ? "the chain has no AI agent" : "the chain has no AI agent other than \(agents.joined(separator: ", "))"
        return "\(answerSubject(r)) \(verbingEN(access)) \(category), only when \(when)"
    }

    private func categoryText(_ id: String) -> String {
        DisplayText.name(categoryName(id)?.resolve(language) ?? id)
    }

    private func verbZH(_ a: AccessSet) -> String {
        a.contains(.read) && a.contains(.write) ? "读写" : (a.contains(.write) ? "写入" : "读取")
    }

    private func verbEN(_ a: AccessSet) -> String {
        a.contains(.read) && a.contains(.write) ? "read and modify" : (a.contains(.write) ? "write to" : "read")
    }

    private func verbingEN(_ a: AccessSet) -> String {
        a.contains(.read) && a.contains(.write) ? "reading and modifying" : (a.contains(.write) ? "writing to" : "reading")
    }
}
