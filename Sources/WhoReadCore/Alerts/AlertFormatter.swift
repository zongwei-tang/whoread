import Foundation

/// Renders alerts as one-line text in English or Simplified Chinese. Shared by the CLI, the app
/// and notifications so wording is identical everywhere.
///
///   zh: Zoom 第一次读取了 ~/.ssh/id_ed25519｜调用链：launchd → zoom.us｜始终允许 · 以后拦截 · 忽略
///   en: Zoom read ~/.ssh/id_ed25519 for the first time | Chain: launchd → zoom.us | Always allow · Block from now on · Ignore
public struct AlertFormatter: Sendable {
    public var language: Language
    public var abbreviate: @Sendable (String) -> String
    public var categoryName: @Sendable (String) -> LocalizedText?

    public init(
        language: Language,
        abbreviate: @escaping @Sendable (String) -> String = { $0 },
        categoryName: @escaping @Sendable (String) -> LocalizedText? = { _ in nil }
    ) {
        self.language = language
        self.abbreviate = abbreviate
        self.categoryName = categoryName
    }

    public func headline(_ alert: Alert) -> String {
        let app = alert.responsible.displayName
        let path = abbreviate(alert.firstPath)
        let category = categoryName(alert.categoryID)?.resolve(language) ?? alert.categoryID
        let both = alert.accesses.contains(.read) && alert.accesses.contains(.write)
        let writeOnly = alert.accesses.contains(.write) && !alert.accesses.contains(.read)
        let verbZH = both ? "读写" : writeOnly ? "写入" : "读取"
        let verbEN = both ? "read and modified" : writeOnly ? "wrote" : "read"
        let verbENBase = both ? "read and modify" : writeOnly ? "write" : "read"
        let verbENing = both ? "reading and modifying" : writeOnly ? "writing" : "reading"
        let firstZH = alert.firstTime ? "第一次" : ""
        let firstEN = alert.firstTime ? " for the first time" : ""
        var text: String
        switch (language, alert.kind) {
        case (.zhHans, .firstAccess):
            text = "\(app) 第一次\(verbZH)了 \(path)"
        case (.en, .firstAccess):
            text = "\(app) \(verbEN) \(path) for the first time"
        case (.zhHans, .criticalNonOwner):
            text = "\(app) \(firstZH)\(verbZH)了 \(path)（\(category)，不是预期的访问者）"
        case (.en, .criticalNonOwner):
            text = "\(app) \(verbEN) \(path)\(firstEN) (\(category), not an expected owner)"
        case (.zhHans, .ruleAlert):
            text = "\(app) \(verbZH)了 \(path)（规则提醒）"
        case (.en, .ruleAlert):
            text = "\(app) \(verbEN) \(path) (rule alert)"
        case (.zhHans, .wouldBlock):
            text = "规则将会拦截：\(app) \(verbZH) \(path)（当前为监控模式）"
        case (.en, .wouldBlock):
            text = "A rule would block \(app) from \(verbENing) \(path) (monitor mode)"
        case (.zhHans, .blocked):
            text = "已拦截：\(app) 试图\(verbZH) \(path)"
        case (.en, .blocked):
            text = "Blocked: \(app) tried to \(verbENBase) \(path)"
        // An ask alert exists once an access was denied for want of an answer; later accesses are held
        // (or denied) the same way until an answer saves a rule.
        case (.zhHans, .ask):
            text = "\(app) 想要\(verbZH) \(path)，你决定之前不会放行"
        case (.en, .ask):
            text = "\(app) wants to \(verbENBase) \(path): not allowed until you decide"
        }
        if alert.count > 1 {
            text += language == .zhHans ? "（\(alert.count) 次）" : " (×\(alert.count))"
        }
        return text
    }

    public func chainLine(_ chain: [ChainLink]) -> String {
        let names = chain.map(\.name).joined(separator: " → ")
        return language == .zhHans ? "调用链：\(names)" : "Chain: \(names)"
    }

    /// Titles for the answers to a question (docs/ASK_MODE.md): "deny" saves nothing, "always deny"
    /// saves a deny rule. Other kinds use the plain titles.
    public func actionTitle(_ action: AlertAction, kind: AlertKind) -> String {
        guard kind == .ask else { return actionTitle(action) }
        switch (language, action) {
        case (.zhHans, .keepBlocking): return "拒绝"
        case (.en, .keepBlocking): return "Deny"
        case (.zhHans, .blockFromNowOn): return "始终拒绝"
        case (.en, .blockFromNowOn): return "Always deny"
        default: return actionTitle(action)
        }
    }

    public func actionTitle(_ action: AlertAction) -> String {
        switch (language, action) {
        case (.zhHans, .allowOnce): return "允许一次"
        case (.en, .allowOnce): return "Allow once"
        case (.zhHans, .alwaysAllow): return "始终允许"
        case (.en, .alwaysAllow): return "Always allow"
        case (.zhHans, .blockFromNowOn): return "以后拦截"
        case (.en, .blockFromNowOn): return "Block from now on"
        case (.zhHans, .keepBlocking): return "保持拦截"
        case (.en, .keepBlocking): return "Keep blocking"
        case (.zhHans, .ignore): return "忽略"
        case (.en, .ignore): return "Ignore"
        case (.zhHans, .trustApplePrograms): return "允许所有 Apple 程序"
        case (.en, .trustApplePrograms): return "Allow all Apple programs"
        }
    }

    /// Full one-line form used by the CLI and as notification fallback.
    public func line(_ alert: Alert) -> String {
        let sep = language == .zhHans ? "｜" : " | "
        let actions = alert.availableActions.map { actionTitle($0, kind: alert.kind) }.joined(separator: " · ")
        return headline(alert) + sep + chainLine(alert.chain) + sep + actions
    }

    public func kindTitle(_ kind: AlertKind) -> String {
        switch (language, kind) {
        case (.zhHans, .firstAccess): return "首次访问"
        case (.en, .firstAccess): return "First access"
        case (.zhHans, .criticalNonOwner): return "非预期访问"
        case (.en, .criticalNonOwner): return "Unexpected access"
        case (.zhHans, .ruleAlert): return "规则提醒"
        case (.en, .ruleAlert): return "Rule alert"
        case (.zhHans, .wouldBlock): return "将被拦截"
        case (.en, .wouldBlock): return "Would block"
        case (.zhHans, .blocked): return "已拦截"
        case (.en, .blocked): return "Blocked"
        case (.zhHans, .ask): return "等你决定"
        case (.en, .ask): return "Needs your decision"
        }
    }
}
