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

    /// Names and paths come from the files and programs themselves: escaped and capped
    /// (`DisplayText`), so a name cannot forge or hide lines of the text the user decides on.
    public func headline(_ alert: Alert) -> String {
        let app = DisplayText.name(alert.responsible.displayName)
        let path = DisplayText.path(abbreviate(alert.firstPath))
        let category = DisplayText.name(categoryName(alert.categoryID)?.resolve(language) ?? alert.categoryID)
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
        let names = DisplayText.escaped(chain.map { DisplayText.name($0.name) }.joined(separator: " → "),
                                        limit: DisplayText.chainLimit, keepEnd: true)
        return language == .zhHans ? "调用链：\(names)" : "Chain: \(names)"
    }

    /// Who signed the program the access is charged to, as the user should judge a request:
    /// a bundle named "Terminal" in a downloads folder is not Terminal.
    public enum Signer: Equatable, Sendable {
        /// An Apple platform binary in a system location.
        case apple
        /// An Apple platform binary outside the system locations: a copy keeps Apple's signature, so
        /// this may be any program built from Apple's (the label says where, not that it was copied).
        case appleCopy
        /// Signed by a developer with this Team ID.
        case team(String)
        /// Ad-hoc signed or unsigned: anyone could have built it.
        case unidentified
        /// The program is not in the stored chain (it was cut at its 64 nearest processes).
        case unknown
    }

    /// The signer of an `.app` or `.binary` responsible, from its process in the chain (the
    /// responsible entity itself keeps no platform flag). nil for an AI agent (named from the
    /// agent catalog) or without a path.
    public static func signer(of responsible: ResponsibleEntity, chain: [ChainLink]) -> Signer? {
        guard responsible.kind != .agent, let path = responsible.path else { return nil }
        let link: ChainLink?
        if responsible.kind == .app {
            let key = PathNormalizer.fold(path) + "/"
            link = chain.last { PathNormalizer.fold($0.path).hasPrefix(key) }
        } else {
            link = chain.last { $0.path == path }
        }
        guard let link else {
            if let team = responsible.teamID { return .team(team) }
            // Attributor keeps a cdhash only for a binary with no Team ID that is not Apple's.
            return responsible.cdhash != nil ? .unidentified : .unknown
        }
        if let team = link.teamID { return .team(team) }
        if link.isPlatformBinary { return IdentitySpec.isSystemLocation(link.path) ? .apple : .appleCopy }
        return .unidentified
    }

    /// "Program: ~/x/Terminal.app (not signed by an identified developer)": where the app or
    /// program really is, and who signed it. Shown with every question and alert, next to the
    /// name the program gave itself. nil for an AI agent.
    public func identityLine(_ alert: Alert) -> String? {
        guard let path = alert.responsible.path, let signer = AlertFormatter.signer(of: alert.responsible, chain: alert.chain) else {
            return nil
        }
        let location = DisplayText.path(abbreviate(path))
        let zh = language == .zhHans
        return zh ? "程序：\(location)（\(signerName(signer))）" : "Program: \(location) (\(signerName(signer)))"
    }

    public func signerName(_ signer: Signer) -> String {
        switch (language, signer) {
        case (.zhHans, .apple): return "Apple"
        case (.en, .apple): return "Apple"
        case (.zhHans, .appleCopy): return "Apple 签名，但不在系统目录中"
        case (.en, .appleCopy): return "Apple-signed, outside the system folders"
        case (.zhHans, .team(let t)): return "开发者团队 " + DisplayText.name(t)
        case (.en, .team(let t)): return "developer team " + DisplayText.name(t)
        case (.zhHans, .unidentified): return "没有已识别开发者的签名"
        case (.en, .unidentified): return "not signed by an identified developer"
        case (.zhHans, .unknown): return "签名未知"
        case (.en, .unknown): return "signature not known"
        }
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
