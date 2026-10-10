import Foundation
import WhoReadCore
import WhoReadIPC

/// Every user-visible string of the app, in English and Simplified Chinese.
///
/// Kept in code (not an .xcstrings catalog) so the table is compiled and unit-tested on any host:
/// a test asserts that every key has both languages. Alert sentences come from
/// `WhoReadCore.AlertFormatter`, shared with the CLI.
public enum L: String, CaseIterable, Sendable {
    // Menu bar
    case appName, modeMonitoring, modeEnforcing, modePaused, modeError, unreadAlertsFormat, openWindow
    case pauseMonitoring, resumeMonitoring, enforcement, enforcementOn, enforcementOff, enforcementInactiveFormat
    case killSwitchAdmin, quit, daemonUnreachable, recentAlerts, noAlerts
    // Ask mode: open questions (menu bar, Alerts tab, notifications)
    case asksTitle, asksWaitingFormat, asksMoreFormat, askDeniedIn, askNotHeld
    case askAllowOnce, askAlwaysAllow, askDeny, askAlwaysDeny, askTrustApple
    case askAllowNotPermittedFormat, askGone, askAgentsFormat, askPathHidden, asksCannotReadFormat
    case askCoversFormat, alertCoversFormat
    case answerRuleLimit, answerNotSavedFormat, answerNoReply, alertNotPermittedFormat
    // What cannot be read (limited view)
    case limitedViewFormat, limitedAskPaths, notShownFormat, cannotReadFormat
    case partAlerts, partLive, partSummaries, partRules, partSettings, partCatalog, partAgents
    // Tabs
    case tabLive, tabAlerts, tabApps, tabFiles, tabAgents, tabRules, tabSettings
    // Columns & common
    case colTime, colApp, colOperation, colPath, colCategory, colChain, colDecision, colKind, colCategories
    case colFirstSeen, colLastSeen, colCount, colSeverity, colApps, colBlocked, colAgent, colStatus
    case kindApp, kindAgent, kindBinary
    case sevMedium, sevHigh, sevCritical
    case decObserved, decAllowed, decDenied, decWouldDeny, decBenign
    case detected, notDetected, search, refresh, save, revert, add, remove, delete, cancel, done, close
    // Live
    case showSystemNoise, pauseFeed, resumeFeed, liveEmpty
    // Alerts
    case markAllRead, unreadOnly, statusUnread, statusRead, statusResolved, alertsEmpty, pathsSeen
    // Agents / apps / files
    case agentsEmpty, appsEmpty, filesEmpty
    // Rules
    case addRule, templates, ruleEnabled, ruleEnforce, ruleDryRun, ruleTarget, ruleSubject, ruleAccess, ruleAction
    case targetCategory, targetSeverity, targetPath, subjectSigned, subjectUnsigned, subjectApp, subjectAnyNonOwner
    case subjectAgentChain, exceptOwners, includePlatformBinaries, accessRead, accessWrite, accessAny
    case actionAllow, actionDeny, actionAlert, rulesEnforcementOffNote, ruleExceptionsFormat, rulesEmpty
    case ruleChainNoAgent, ruleChainAgentsFormat
    // Settings
    case setMonitoredPaths, setProjectRoots, setProjectRootsNote, setAsk, setAskNote, setTrustApple, setTrustAppleNote
    case setRetention, setRetentionDays, setDetailDays, setNotifications, setNotificationsEnabled, setMinSeverity
    case setNotifyWouldBlock, setEnforcement, setEnforcementMaster, setEnforcementNote, setLatency, setReaddir
    case slowResponsesFormat, slowMissesFormat, slowP99Format, uncleanStopFormat
    case setLanguage, setLanguageSystem, setCoalesce, setSaved, setPermissionNeeded
    // Onboarding
    case onbTitle, onbIntro, onbFDATitle, onbFDABody, onbFDAButton, onbExtTitle, onbExtBody, onbExtButton
    case onbExtApprove, onbDaemonTitle, onbDaemonBody, onbAllSet, onbWaiting, onbDone, onbFailedFormat, onbContinue
    case onbOpenLoginItems, onbRestartRequired, openSetup
    // Notifications
    case notifTitle, notifBlockedTitle, notifUncleanStopTitle, notifRuleNotBlockingTitle, notifAskTitle, notifAskFailedTitle
    // Enforcement inactive reasons and caveats
    case reasonDisabledByUser, reasonKillSwitchFile, reasonRulesFailedToLoad, reasonSourceCannotEnforce
    case sourceCannotEnforceNote
    // Rule editor
    case ruleName, ruleSigningID, ruleTeamID, ruleNoTeamID, ruleProgramPath, ruleCdhash, ruleAgentsNote
    case rulePathNotMonitored, ruleBlockAppFormat
    case ruleErrCategory, ruleErrPath, ruleErrSigningID, ruleErrTeamID, ruleErrProgramPath, ruleErrCdhash, ruleErrApp
    case tplBlockAgentsCritical, tplAlertAgentsHigh, tplDenyNonOwnerSSH
    // Catalog editing (Settings → Monitored paths)
    case setMonitoredPathsNote, catPathPlaceholder, catAddCategory, catNewCategoryName, catDeleteCategory, catPathsManaged
    case catInvalidPath, catCustomName
    // Event details
    case detTitle, detProcess, detPID, detExecutable, detCdhash, detPlatformBinary, detArguments, detResponsible, detOtherPath
    case yes, no, accessReadWrite
    // Operations
    case opOpen, opClose, opRename, opClone, opCopyfile, opLink, opUnlink, opTruncate, opExchangedata, opReaddir, opCreate
    case opSetmode, opSetowner, opSetacl, opMount
    // Errors
    case errNotPermitted, errUnavailable, errVersionMismatchFormat, errDaemonFormat, errAdminFormat, errNotConsoleUser
    case errNoAnswer
}

public enum L10n {
    /// Language used when no explicit choice is set.
    nonisolated(unsafe) public static var current: Language = Language.preferred(from: Locale.preferredLanguages)

    public static func t(_ key: L, _ language: Language = current) -> String {
        guard let pair = table[key] else { return key.rawValue }
        return language == .zhHans ? pair.1 : pair.0
    }

    public static func f(_ key: L, _ args: CVarArg..., language: Language = current) -> String {
        String(format: t(key, language), arguments: args)
    }

    static let table: [L: (String, String)] = [
        .appName: ("WhoRead", "WhoRead"),
        .modeMonitoring: ("Monitoring", "监控中"),
        .modeEnforcing: ("Enforcing", "拦截中"),
        .modePaused: ("Paused", "已暂停"),
        .modeError: ("Error", "出错"),
        .unreadAlertsFormat: ("%d unread alerts", "%d 条未读告警"),
        .openWindow: ("Open WhoRead…", "打开 WhoRead…"),
        .pauseMonitoring: ("Pause monitoring", "暂停监控"),
        .resumeMonitoring: ("Resume monitoring", "恢复监控"),
        .enforcement: ("Enforcement", "拦截"),
        .enforcementOn: ("On", "开"),
        .enforcementOff: ("Off", "关"),
        .enforcementInactiveFormat: ("Not active: %@", "未生效：%@"),
        .killSwitchAdmin: ("Turn enforcement off now (administrator)…", "立即关闭拦截（需要管理员密码）…"),
        .quit: ("Quit WhoRead", "退出 WhoRead"),
        .daemonUnreachable: ("Cannot reach the WhoRead daemon", "无法连接 WhoRead 守护进程"),
        .recentAlerts: ("Recent alerts", "最近告警"),
        .noAlerts: ("No alerts", "没有告警"),

        .asksTitle: ("Waiting for your answer", "等待你的决定"),
        .asksWaitingFormat: ("%ld questions waiting", "%ld 个访问等待你的决定"),
        .asksMoreFormat: ("%ld more…", "还有 %ld 个…"),
        .askDeniedIn: ("Denied if unanswered in", "未回答将被拒绝，剩余"),
        .askNotHeld: ("Denied for now; your answer applies to the next attempt.", "这次已拒绝；你的回答会用于下一次访问。"),
        .askAllowOnce: ("Allow once (10 min)", "允许一次（10 分钟）"),
        .askAlwaysAllow: ("Always allow", "始终允许"),
        .askDeny: ("Deny", "拒绝"),
        .askAlwaysDeny: ("Always deny", "始终拒绝"),
        .askTrustApple: ("Allow all Apple programs", "允许所有苹果程序"),
        .askAllowNotPermittedFormat: ("Not allowed: the WhoRead monitor does not recognise this app as the signed WhoRead app, and only that app or an administrator can allow. The question is still open. In Terminal: %@",
                                      "没有权限：WhoRead 监控程序没有把这个应用识别为已签名的 WhoRead 应用，只有该应用或管理员才能允许。问题仍然保留。请在终端运行：%@"),
        .askGone: ("This question is no longer open: it was answered elsewhere, expired, or the WhoRead monitor restarted. If the program tries again, you will be asked again.",
                   "这个问题已经关闭：已在别处回答、已过期，或 WhoRead 监控程序已重启。如果程序再次尝试访问，会再次询问你。"),
        .answerRuleLimit: ("Not saved: WhoRead keeps at most 512 rules and that limit is reached, so nothing changed and the question or alert stays open. Delete rules you no longer need in the Rules tab, then answer again (Deny still works).",
                           "未保存：WhoRead 最多保存 512 条规则，现已达到上限，所以没有任何改变，问题或告警仍然保留。请在「规则」标签中删除不再需要的规则，然后再回答（「拒绝」仍然可用）。"),
        .answerNotSavedFormat: ("Your answer applies now, but WhoRead could not save it (%@). After the WhoRead monitor restarts you may be asked again.",
                                "你的回答已经生效，但 WhoRead 无法保存它（%@）。WhoRead 监控程序重启后可能会再次询问你。"),
        .answerNoReply: ("No reply from the WhoRead daemon: your answer may not have been taken. If the question is still listed, answer it again.",
                         "WhoRead 守护进程没有回应：你的回答可能没有生效。如果问题仍在列表中，请再回答一次。"),
        .alertNotPermittedFormat: ("Not permitted: the WhoRead monitor does not recognise this app as the signed WhoRead app, and this needs that app or an administrator. In Terminal: %@",
                                   "没有权限：WhoRead 监控程序没有把这个应用识别为已签名的 WhoRead 应用，这项操作需要该应用或管理员。请在终端运行：%@"),
        .askAgentsFormat: ("AI agent in the chain: %@", "调用链中有 AI agent：%@"),
        .askCoversFormat: ("Allow once (10 min) and Always allow cover: %@.", "「允许一次（10 分钟）」和「始终允许」适用于：%@。"),
        .alertCoversFormat: ("Always allow covers: %@.", "「始终允许」适用于：%@。"),
        .askPathHidden: ("(file path hidden: only the signed WhoRead app or sudo can see it)", "（文件路径已隐藏：只有已签名的 WhoRead 应用或 sudo 可以查看）"),
        .asksCannotReadFormat: ("Open questions cannot be read: %@", "无法读取等待回答的问题：%@"),

        .limitedViewFormat: ("Limited view: the WhoRead monitor does not recognise this app as the signed WhoRead app, so it does not show it %@. Questions still arrive and you can deny them here. Allowing, and everything else, needs the signed WhoRead app or sudo in Terminal (for example: sudo whoread asks).",
                             "受限视图：WhoRead 监控程序没有把这个应用识别为已签名的 WhoRead 应用，因此不向它提供%@。问题仍会出现，你可以在这里拒绝。允许访问以及其他内容需要已签名的 WhoRead 应用，或在终端使用 sudo（例如：sudo whoread asks）。"),
        .limitedAskPaths: ("the file paths in questions", "问题中的文件路径"),
        .notShownFormat: ("Not shown here: %@. The WhoRead monitor shows them only to the signed WhoRead app, or with sudo in Terminal (%@).",
                          "这里不显示%@：WhoRead 监控程序只把它们提供给已签名的 WhoRead 应用，或在终端用 sudo 查看（%@）。"),
        .cannotReadFormat: ("Could not read %@: %@", "无法读取%@：%@"),
        .partAlerts: ("alerts", "告警"),
        .partLive: ("the live feed", "实时记录"),
        .partSummaries: ("the app, file and AI agent history", "应用、文件和 AI agent 的历史记录"),
        .partRules: ("the rules", "规则"),
        .partSettings: ("the settings", "设置"),
        .partCatalog: ("the monitored paths", "监控路径"),
        .partAgents: ("the list of AI agents", "AI agent 列表"),

        .tabLive: ("Live", "实时"),
        .tabAlerts: ("Alerts", "告警"),
        .tabApps: ("Apps", "应用"),
        .tabFiles: ("Files", "文件"),
        .tabAgents: ("Agents", "AI agent"),
        .tabRules: ("Rules", "规则"),
        .tabSettings: ("Settings", "设置"),

        .colTime: ("Time", "时间"),
        .colApp: ("App", "应用"),
        .colOperation: ("Operation", "操作"),
        .colPath: ("Path", "路径"),
        .colCategory: ("Category", "类别"),
        .colChain: ("Call chain", "调用链"),
        .colDecision: ("Decision", "结果"),
        .colKind: ("Kind", "类型"),
        .colCategories: ("Categories touched", "碰过的类别"),
        .colFirstSeen: ("First seen", "首次"),
        .colLastSeen: ("Last seen", "最近"),
        .colCount: ("Count", "次数"),
        .colSeverity: ("Severity", "严重程度"),
        .colApps: ("Apps", "应用"),
        .colBlocked: ("Blocked", "被拦截"),
        .colAgent: ("AI agent", "AI agent"),
        .colStatus: ("Status", "状态"),
        .kindApp: ("App", "应用"),
        .kindAgent: ("AI agent", "AI agent"),
        .kindBinary: ("Program", "程序"),
        .sevMedium: ("Medium", "中"),
        .sevHigh: ("High", "高"),
        .sevCritical: ("Critical", "严重"),
        .decObserved: ("Recorded", "已记录"),
        .decAllowed: ("Allowed", "已允许"),
        .decDenied: ("Blocked", "已拦截"),
        .decWouldDeny: ("Would block", "将被拦截"),
        .decBenign: ("System (folded)", "系统（已折叠）"),
        .detected: ("Detected", "已检测到"),
        .notDetected: ("Not detected", "未检测到"),
        .search: ("Search", "搜索"),
        .refresh: ("Refresh", "刷新"),
        .save: ("Save", "保存"),
        .revert: ("Revert", "还原"),
        .add: ("Add", "添加"),
        .remove: ("Remove", "移除"),
        .delete: ("Delete", "删除"),
        .cancel: ("Cancel", "取消"),
        .done: ("Done", "完成"),
        .close: ("Close", "关闭"),

        .showSystemNoise: ("Show folded system activity", "显示已折叠的系统活动"),
        .pauseFeed: ("Pause feed", "暂停滚动"),
        .resumeFeed: ("Resume feed", "继续滚动"),
        .liveEmpty: ("No sensitive file access yet.", "还没有敏感文件访问。"),

        .markAllRead: ("Mark all read", "全部标为已读"),
        .unreadOnly: ("Unread only", "只看未读"),
        .statusUnread: ("Unread", "未读"),
        .statusRead: ("Read", "已读"),
        .statusResolved: ("Handled", "已处理"),
        .alertsEmpty: ("No alerts. WhoRead only alerts on unusual access.", "没有告警。WhoRead 只在出现异常时提醒。"),
        .pathsSeen: ("Paths", "涉及路径"),

        .agentsEmpty: ("No AI agent has touched a sensitive file yet.", "还没有 AI agent 碰过敏感文件。"),
        .appsEmpty: ("No app has touched a sensitive file yet.", "还没有应用碰过敏感文件。"),
        .filesEmpty: ("No sensitive category has been touched yet.", "还没有敏感类别被访问。"),

        .addRule: ("Add rule…", "添加规则…"),
        .templates: ("Templates", "模板"),
        .ruleEnabled: ("Enabled", "启用"),
        .ruleEnforce: ("Enforce", "强制拦截"),
        .ruleDryRun: ("Dry run (alert only)", "演练（只告警）"),
        .ruleTarget: ("Protects", "保护对象"),
        .ruleSubject: ("Applies to", "适用于"),
        .ruleAccess: ("Access", "访问类型"),
        .ruleAction: ("Action", "动作"),
        .targetCategory: ("Category", "类别"),
        .targetSeverity: ("Severity at least", "严重程度不低于"),
        .targetPath: ("Path prefix", "路径前缀"),
        .subjectSigned: ("Signed program (team + signing ID)", "已签名程序（team ID + signing ID）"),
        .subjectUnsigned: ("Unsigned program (path + cdhash)", "未签名程序（路径 + cdhash）"),
        .subjectApp: ("App", "应用"),
        .subjectAnyNonOwner: ("Anything that is not an expected owner", "任意非 owner 进程"),
        .subjectAgentChain: ("Anything started by an AI agent", "祖先链中包含 AI agent 的任意进程"),
        .exceptOwners: ("Except expected owners (e.g. ssh)", "owner 进程除外（例如 ssh）"),
        .includePlatformBinaries: ("Also apply to Apple system programs", "也作用于 Apple 系统程序"),
        .accessRead: ("Read", "读"),
        .accessWrite: ("Write", "写"),
        .accessAny: ("Any", "任意"),
        .actionAllow: ("Allow", "允许"),
        .actionDeny: ("Block", "拦截"),
        .actionAlert: ("Alert", "告警"),
        .rulesEnforcementOffNote: ("Enforcement is off: block rules only raise \"would block\" alerts.", "拦截总开关已关闭：拦截规则只会产生「将被拦截」告警。"),
        .ruleExceptionsFormat: ("%d exceptions", "%d 个例外"),
        .rulesEmpty: ("No rules.", "没有规则。"),
        .ruleChainNoAgent: ("only without an AI agent in the chain", "仅限调用链中没有 AI agent"),
        .ruleChainAgentsFormat: ("only with these AI agents in the chain: %@", "仅限调用链中的这些 AI agent：%@"),

        .setMonitoredPaths: ("Monitored paths", "监控路径"),
        .setProjectRoots: ("Project roots", "Project roots"),
        .setProjectRootsNote: ("Inside these folders, .env*, *.pem and *.key files are watched at any depth.", "在这些目录下，任意深度的 .env*、*.pem、*.key 文件都会被监控。"),
        .setAsk: ("Questions", "访问询问"),
        .setAskNote: ("With enforcement on, WhoRead holds the first access of an app to a sensitive file and asks you. Your answer is saved as a rule; unanswered in time, the access is denied.", "开启拦截后，应用第一次访问敏感文件时 WhoRead 会暂停这次访问并询问你。你的回答会保存为规则；未及时回答则拒绝访问。"),
        .setTrustApple: ("Trust all Apple programs (not when started by an AI agent)", "信任所有苹果程序（由 AI agent 启动时除外）"),
        .setTrustAppleNote: ("Apple programs in system locations are then allowed without asking. This weakens protection.", "开启后，系统位置中的苹果程序无需询问即被允许。这会削弱保护。"),
        .setRetention: ("Retention", "保留期"),
        .setRetentionDays: ("Keep history (days)", "保留历史（天）"),
        .setDetailDays: ("Keep details (days)", "保留明细（天）"),
        .setNotifications: ("Notifications", "通知"),
        .setNotificationsEnabled: ("Show notifications", "显示通知"),
        .setMinSeverity: ("Minimum severity", "最低严重程度"),
        .setNotifyWouldBlock: ("Notify for \"would block\"", "「将被拦截」时也通知"),
        .setEnforcement: ("Enforcement", "拦截"),
        .setEnforcementMaster: ("Enforce block rules", "执行拦截规则"),
        .setEnforcementNote: ("Rules marked Enforce block, and accesses nothing has decided yet are asked. WhoRead never turns enforcement off on its own. Needs the Endpoint Security extension.", "标记为「强制拦截」的规则会拦截，尚未决定的访问会询问你。WhoRead 不会自行关闭拦截。需要 Endpoint Security 扩展。"),
        .setLatency: ("Warn when p99 response time exceeds (ms)", "p99 响应时间超过此值时提醒（毫秒）"),
        .setReaddir: ("Also record directory listings", "同时记录目录列表（readdir）"),
        .setLanguage: ("Language", "语言"),
        .setLanguageSystem: ("System", "跟随系统"),
        .setCoalesce: ("Merge repeated alerts within (minutes)", "合并多少分钟内的重复告警"),
        .setSaved: ("Saved", "已保存"),
        .setPermissionNeeded: ("This change needs administrator rights.", "这项修改需要管理员权限。"),
        .slowResponsesFormat: ("Slow responses: %@. Enforcement stays as you set it.", "响应变慢：%@。拦截保持你的设置。"),
        .slowMissesFormat: ("%ld missed kernel deadlines", "错过内核期限 %ld 次"),
        .slowP99Format: ("p99 %@ ms (warning above %@ ms)", "p99 %@ 毫秒（超过 %@ 毫秒提醒）"),
        .uncleanStopFormat: ("The monitor stopped unexpectedly while it could block (%@). Enforcement stays as you set it.", "监控程序在可拦截状态下意外停止（%@）。拦截保持你的设置。"),

        .onbTitle: ("Welcome to WhoRead", "欢迎使用 WhoRead"),
        .onbIntro: ("WhoRead shows which app read your SSH keys, cloud credentials, browser data and other sensitive files — and who started it. Everything stays on this Mac. File contents are never read.", "WhoRead 告诉你哪个应用读了你的 SSH 密钥、云凭证、浏览器数据等敏感文件，以及是谁启动了它。所有数据只留在这台 Mac 上，从不读取文件内容。"),
        .onbFDATitle: ("Allow Full Disk Access", "授予「完全磁盘访问权限」"),
        .onbFDABody: ("macOS requires Full Disk Access for any app that monitors file access. Turn on WhoRead in the list.", "macOS 要求监控文件访问的应用拥有完全磁盘访问权限。请在列表中打开 WhoRead。"),
        .onbFDAButton: ("Open Privacy Settings", "打开隐私设置"),
        .onbExtTitle: ("Install the system extension", "安装系统扩展"),
        .onbExtBody: ("WhoRead's monitor runs as an Endpoint Security system extension. macOS asks you to approve it once.", "WhoRead 的监控程序是一个 Endpoint Security 系统扩展，macOS 会请你批准一次。"),
        .onbExtButton: ("Install extension", "安装扩展"),
        .onbExtApprove: ("Approve it in System Settings → General → Login Items & Extensions", "请在「系统设置 → 通用 → 登录项与扩展」中批准"),
        .onbDaemonTitle: ("Monitoring is running", "监控已运行"),
        .onbDaemonBody: ("WhoRead records which apps touch your sensitive files. With enforcement on, it asks you the first time an app wants one.", "WhoRead 会记录哪些应用碰了你的敏感文件。开启拦截后，应用第一次想访问时会先询问你。"),
        .onbAllSet: ("All set", "全部完成"),
        .onbWaiting: ("Waiting…", "等待中…"),
        .onbDone: ("Done", "已完成"),
        .onbFailedFormat: ("Failed: %@", "失败：%@"),
        .onbContinue: ("Continue", "继续"),
        .onbOpenLoginItems: ("Open Login Items & Extensions", "打开「登录项与扩展」"),
        .onbRestartRequired: ("Restart your Mac to finish activating the extension.", "重启 Mac 以完成扩展激活。"),
        .openSetup: ("Open setup…", "打开设置向导…"),

        .notifTitle: ("WhoRead", "WhoRead"),
        .notifBlockedTitle: ("WhoRead blocked an access", "WhoRead 拦截了一次访问"),
        .notifUncleanStopTitle: ("WhoRead's monitor stopped unexpectedly", "WhoRead 监控程序意外停止"),
        .notifRuleNotBlockingTitle: ("Rule saved, but it does not block yet", "规则已保存，但暂时不会拦截"),
        .notifAskTitle: ("Allow this access?", "允许这次访问吗？"),
        .notifAskFailedTitle: ("WhoRead could not take your answer", "WhoRead 未能接受你的回答"),

        .reasonDisabledByUser: ("switched off", "开关已关闭"),
        .reasonKillSwitchFile: ("kill-switch file present", "存在紧急关闭文件"),
        .reasonRulesFailedToLoad: ("rules failed to load", "规则加载失败"),
        .reasonSourceCannotEnforce: ("this monitor cannot block (eslogger)", "当前监控方式无法拦截（eslogger）"),
        .sourceCannotEnforceNote: ("This monitor (eslogger) cannot block: block rules only raise \"would block\" alerts.", "当前监控方式（eslogger）无法拦截：拦截规则只会产生「将被拦截」告警。"),

        .ruleName: ("Name", "名称"),
        .ruleSigningID: ("Signing ID", "Signing ID"),
        .ruleTeamID: ("Team ID", "Team ID"),
        .ruleNoTeamID: ("Apple or ad-hoc signed (no Team ID)", "Apple 或 ad-hoc 签名（没有 Team ID）"),
        .ruleProgramPath: ("Program path", "程序路径"),
        .ruleCdhash: ("cdhash (optional, 40 hex digits)", "cdhash（可选，40 位十六进制）"),
        .ruleAgentsNote: ("None selected means any AI agent.", "不选表示任意 AI agent。"),
        .rulePathNotMonitored: ("This path is not monitored yet: saving the rule adds it to the Custom category.", "这个路径尚未被监控：保存规则时会把它加入「自定义」类别。"),
        .ruleBlockAppFormat: ("Block %@ from %@", "拦截 %@ 访问 %@"),
        .ruleErrCategory: ("Choose a category.", "请选择类别。"),
        .ruleErrPath: ("The path must start with / or ~/.", "路径必须以 / 或 ~/ 开头。"),
        .ruleErrSigningID: ("Enter a signing ID.", "请填写 signing ID。"),
        .ruleErrTeamID: ("Enter a Team ID, or mark the program as Apple or ad-hoc signed.", "请填写 Team ID，或勾选 Apple / ad-hoc 签名。"),
        .ruleErrProgramPath: ("The program path must start with /.", "程序路径必须以 / 开头。"),
        .ruleErrCdhash: ("A cdhash is 40 hexadecimal digits.", "cdhash 是 40 位十六进制数。"),
        .ruleErrApp: ("Choose an app.", "请选择应用。"),
        .tplBlockAgentsCritical: ("Block AI agents from reading critical files", "禁止 AI agent 读取严重级别的文件"),
        .tplAlertAgentsHigh: ("Always alert when AI agents touch high-severity files", "AI agent 碰到高敏感文件时总是告警"),
        .tplDenyNonOwnerSSH: ("Block non-owners from reading SSH keys", "禁止非 owner 进程读取 SSH 密钥"),

        .setMonitoredPathsNote: ("Paths starting with ~/ apply to every home folder. Changes take effect immediately.", "以 ~/ 开头的路径适用于每个主目录。修改立即生效。"),
        .catPathPlaceholder: ("/path or ~/path", "/路径 或 ~/路径"),
        .catAddCategory: ("Add category", "添加类别"),
        .catNewCategoryName: ("Category name", "类别名称"),
        .catDeleteCategory: ("Delete category", "删除类别"),
        .catPathsManaged: ("Folders come from Project roots below.", "目录来自下方的 Project roots。"),
        .catInvalidPath: ("A path must start with / or ~/ and name a folder or file.", "路径必须以 / 或 ~/ 开头，并指向具体的目录或文件。"),
        .catCustomName: ("Custom", "自定义"),

        .detTitle: ("Access", "访问"),
        .detProcess: ("Process", "进程"),
        .detPID: ("PID", "PID"),
        .detExecutable: ("Executable", "可执行文件"),
        .detCdhash: ("cdhash", "cdhash"),
        .detPlatformBinary: ("Apple platform binary", "Apple 平台程序"),
        .detArguments: ("Arguments", "参数"),
        .detResponsible: ("Charged to", "归属"),
        .detOtherPath: ("Other path", "另一路径"),
        .yes: ("Yes", "是"),
        .no: ("No", "否"),
        .accessReadWrite: ("Read + write", "读写"),

        .opOpen: ("open", "打开"),
        .opClose: ("modified", "修改"),
        .opRename: ("rename", "重命名"),
        .opClone: ("clone", "克隆"),
        .opCopyfile: ("copy", "复制"),
        .opLink: ("hard link", "硬链接"),
        .opUnlink: ("delete", "删除"),
        .opTruncate: ("truncate", "截断"),
        .opExchangedata: ("exchange", "交换内容"),
        .opReaddir: ("list", "列目录"),
        .opCreate: ("create", "创建"),
        .opSetmode: ("change permissions", "修改权限"),
        .opSetowner: ("change owner", "修改所有者"),
        .opSetacl: ("change ACL", "修改 ACL"),
        .opMount: ("mount over", "挂载覆盖"),

        .errNotPermitted: ("Not permitted: the WhoRead monitor does not recognise this app as the signed WhoRead app, and changes that weaken protection need that app or sudo.",
                           "没有权限：WhoRead 监控程序没有把这个应用识别为已签名的 WhoRead 应用，而削弱保护的修改需要该应用或 sudo。"),
        .errUnavailable: ("The WhoRead daemon is not running.", "WhoRead 守护进程没有运行。"),
        .errVersionMismatchFormat: ("The WhoRead app and daemon versions differ (%@). Update or restart the daemon.", "WhoRead 应用与守护进程版本不一致（%@）。请更新或重启守护进程。"),
        .errDaemonFormat: ("The daemon refused: %@", "守护进程拒绝了请求：%@"),
        .errAdminFormat: ("Administrator action failed: %@", "管理员操作失败：%@"),
        .errNoAnswer: ("No answer from the WhoRead daemon.", "WhoRead 守护进程没有响应。"),
        .errNotConsoleUser: ("The WhoRead monitor serves only the user logged in at the screen (and administrators). This app runs as another user, so it cannot show or answer questions. Use the WhoRead app of the user at the screen, or sudo whoread asks.",
                             "WhoRead 监控程序只为当前在屏幕前登录的用户（以及管理员）服务。这个应用以其他用户身份运行，无法显示或回答问题。请使用屏幕前那个用户的 WhoRead 应用，或运行 sudo whoread asks。"),
    ]

    public static func mode(_ m: DaemonMode, _ language: Language = current) -> String {
        switch m {
        // Ask mode replaced the learning period: never shown as a state of its own.
        case .learning, .monitoring: return t(.modeMonitoring, language)
        case .enforcing: return t(.modeEnforcing, language)
        case .paused: return t(.modePaused, language)
        case .error: return t(.modeError, language)
        }
    }

    public static func severity(_ s: Severity, _ language: Language = current) -> String {
        switch s {
        case .medium: return t(.sevMedium, language)
        case .high: return t(.sevHigh, language)
        case .critical: return t(.sevCritical, language)
        }
    }

    public static func operation(_ op: FileOperation, _ language: Language = current) -> String {
        switch op {
        case .open: return t(.opOpen, language)
        case .close: return t(.opClose, language)
        case .rename: return t(.opRename, language)
        case .clone: return t(.opClone, language)
        case .copyfile: return t(.opCopyfile, language)
        case .link: return t(.opLink, language)
        case .unlink: return t(.opUnlink, language)
        case .truncate: return t(.opTruncate, language)
        case .exchangedata: return t(.opExchangedata, language)
        case .readdir: return t(.opReaddir, language)
        case .create: return t(.opCreate, language)
        case .setmode: return t(.opSetmode, language)
        case .setowner: return t(.opSetowner, language)
        case .setacl: return t(.opSetacl, language)
        case .mount: return t(.opMount, language)
        }
    }

    public static func decision(_ e: AnalyzedEvent, _ language: Language = current) -> String {
        if e.isBenign { return t(.decBenign, language) }
        switch e.decision {
        case .observed: return t(.decObserved, language)
        case .allowed: return t(.decAllowed, language)
        case .denied: return t(.decDenied, language)
        case .wouldDeny: return t(.decWouldDeny, language)
        }
    }

    public static func kind(_ k: ResponsibleEntity.Kind, _ language: Language = current) -> String {
        switch k {
        case .app: return t(.kindApp, language)
        case .agent: return t(.kindAgent, language)
        case .binary: return t(.kindBinary, language)
        }
    }

    public static func access(_ a: AccessSet, _ language: Language = current) -> String {
        switch (a.contains(.read), a.contains(.write)) {
        case (true, true): return t(.accessReadWrite, language)
        case (false, true): return t(.accessWrite, language)
        default: return t(.accessRead, language)
        }
    }

    public static func inactiveReason(_ r: EnforcementState.InactiveReason, _ language: Language = current) -> String {
        switch r {
        case .disabledByUser: return t(.reasonDisabledByUser, language)
        case .killSwitchFile: return t(.reasonKillSwitchFile, language)
        case .rulesFailedToLoad: return t(.reasonRulesFailedToLoad, language)
        case .sourceCannotEnforce: return t(.reasonSourceCannotEnforce, language)
        // Latency trips are gone (enforcement is never switched off automatically); not shown.
        default: return r.rawValue
        }
    }

    /// What a poll reads, as named in "not shown" and "could not read" notes.
    public static func partName(_ part: SnapshotPart, _ language: Language = current) -> String {
        switch part {
        case .alerts: return t(.partAlerts, language)
        case .live: return t(.partLive, language)
        case .summaries: return t(.partSummaries, language)
        case .rules: return t(.partRules, language)
        case .settings: return t(.partSettings, language)
        case .catalog: return t(.partCatalog, language)
        case .agents: return t(.partAgents, language)
        }
    }

    /// The command that shows the same data in Terminal.
    public static func partCommand(_ part: SnapshotPart) -> String {
        switch part {
        case .alerts: return "sudo whoread alerts"
        case .live: return "sudo whoread tail"
        case .summaries: return "sudo whoread apps"
        case .rules: return "sudo whoread rules"
        case .settings: return "whoread settings"
        case .catalog: return "whoread catalog"
        case .agents: return "whoread agents"
        }
    }

    /// Localized name of a built-in rule template (`Rule.template`).
    public static func templateName(_ template: String?, _ language: Language = current) -> String? {
        switch template {
        case "block-agents-critical": return t(.tplBlockAgentsCritical, language)
        case "alert-agents-high": return t(.tplAlertAgentsHigh, language)
        case "deny-nonowner-ssh": return t(.tplDenyNonOwnerSSH, language)
        default: return nil
        }
    }

    /// Button title for an answer to an ask-mode question (also on `ask` alerts). Other actions
    /// keep the shared alert wording.
    public static func askActionTitle(_ a: AlertAction, _ language: Language = current) -> String {
        switch a {
        case .allowOnce: return t(.askAllowOnce, language)
        case .alwaysAllow: return t(.askAlwaysAllow, language)
        case .keepBlocking: return t(.askDeny, language)
        case .blockFromNowOn: return t(.askAlwaysDeny, language)
        case .trustApplePrograms: return t(.askTrustApple, language)
        case .ignore: return AlertFormatter(language: language).actionTitle(a)
        }
    }

    /// What to show when the daemon did not take an answer to a question. An allow refused for lack
    /// of privilege (not recognised as the signed app, not root) says how to give it from Terminal.
    public static func answerError(_ e: IPCError, askID: Int64, action: AlertAction, _ language: Language = current) -> String {
        if isNotConsoleUser(e) { return t(.errNotConsoleUser, language) }
        switch e.code {
        case .notPermitted where AskAnswers.isAllow(action):
            return f(.askAllowNotPermittedFormat, "sudo whoread ask \(askID) \(AskAnswers.cliVerb(action))", language: language)
        // Denying is open to the console user: refused for a reason of its own (the stored rules could
        // not be loaded), which the daemon's message gives. Not "this app is not recognised".
        case .notPermitted:
            return f(.errDaemonFormat, DisplayText.escaped(e.message, limit: 1000), language: language)
        case .notFound:
            return t(.askGone, language)
        default:
            return answerOutcome(e, language) ?? message(for: e, language)
        }
    }

    /// The same for an answer given on an alert (Alerts tab, alert banners; `whoread alert` words).
    /// `kind`: the alert's kind, when known ("deny" on a question's alert is open to the console user).
    public static func alertActionError(_ e: IPCError, alertID: Int64, action: AlertAction, kind: AlertKind? = nil,
                                        _ language: Language = current) -> String {
        if isNotConsoleUser(e) { return t(.errNotConsoleUser, language) }
        if e.code == .notPermitted {
            // "Block from now on", and "deny" on a question's alert, strengthen protection: open to the
            // console user, so refused for a reason of its own.
            if action == .blockFromNowOn || (action == .keepBlocking && kind == .ask) {
                return f(.errDaemonFormat, DisplayText.escaped(e.message, limit: 1000), language: language)
            }
            return f(.alertNotPermittedFormat, "sudo whoread alert \(alertID) \(alertCLIWord(action))", language: language)
        }
        return answerOutcome(e, language) ?? message(for: e, language)
    }

    /// The daemon serves only root and the user at the console: this app runs as another user. Every
    /// request is refused then, whatever it is (ServiceHandler.authorize words it so).
    static func isNotConsoleUser(_ e: IPCError) -> Bool {
        e.code == .notPermitted && e.message.hasPrefix("only root or the console user")
    }

    /// `whoread alert ID WORD`.
    static func alertCLIWord(_ a: AlertAction) -> String {
        switch a {
        case .allowOnce: return "allow-once"
        case .alwaysAllow: return "always-allow"
        case .keepBlocking: return "keep-blocking"
        case .blockFromNowOn: return "block"
        case .ignore: return "ignore"
        case .trustApplePrograms: return "trust-apple"
        }
    }

    /// Outcomes of an answer that a plain "refused" would misreport: the rule limit (nothing changed),
    /// a rule or setting applied but not saved (it took effect), no reply (it may or may not have).
    /// The daemon's messages are matched as DaemonCore words them (pinned by tests).
    static func answerOutcome(_ e: IPCError, _ language: Language) -> String? {
        switch e.code {
        case .invalid where e.message.hasPrefix("too many rules"):
            return t(.answerRuleLimit, language)
        case .internalError where e.message.contains("applied but not saved"):
            return f(.answerNotSavedFormat, DisplayText.escaped(e.message, limit: 300), language: language)
        case .unavailable:
            return t(.answerNoReply, language)
        default:
            return nil
        }
    }

    /// What to show for a failed request. Daemon messages are English; known codes get a
    /// translated sentence.
    public static func message(for e: IPCError, _ language: Language = current) -> String {
        switch e.code {
        case .notPermitted: return t(isNotConsoleUser(e) ? .errNotConsoleUser : .errNotPermitted, language)
        case .unavailable: return t(.errUnavailable, language)
        // The daemon's message can quote names and paths: one escaped line.
        case .versionMismatch: return f(.errVersionMismatchFormat, DisplayText.escaped(e.message, limit: 1000), language: language)
        default: return f(.errDaemonFormat, DisplayText.escaped(e.message, limit: 1000), language: language)
        }
    }
}

