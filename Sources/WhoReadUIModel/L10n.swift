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
    case appName, modeLearning, modeMonitoring, modeEnforcing, modePaused, modeError, unreadAlertsFormat, openWindow
    case pauseMonitoring, resumeMonitoring, enforcement, enforcementOn, enforcementOff, enforcementInactiveFormat
    case killSwitchAdmin, quit, daemonUnreachable, recentAlerts, noAlerts, learningUntilFormat
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
    // Settings
    case setMonitoredPaths, setProjectRoots, setProjectRootsNote, setLearning, setLearningDays, setRestartLearning
    case setRetention, setRetentionDays, setDetailDays, setNotifications, setNotificationsEnabled, setMinSeverity
    case setNotifyWouldBlock, setEnforcement, setEnforcementMaster, setEnforcementNote, setLatency, setReaddir
    case setLanguage, setLanguageSystem, setCoalesce, setSaved, setPermissionNeeded
    // Onboarding
    case onbTitle, onbIntro, onbFDATitle, onbFDABody, onbFDAButton, onbExtTitle, onbExtBody, onbExtButton
    case onbExtApprove, onbDaemonTitle, onbDaemonBody, onbAllSet, onbWaiting, onbDone, onbFailedFormat, onbContinue
    case onbOpenLoginItems, onbRestartRequired, openSetup
    // Notifications
    case notifTitle, notifBlockedTitle, notifEnforcementTrippedTitle, notifEnforcementTrippedBodyFormat, notifRuleNotBlockingTitle
    // Enforcement inactive reasons and caveats
    case reasonDisabledByUser, reasonKillSwitchFile, reasonLatencyTripped, reasonRulesFailedToLoad, reasonSourceCannotEnforce
    case sourceCannotEnforceNote
    // Rule editor
    case ruleName, ruleSigningID, ruleTeamID, ruleNoTeamID, ruleProgramPath, ruleCdhash, ruleAgentsNote
    case rulePathNotMonitored, ruleMonitorPath, ruleBlockAppFormat
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
    // Errors
    case errNotPermitted, errUnavailable, errVersionMismatchFormat, errDaemonFormat, errAdminFormat
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
        .modeLearning: ("Learning", "学习中"),
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
        .learningUntilFormat: ("Learning normal behaviour until %@", "正在学习正常行为，直到 %@"),

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

        .setMonitoredPaths: ("Monitored paths", "监控路径"),
        .setProjectRoots: ("Project roots", "Project roots"),
        .setProjectRootsNote: ("Inside these folders, .env*, *.pem and *.key files are watched at any depth.", "在这些目录下，任意深度的 .env*、*.pem、*.key 文件都会被监控。"),
        .setLearning: ("Learning period", "学习期"),
        .setLearningDays: ("Days", "天数"),
        .setRestartLearning: ("Restart learning", "重新学习"),
        .setRetention: ("Retention", "保留期"),
        .setRetentionDays: ("Keep history (days)", "保留历史（天）"),
        .setDetailDays: ("Keep details (days)", "保留明细（天）"),
        .setNotifications: ("Notifications", "通知"),
        .setNotificationsEnabled: ("Show notifications", "显示通知"),
        .setMinSeverity: ("Minimum severity", "最低严重程度"),
        .setNotifyWouldBlock: ("Notify for \"would block\"", "「将被拦截」时也通知"),
        .setEnforcement: ("Enforcement", "拦截"),
        .setEnforcementMaster: ("Enforce block rules", "执行拦截规则"),
        .setEnforcementNote: ("Only rules you marked as Enforce can block. Needs the Endpoint Security extension.", "只有你标记为「强制拦截」的规则才会拦截。需要 Endpoint Security 扩展。"),
        .setLatency: ("Disable automatically if p99 response exceeds (ms)", "p99 响应超过此值时自动关闭（毫秒）"),
        .setReaddir: ("Also record directory listings", "同时记录目录列表（readdir）"),
        .setLanguage: ("Language", "语言"),
        .setLanguageSystem: ("System", "跟随系统"),
        .setCoalesce: ("Merge repeated alerts within (minutes)", "合并多少分钟内的重复告警"),
        .setSaved: ("Saved", "已保存"),
        .setPermissionNeeded: ("This change needs administrator rights.", "这项修改需要管理员权限。"),

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
        .onbDaemonBody: ("WhoRead learns what is normal for 7 days and only alerts on unusual access.", "WhoRead 会学习 7 天的正常行为，之后只在出现异常时提醒。"),
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
        .notifEnforcementTrippedTitle: ("WhoRead turned enforcement off", "WhoRead 已关闭拦截"),
        .notifEnforcementTrippedBodyFormat: ("The monitor answered too slowly (%@). Nothing is blocked until you turn enforcement back on.", "监控响应过慢（%@），在你重新开启拦截之前不会拦截任何访问。"),
        .notifRuleNotBlockingTitle: ("Rule saved, but it does not block yet", "规则已保存，但暂时不会拦截"),

        .reasonDisabledByUser: ("switched off", "开关已关闭"),
        .reasonKillSwitchFile: ("kill-switch file present", "存在紧急关闭文件"),
        .reasonLatencyTripped: ("turned off automatically: responses too slow", "响应过慢，已自动关闭"),
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
        .rulePathNotMonitored: ("This path is not monitored, so the rule can never match.", "这个路径不在监控范围内，规则永远不会生效。"),
        .ruleMonitorPath: ("Also monitor this path", "同时监控这个路径"),
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

        .errNotPermitted: ("Not permitted. Changes that weaken protection need the WhoRead app or sudo.", "没有权限：削弱保护的修改需要 WhoRead 应用或 sudo。"),
        .errUnavailable: ("The WhoRead daemon is not running.", "WhoRead 守护进程没有运行。"),
        .errVersionMismatchFormat: ("The WhoRead app and daemon versions differ (%@). Update or restart the daemon.", "WhoRead 应用与守护进程版本不一致（%@）。请更新或重启守护进程。"),
        .errDaemonFormat: ("The daemon refused: %@", "守护进程拒绝了请求：%@"),
        .errAdminFormat: ("Administrator action failed: %@", "管理员操作失败：%@"),
    ]

    public static func mode(_ m: DaemonMode, _ language: Language = current) -> String {
        switch m {
        case .learning: return t(.modeLearning, language)
        case .monitoring: return t(.modeMonitoring, language)
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
        case .latencyTripped: return t(.reasonLatencyTripped, language)
        case .rulesFailedToLoad: return t(.reasonRulesFailedToLoad, language)
        case .sourceCannotEnforce: return t(.reasonSourceCannotEnforce, language)
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

    /// What to show for a failed request. Daemon messages are English; known codes get a
    /// translated sentence.
    public static func message(for e: IPCError, _ language: Language = current) -> String {
        switch e.code {
        case .notPermitted: return t(.errNotPermitted, language)
        case .unavailable: return t(.errUnavailable, language)
        case .versionMismatch: return f(.errVersionMismatchFormat, e.message, language: language)
        default: return f(.errDaemonFormat, e.message, language: language)
        }
    }
}

