// NOT YET COMPILED (see WhoReadApp.swift).
import Foundation
import UserNotifications
import WhoReadCore
import WhoReadUIModel

/// UNUserNotificationCenter with action buttons ("允许一次 / 始终允许 / 保持拦截" …).
final class NotificationManager: @unchecked Sendable {
    static let shared = NotificationManager()

    private func actionID(_ a: AlertAction) -> String { "whoread.action." + a.rawValue }

    /// Called at launch and again whenever the UI language changes.
    func registerCategories(language: Language = L10n.current) {
        let f = AlertFormatter(language: language)
        func category(_ id: String, _ actions: [AlertAction]) -> UNNotificationCategory {
            let buttons = actions.map { a -> UNNotificationAction in
                let destructive = a == .blockFromNowOn || a == .keepBlocking
                return UNNotificationAction(identifier: actionID(a), title: f.actionTitle(a), options: destructive ? [.destructive] : [])
            }
            return UNNotificationCategory(identifier: id, actions: buttons, intentIdentifiers: [], options: [])
        }
        UNUserNotificationCenter.current().setNotificationCategories([
            category(NotificationPlanner.categoryBlocked, [.allowOnce, .alwaysAllow, .keepBlocking]),
            category(NotificationPlanner.categoryAlert, [.alwaysAllow, .blockFromNowOn, .ignore]),
            category(NotificationPlanner.categoryWouldBlock, [.alwaysAllow, .ignore]),
        ])
    }

    func post(_ n: PlannedNotification) {
        let content = UNMutableNotificationContent()
        content.title = n.title
        content.body = n.body
        content.categoryIdentifier = n.categoryIdentifier
        content.threadIdentifier = n.threadIdentifier
        content.userInfo = ["alertID": NSNumber(value: n.alertID)]
        content.sound = n.categoryIdentifier == NotificationPlanner.categoryBlocked ? .default : nil
        let request = UNNotificationRequest(identifier: n.identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// A notice about WhoRead itself (no action buttons). Clicking it opens `tab`.
    func post(_ notice: SystemNotice, tab: Tab) {
        let content = UNMutableNotificationContent()
        content.title = notice.title
        content.body = notice.body
        content.userInfo = ["tab": tab.rawValue]
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: notice.identifier, content: content, trigger: nil))
    }

    func handle(_ response: UNNotificationResponse) {
        let info = response.notification.request.content.userInfo
        guard let id = (info["alertID"] as? NSNumber)?.int64Value else {
            if let raw = info["tab"] as? String, let tab = Tab(rawValue: raw) {
                Task { @MainActor in NavigationState.shared.show(tab: tab) }
            }
            return
        }
        let raw = response.actionIdentifier
        guard raw.hasPrefix("whoread.action."), let action = AlertAction(rawValue: String(raw.dropFirst("whoread.action.".count))) else {
            // Clicked the banner itself: open the Alerts tab.
            Task { @MainActor in NavigationState.shared.show(tab: .alerts) }
            return
        }
        Task { @MainActor in DaemonConnection.shared.act(on: id, action, fromNotification: true) }
    }
}
