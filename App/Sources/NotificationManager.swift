// NOT YET COMPILED (see WhoReadApp.swift).
import Foundation
import UserNotifications
import WhoReadCore
import WhoReadUIModel

/// UNUserNotificationCenter with action buttons ("允许一次 / 始终允许 / 保持拦截" …), and the ask-mode
/// questions ("允许一次（10 分钟）/ 始终允许 / 拒绝 / 始终拒绝").
final class NotificationManager: @unchecked Sendable {
    static let shared = NotificationManager()

    private func actionID(_ a: AlertAction) -> String { "whoread.action." + a.rawValue }

    /// Called at launch and again whenever the UI language changes. The categories and their
    /// titles come from `NotificationPlanner.categories` (one per kind of app, AI agent or program,
    /// so "always allow" says what it covers).
    func registerCategories(language: Language = L10n.current) {
        let categories = NotificationPlanner.categories(language: language).map { c in
            UNNotificationCategory(identifier: c.identifier, actions: c.buttons.map { b in
                // Allowing from a banner needs the Mac unlocked (not from the lock screen).
                let options: UNNotificationActionOptions = b.needsUnlock ? [.authenticationRequired] : (b.destructive ? [.destructive] : [])
                return UNNotificationAction(identifier: actionID(b.action), title: b.title, options: options)
            }, intentIdentifiers: [], options: [])
        }
        UNUserNotificationCenter.current().setNotificationCategories(Set(categories))
    }

    func post(_ n: PlannedNotification) {
        let content = UNMutableNotificationContent()
        content.title = n.title
        content.body = n.body
        content.categoryIdentifier = n.categoryIdentifier
        content.threadIdentifier = n.threadIdentifier
        content.userInfo = ["alertID": NSNumber(value: n.alertID)]
        content.sound = n.categoryIdentifier.hasPrefix(NotificationPlanner.categoryBlocked + ".") ? .default : nil
        let request = UNNotificationRequest(identifier: n.identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// An open question, with the answers as buttons (`NotificationPlanner.askCategory`).
    func post(_ n: PlannedAskNotification) {
        let content = UNMutableNotificationContent()
        content.title = n.title
        content.body = n.body
        content.categoryIdentifier = n.categoryIdentifier
        content.threadIdentifier = NotificationPlanner.categoryAsk
        content.userInfo = ["askID": NSNumber(value: n.askID)]
        // A replacement (the same question, now with its path) does not sound again.
        content.sound = n.quiet ? nil : .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: n.identifier, content: content, trigger: nil))
    }

    /// Withdraws the banners of questions no longer open.
    func remove(asks identifiers: [String]) {
        guard !identifiers.isEmpty else { return }
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
        center.removePendingNotificationRequests(withIdentifiers: identifiers)
    }

    /// Withdraws question banners left by a previous run of the app (answered or expired since).
    func removeDeliveredAsks(keeping open: Set<String>) {
        UNUserNotificationCenter.current().getDeliveredNotifications { delivered in
            let stale = delivered.map(\.request.identifier).filter { NotificationPlanner.isAskIdentifier($0) && !open.contains($0) }
            if !stale.isEmpty { UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: stale) }
        }
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

    /// The answer button the user pressed; nil for a click on the banner itself.
    private func pressedAction(in response: UNNotificationResponse) -> AlertAction? {
        let raw = response.actionIdentifier
        guard raw.hasPrefix("whoread.action.") else { return nil }
        return AlertAction(rawValue: String(raw.dropFirst("whoread.action.".count)))
    }

    func handle(_ response: UNNotificationResponse) {
        let info = response.notification.request.content.userInfo
        if let ask = (info["askID"] as? NSNumber)?.int64Value {
            guard let action = pressedAction(in: response) else {
                // Clicked the banner itself: open questions are listed in the Alerts tab.
                Task { @MainActor in NavigationState.shared.show(tab: .alerts) }
                return
            }
            Task { @MainActor in DaemonConnection.shared.answer(ask: ask, action, fromNotification: true) }
            return
        }
        guard let id = (info["alertID"] as? NSNumber)?.int64Value else {
            if let raw = info["tab"] as? String, let tab = Tab(rawValue: raw) {
                Task { @MainActor in NavigationState.shared.show(tab: tab) }
            }
            return
        }
        guard let action = pressedAction(in: response) else {
            // Clicked the banner itself: open the Alerts tab.
            Task { @MainActor in NavigationState.shared.show(tab: .alerts) }
            return
        }
        Task { @MainActor in DaemonConnection.shared.act(on: id, action, fromNotification: true) }
    }
}
