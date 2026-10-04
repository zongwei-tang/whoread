// WhoRead menu bar app (macOS 14+).
// NOT YET COMPILED: written on a Linux host. Logic lives in WhoReadUIModel (unit-tested);
// this target is SwiftUI/AppKit glue only.
import SwiftUI
import UserNotifications
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

@main
struct WhoReadApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var connection = DaemonConnection.shared

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environment(connection)
                .environment(connection.model)
        } label: {
            MenuBarLabel(state: connection.model.menuBar)
        }
        .menuBarExtraStyle(.window)

        Window(L10n.t(.appName), id: "main") {
            MainWindow()
                .environment(connection)
                .environment(connection.model)
                .frame(minWidth: 900, minHeight: 560)
        }
        .defaultSize(width: 1100, height: 700)
    }
}

/// Icon + unread badge in the menu bar.
struct MenuBarLabel: View {
    let state: MenuBarState
    var body: some View {
        HStack(spacing: 2) {
            Image(systemName: state.symbol)
            if let badge = state.badge {
                Text(badge).font(.caption2.monospacedDigit())
            }
        }
        .accessibilityLabel(Text(state.title))
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--uninstall-extension") {
            // Used by scripts/release/uninstall.sh: deactivate and quit.
            Task { @MainActor in
                SystemExtensionManager.shared.onFinish = { NSApp.terminate(nil) }
                SystemExtensionManager.shared.deactivate()
            }
            return
        }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        NotificationManager.shared.registerCategories()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        Task { @MainActor in DaemonConnection.shared.start() }
    }

    // Show banners even while the app is frontmost.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        NotificationManager.shared.handle(response)
        completionHandler()
    }
}
