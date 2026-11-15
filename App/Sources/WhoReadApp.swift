// WhoRead menu bar app (macOS 14+). Logic lives in WhoReadUIModel (unit-tested); this target is
// SwiftUI/AppKit glue only.
import SwiftUI
import UserNotifications
import WhoReadCore
import WhoReadIPC
import WhoReadUIModel

/// The entry point. `--self-check` checks the daemon and exits before anything of the app starts: no
/// window, no menu bar item, no notification permission request. Anything else runs the menu bar app.
@main
@MainActor
enum WhoReadMain {
    static func main() {
        if CommandLine.arguments.dropFirst().contains(SelfCheck.argument) { SelfCheckCommand.run() }
        WhoReadApp.main()
    }
}

/// `--self-check` (`SelfCheck`): on the Mach service and transport the app would use, then exit.
@MainActor
enum SelfCheckCommand {
    static func run() -> Never {
        let name = DaemonConnection.resolveServiceName()
        let client = XPCClient(machServiceName: name, timeout: SelfCheck.timeout)
        let result = SelfCheck.run(client, viaExtension: name == DaemonConnection.extensionServiceName)
        client.invalidate()
        for line in result.lines { print(line) }
        fflush(stdout)
        exit(result.exitStatus)
    }
}

struct WhoReadApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var connection = DaemonConnection.shared

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environment(connection)
                .environment(connection.model)
        } label: {
            MenuBarLabel(model: connection.model)
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

/// Icon + badge in the menu bar: open questions first (a question mark and their count), then
/// unread alerts. Reads the model in its own body so observation tracking refreshes it (a value
/// computed in `App.body` might not be).
struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let state = model.menuBar
        HStack(spacing: 2) {
            Image(systemName: state.labelSymbol)
            if let badge = state.badge {
                Text(badge).font(.caption2.monospacedDigit())
            }
        }
        .accessibilityLabel(Text(state.accessibilityLabel))
        // The label lives as long as the app: lets notification clicks open the main window.
        .onAppear { NavigationState.shared.openMainWindow = { openWindow(id: "main") } }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--uninstall-extension") {
            // Used by scripts/release/uninstall.sh: deactivate and quit.
            Task { @MainActor in
                // The exit status tells scripts/release/uninstall.sh whether deactivation worked.
                SystemExtensionManager.shared.onFinish = { ok in exit(ok ? 0 : 1) }
                SystemExtensionManager.shared.deactivate()
            }
            return
        }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        NotificationManager.shared.registerCategories()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        Task { @MainActor in
            DaemonConnection.shared.start()
            // The first launch registers WhoRead to open at login; later ones leave it as the user set it.
            AppLoginItem.shared.appLaunched()
        }
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
