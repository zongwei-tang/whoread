import Foundation
import ServiceManagement
import WhoReadUIModel

/// WhoRead itself as a login item: `SMAppService.mainApp` (ServiceManagement, macOS 13+).
final class MainAppLoginItem: LoginItemService {
    var status: LoginItemStatus {
        switch SMAppService.mainApp.status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .notFound
        }
    }

    func register() throws { try SMAppService.mainApp.register() }
    func unregister() throws { try SMAppService.mainApp.unregister() }
    func openSystemSettingsLoginItems() { SMAppService.openSystemSettingsLoginItems() }
}

/// The app's "open at login" (`OpenAtLogin`), remembered in the standard user defaults.
@MainActor
enum AppLoginItem {
    static let shared = OpenAtLogin(
        service: MainAppLoginItem(),
        isHandled: { UserDefaults.standard.bool(forKey: OpenAtLogin.handledKey) },
        markHandled: { UserDefaults.standard.set(true, forKey: OpenAtLogin.handledKey) })

    /// `--unregister-login-item` (scripts/uninstall.sh), before anything of the app starts: exit status 0
    /// when WhoRead no longer opens at login, 1 (with the reason on stderr) when macOS refused.
    static func unregisterAndExit() -> Never {
        let ok = shared.uninstall(forgetHandled: {
            UserDefaults.standard.removeObject(forKey: OpenAtLogin.handledKey)
            UserDefaults.standard.synchronize()
        })
        if !ok, let note = shared.note(.en) {
            FileHandle.standardError.write(Data((note + "\n").utf8))
        }
        exit(ok ? 0 : 1)
    }
}
