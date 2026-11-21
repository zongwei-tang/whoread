import Foundation
#if os(macOS)
import Observation
#endif
import WhoReadCore

/// Whether WhoRead opens at login, as ServiceManagement reports it (`SMAppService.Status`).
public enum LoginItemStatus: Equatable, Sendable {
    case notRegistered
    case enabled
    /// Registered, but not allowed to open: the user turned it off in System Settings → General → Login
    /// Items (or never approved it). Only the user can allow it again, there.
    case requiresApproval
    case notFound
}

/// What "open at login" needs from ServiceManagement: `SMAppService.mainApp` in the app, a fake in tests.
public protocol LoginItemService: AnyObject {
    var status: LoginItemStatus { get }
    func register() throws
    func unregister() throws
    /// System Settings → General → Login Items.
    func openSystemSettingsLoginItems()
}

/// Settings → General → Open at login. The first launch registers WhoRead as a login item; no later
/// launch does, so a user who turns it off in System Settings (or here) is not overridden. The app keeps
/// whether that happened (`handledKey`, in UserDefaults). The switch shows what ServiceManagement
/// reports; turning it on while macOS waits for the user's approval opens System Settings instead.
///
/// `@Observable` on macOS only, as `AppModel`. Main thread only.
#if os(macOS)
@Observable
#endif
public final class OpenAtLogin {
    /// UserDefaults key: the first launch registered WhoRead, or the user has chosen since.
    public static let handledKey = "OpenAtLoginHandled"

    /// As last read from ServiceManagement (`refresh`).
    public private(set) var status: LoginItemStatus = .notRegistered
    /// Why the last change did not take, in the system's words (escaped); nil after one that did.
    public private(set) var failure: String?
    private let service: LoginItemService
    private let isHandled: () -> Bool
    private let markHandled: () -> Void

    public init(service: LoginItemService, isHandled: @escaping () -> Bool, markHandled: @escaping () -> Void) {
        self.service = service
        self.isHandled = isHandled
        self.markHandled = markHandled
    }

    /// The switch: on while WhoRead opens at login.
    public var isOn: Bool { status == .enabled }

    /// Reads the status again: the user may have changed it in System Settings meanwhile.
    public func refresh() { status = service.status }

    /// At every launch: only the first registers WhoRead, and only when macOS has no login item for it
    /// yet. One that exists (registered by an earlier copy, or turned off in System Settings) is left as
    /// the user has it. A registration that fails is tried again at the next launch: nothing was
    /// registered that the user could have turned off.
    public func appLaunched() {
        refresh()
        guard !isHandled() else { return }
        switch status {
        case .enabled, .requiresApproval:
            markHandled()
        case .notRegistered, .notFound:
            do {
                try service.register()
                markHandled()
                failure = nil
            } catch {
                failure = OpenAtLogin.describe(error)
            }
            refresh()
        }
    }

    /// The switch in Settings. From now on the user decides: no launch registers WhoRead again.
    public func set(_ on: Bool) {
        markHandled()
        failure = nil
        refresh()
        // Turned off in System Settings: only the user can allow it again, there.
        if on && status == .requiresApproval {
            service.openSystemSettingsLoginItems()
            return
        }
        var error: Error?
        do {
            if on { try service.register() } else { try service.unregister() }
        } catch let e {
            error = e
        }
        refresh()
        if on && status == .requiresApproval {
            // Registered, but macOS waits for the user's approval.
            service.openSystemSettingsLoginItems()
        } else if let error, isOn != on {
            // An error that left it as it was ("already registered" or "not registered" changes nothing).
            failure = OpenAtLogin.describe(error)
        }
    }

    public func openSystemSettings() { service.openSystemSettingsLoginItems() }

    /// The app's argument for scripts/uninstall.sh: `uninstall`, then exit before anything else starts.
    public static let unregisterArgument = "--unregister-login-item"

    /// WhoRead is being removed: takes its login item back, if there is one, and forgets that the first
    /// launch happened (`forgetHandled`), so that installing WhoRead again later opens it at login again.
    /// False when ServiceManagement refused and the login item is still there (`note` says why); the
    /// flag is kept then.
    public func uninstall(forgetHandled: () -> Void) -> Bool {
        refresh()
        if status == .enabled || status == .requiresApproval {
            var error: Error?
            do { try service.unregister() } catch let e { error = e }
            refresh()
            if status == .enabled || status == .requiresApproval {
                failure = OpenAtLogin.describe(error ?? CocoaError(.featureUnsupported))
                return false
            }
        }
        failure = nil
        forgetHandled()
        return true
    }

    /// Under the switch: why the last change failed, or that the user has to allow it in System Settings.
    public func note(_ language: Language = L10n.current) -> String? {
        if let failure { return L10n.f(.loginItemFailedFormat, failure, language: language) }
        return status == .requiresApproval ? L10n.t(.loginItemNeedsApproval, language) : nil
    }

    static func describe(_ error: Error) -> String {
        DisplayText.escaped(error.localizedDescription, limit: 300)
    }
}
