import Foundation
#if canImport(Security)
import Security
#endif

/// Which code-signing requirement the XPC listener installs on a new connection, and what the
/// handler may then assume about that peer.
///
/// The requirement is installed with `NSXPCConnection.setCodeSigningRequirement`, which checks every
/// incoming message against it: "If new messages do not match the requirement, the connection is
/// invalidated" (NSXPCConnection.h, macOS 13). XPC makes that check on the audit token each message
/// carries, so what the handler is told holds for the code that sent the message, not for whoever
/// holds the peer's pid by the time the request is served.
///
/// The CLI and the app both meet the client requirement; only the app may weaken protection. The app
/// is told apart by installing `(client) and (app)` on its connection, so XPC checks every one of its
/// messages against the app requirement too. Which of the two to install is chosen from a look at the
/// peer's pid when the connection arrives (`looksLikeApp`), and that look is only a hint: a wrong
/// guess either installs the app requirement on a connection whose messages then fail it (the
/// connection is invalidated), or the client requirement on the app's own (no privilege on that
/// connection). Neither gives `isApp` to code that is not the app.
public struct XPCPeerPolicy: Sendable {
    public enum Decision: Sendable, Equatable {
        case reject
        /// `requirement` nil: install none (root, or a development build without requirements).
        case accept(requirement: String?, peer: IPCPeer)
    }

    public let clientRequirement: String?
    public let appRequirement: String?
    /// Requirements that do not parse. Each is handled fail-closed (see `decide`); log them.
    public let errors: [String]
    /// Requirements that work but should not be relied on outside development; log them.
    public let warnings: [String]
    let clientUsable: Bool
    let appUsable: Bool

    /// `parses` checks a requirement's syntax: `setCodeSigningRequirement` raises an Objective-C
    /// exception on a malformed one, which would take the daemon down at the first connection.
    public init(clientRequirement: String?, appRequirement: String?, parses: (String) -> Bool = XPCPeerPolicy.parses) {
        self.clientRequirement = clientRequirement
        self.appRequirement = appRequirement
        var errors: [String] = []
        var warnings: [String] = []
        clientUsable = clientRequirement.map(parses) ?? false
        if clientRequirement != nil && !clientUsable {
            errors.append("the client code-signing requirement does not parse: every non-root client is refused")
        }
        var appUsable = appRequirement.map(parses) ?? false
        if appRequirement != nil && !appUsable {
            errors.append("the app code-signing requirement does not parse: the WhoRead app is never recognised")
        }
        // Each can parse alone and not combined: a `//` or `#` comment, or a trailing `;`, in the client
        // requirement swallows or breaks the rest of "(client) and (app)", which the app's connection gets.
        if clientUsable, appUsable, let client = clientRequirement, let app = appRequirement,
           !parses(XPCPeerPolicy.combined(client: client, app: app)) {
            appUsable = false
            errors.append("the client and app code-signing requirements do not parse when combined (a comment or a "
                          + "trailing ';' in the client one?): the WhoRead app is never recognised")
        }
        self.appUsable = appUsable
        if let app = appRequirement, appUsable, !app.contains(XPCPeerPolicy.developerIDLeafOID) {
            // Apple Development (and ad hoc) builds carry get-task-allow: code running as the user can
            // attach to such an app and send requests as it.
            warnings.append("the app code-signing requirement does not pin Developer ID: development-signed "
                            + "(debuggable) builds are recognised as the app. Use it for development only")
        }
        self.errors = errors
        self.warnings = warnings
    }

    /// Marker extension of a Developer ID Application leaf certificate.
    public static let developerIDLeafOID = "1.2.840.113635.100.6.1.13"

    /// The requirement installed on the app's connection: the client one as well, so the app path
    /// never admits code the client requirement would refuse.
    public var appConnectionRequirement: String? {
        guard clientUsable, appUsable, let client = clientRequirement, let app = appRequirement else { return nil }
        return XPCPeerPolicy.combined(client: client, app: app)
    }

    static func combined(client: String, app: String) -> String { "(\(client)) and (\(app))" }

    /// The app can be recognised at all (worth looking at a new peer's pid).
    public var recognisesApp: Bool { appConnectionRequirement != nil }

    public func decide(euid: UInt32, pid: Int32, looksLikeApp: Bool) -> Decision {
        // Root may use any build (`sudo whoread enforcement off` must always work; root can create the
        // kill-switch file anyway).
        if euid == 0 { return .accept(requirement: nil, peer: IPCPeer(pid: pid, euid: euid, isTrustedCode: false)) }
        guard let client = clientRequirement else {
            // Development build without requirements: any local client may connect (the handler still
            // checks the euid), and nothing is recognised as the app.
            return .accept(requirement: nil, peer: IPCPeer(pid: pid, euid: euid, isTrustedCode: false))
        }
        // A requirement that does not parse must not turn into "no requirement".
        guard clientUsable else { return .reject }
        if looksLikeApp, let both = appConnectionRequirement {
            return .accept(requirement: both, peer: IPCPeer(pid: pid, euid: euid, isTrustedCode: true, isApp: true))
        }
        return .accept(requirement: client, peer: IPCPeer(pid: pid, euid: euid, isTrustedCode: true))
    }

    /// The requirement compiles (Security framework). Elsewhere there is no XPC: any non-empty text.
    public static func parses(_ requirement: String) -> Bool {
        #if canImport(Security)
        var compiled: SecRequirement?
        return SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess && compiled != nil
        #else
        return !requirement.isEmpty
        #endif
    }
}
