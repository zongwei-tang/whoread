import Foundation
import WhoReadCore
import WhoReadIPC

/// `WhoRead.app/Contents/MacOS/WhoRead --self-check`: does the daemon answer, does it monitor, and does
/// it take this program for the WhoRead app? The installer pins the app's code identity in the daemon's
/// requirements; an app rebuilt or replaced after installing no longer matches.
///
/// Three requests on the connection the app would use: the handshake (protocol version), the status,
/// and one read that only the WhoRead app (or root) may make, the rules (cheap: served from memory, and
/// the reply is dropped). One line per step on stdout, in stable English for people and scripts, so not
/// localized. Only status fields are printed (the daemon's version, the protocol, the source kind, the
/// source's error and hint), escaped as the CLI prints them: never an event, an alert or a rule, so no
/// line names a file or a command line.
///
///     daemon: reachable (WhoRead <version>, protocol <n>)   | daemon: unreachable (<reason>)
///     monitoring: running (source <kind>)                   | monitoring: stopped (source <kind>): <error> [hint: <hint>]
///     app recognised: yes                                   | app recognised: no (<reason>)
///
/// A stopped source's error and hint appear only when the daemon has them. The first step that fails
/// ends the check: an unreachable daemon prints one line. With the dev LaunchDaemon, no answer to the
/// handshake also says that it may be refusing this program (`refusalHint`): XPC drops each connection of
/// an app its pinned client requirement does not admit, which looks like no answer.
public struct SelfCheck: Equatable, Sendable {
    /// The exit status.
    public enum Outcome: Int32, Sendable {
        /// The daemon answers and serves this program as the WhoRead app.
        case recognised = 0
        /// No answer, or another protocol.
        case unreachable = 1
        /// The daemon answers, but does not serve this program as the WhoRead app.
        case notRecognised = 2
    }

    /// The command line flag.
    public static let argument = "--self-check"
    /// Seconds each request may take.
    public static let timeout: TimeInterval = 10

    public var lines: [String]
    public var outcome: Outcome
    public var exitStatus: Int32 { outcome.rawValue }

    public init(lines: [String], outcome: Outcome) {
        self.lines = lines
        self.outcome = outcome
    }

    /// `viaExtension`: the daemon answers on the system extension's service, which scripts/install.sh
    /// does not set up. `asRoot`: this process runs as root, which the daemon serves whatever program
    /// asks, so the read would say nothing about the app; it is not made then.
    public static func run(_ client: IPCClient, viaExtension: Bool = false, asRoot: Bool = geteuid() == 0) -> SelfCheck {
        var lines: [String] = []
        func end(_ line: String, _ outcome: Outcome) -> SelfCheck {
            lines.append(line)
            return SelfCheck(lines: lines, outcome: outcome)
        }

        let version: Int
        do {
            guard case .hello(let v) = try client.call(.hello(clientVersion: whoReadIPCVersion)) else {
                return end("daemon: unreachable (protocol mismatch: unexpected reply)", .unreachable)
            }
            version = v
        } catch {
            return end("daemon: unreachable (\(reason(error))\(viaExtension ? "" : refusalHint(error)))", .unreachable)
        }
        guard version == whoReadIPCVersion else {
            return end("daemon: unreachable (protocol mismatch: the daemon speaks protocol \(version), this app \(whoReadIPCVersion))",
                       .unreachable)
        }
        let status: DaemonStatus
        do {
            status = try client.status()
        } catch {
            return end("daemon: unreachable (\(reason(error)))", .unreachable)
        }
        lines.append("daemon: reachable (WhoRead \(DisplayText.escaped(status.version, limit: 64)), protocol \(version))")
        lines.append(monitoringLine(status))

        if asRoot {
            return end("app recognised: no (running as root, which the daemon serves whatever program asks: run the self-check "
                       + "as the user logged in at the screen)", .notRecognised)
        }
        do {
            _ = try client.rules()
            return end("app recognised: yes", .recognised)
        } catch let e as IPCError where e.code == .notPermitted && !L10n.isNotConsoleUser(e) {
            let why: String
            if viaExtension {
                why = "the system extension does not take this program for the signed WhoRead app"
            } else if status.source == .native {
                // A VM with SIP disabled: scripts/install.sh would install the eslogger source (and needs Xcode).
                why = "the daemon does not take this program for the WhoRead app it was installed with: it runs the native "
                    + "monitor, so install it again with this app, sudo scripts/install-dev-daemon.sh native --app WhoRead.app"
            } else {
                why = "the daemon does not take this program for the WhoRead app it was installed with: if the app was rebuilt "
                    + "or replaced after installing, run scripts/install.sh again"
            }
            return end("app recognised: no (\(why))", .notRecognised)
        } catch {
            // No answer, or a reply this app cannot read: the daemon could not be asked, which is not a refusal.
            let unanswered = (error as? IPCError).map { $0.code == .unavailable || $0.code == .versionMismatch } ?? (error is DecodingError)
            return end("app recognised: no (\(unanswered ? "could not be checked: " : "")\(reason(error)))",
                       unanswered ? .unreachable : .notRecognised)
        }
    }

    static func monitoringLine(_ s: DaemonStatus) -> String {
        let kind = s.source.rawValue
        guard !s.sourceRunning else { return "monitoring: running (source \(kind))" }
        var line = "monitoring: stopped (source \(kind))"
        if let error = s.sourceError { line += ": " + escaped(error) }
        if let hint = s.sourceHint { line += " [hint: " + escaped(hint) + "]" }
        return line
    }

    /// After the reason the handshake got no answer (`.unavailable`) from the dev LaunchDaemon: it may be
    /// refusing this very program. The client requirement scripts/install.sh pins admits only the app and
    /// CLI it installed, and XPC drops every connection of a rebuilt or replaced app (the app says so too:
    /// `AppModel.unreachableText`). Nothing for a daemon that answered, whatever it said.
    static func refusalHint(_ error: Error) -> String {
        guard let e = error as? IPCError, e.code == .unavailable else { return "" }
        return "; if com.whoread.daemon is running, it may be refusing this program: run scripts/install.sh again, which is "
            + "needed when the app was rebuilt or replaced after installing"
    }

    /// Why a request failed, in one line: the daemon's or the transport's words, escaped.
    static func reason(_ error: Error) -> String {
        switch error {
        case let e as IPCError where e.code == .versionMismatch: return "protocol mismatch: " + escaped(e.message)
        case let e as IPCError: return escaped(e.message)
        case is DecodingError: return "protocol mismatch: unreadable reply"
        default: return escaped("\(error)")
        }
    }

    /// Text from the daemon or the transport: hidden characters (line breaks included) escaped, so it
    /// stays on its line and cannot send a terminal escape sequence; capped.
    static func escaped(_ s: String) -> String { DisplayText.escaped(s, limit: 1000) }
}
