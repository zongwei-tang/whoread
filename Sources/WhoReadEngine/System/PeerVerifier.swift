import Foundation
import WhoReadIPC

/// Decides whether an XPC peer is the WhoRead menu bar app (as opposed to the CLI or anything
/// else running as the user). Only the app and root may weaken protection (enforcement off,
/// pause, allow rules…): an AI agent running as the user can run `whoread`, but cannot become
/// the signed app.
public protocol PeerVerifier: Sendable {
    func isApp(pid: Int32) -> Bool
}

public struct NoAppPeers: PeerVerifier {
    public init() {}
    public func isApp(pid: Int32) -> Bool { false }
}

#if os(macOS)
import Security

/// Checks the peer's code against a designated requirement for the app, e.g.
/// `identifier "com.example.whoread" and anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
///
/// NOT YET COMPILED. Uses public Security APIs: SecCodeCopyGuestWithAttributes with
/// kSecGuestAttributePid, SecRequirementCreateWithString, SecCodeCheckValidity. A pid can be
/// reused between connect and check; the XPC connection's own code-signing requirement is the
/// primary gate and this only classifies already-accepted peers.
public struct SignedAppPeerVerifier: PeerVerifier {
    public let requirementText: String

    public init(requirement: String) {
        self.requirementText = requirement
    }

    public func isApp(pid: Int32) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}
#endif
