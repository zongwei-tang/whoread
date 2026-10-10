import Foundation
import WhoReadIPC

/// A first look at a new XPC peer: does its pid seem to be the WhoRead menu bar app (as opposed to the
/// CLI or anything else running as the user)? Only the app and root may weaken protection
/// (enforcement off, pause, allow rules…).
///
/// The answer only chooses which requirement XPC enforces on that connection (`XPCPeerPolicy`): the
/// app's connection gets the app requirement, which XPC checks against the audit token of every
/// message. A pid names whoever holds it at the moment of the look, so the answer never grants
/// anything on its own, and `ServiceHandler` never consults it.
public protocol PeerVerifier: Sendable {
    func isApp(pid: Int32) -> Bool
}

public struct NoAppPeers: PeerVerifier {
    public init() {}
    public func isApp(pid: Int32) -> Bool { false }
}

extension XPCPeerPolicy {
    /// The accept-time look at a pid checks exactly the requirement XPC then enforces on the app's
    /// connection (`appConnectionRequirement`, the client one included), so a "yes" never installs a
    /// requirement the app itself fails (its connection would be invalidated, not merely unprivileged).
    public var appCandidate: PeerVerifier {
        #if os(macOS)
        if let requirement = appConnectionRequirement { return SignedAppPeerVerifier(requirement: requirement) }
        #endif
        return NoAppPeers()
    }
}

#if os(macOS)
import Security

/// Checks the code running as `pid` against the app's designated requirement, e.g.
/// `identifier "com.example.whoread" and anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
/// Public Security APIs: SecCodeCopyGuestWithAttributes with kSecGuestAttributePid,
/// SecRequirementCreateWithString, SecCodeCheckValidity. A requirement that does not parse is never
/// met (SecCodeCheckValidity with no requirement would succeed).
public struct SignedAppPeerVerifier: PeerVerifier {
    public let requirementText: String

    public init(requirement: String) {
        self.requirementText = requirement
    }

    public func isApp(pid: Int32) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}
#endif
