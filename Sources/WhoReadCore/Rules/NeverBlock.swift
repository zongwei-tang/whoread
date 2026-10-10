import Foundation

/// Processes WhoRead never denies, regardless of rules. Hard-coded on purpose: a corrupted or
/// malicious rule file must not be able to wedge the login session or the update machinery.
///
/// Matching is by executable name, the platform-binary flag (which the kernel only sets for
/// Apple-signed system binaries, so a third-party binary named `launchd` does not qualify) *and* a
/// root-owned system location: a copied Apple binary keeps its platform flag, so `cp /bin/cat
/// /tmp/launchd` (or `~/mds_x`) must not escape every rule.
public struct NeverBlockList: Sendable {
    public static let exactNames: Set<String> = [
        "launchd",
        "kernel_task",
        "WindowServer",
        "loginwindow",
        "securityd",
        "trustd",
        "opendirectoryd",
        "syspolicyd",
        "tccd",
        "backupd",
        "backupd-helper",
        "installd",
        "softwareupdated",
        // Spotlight's helpers belong to the "mds family" too.
        "mdworker",
        "mdworker_shared",
        "mdsync",
        "corespotlightd",
        // Endpoint Security's own daemon.
        "endpointsecurityd",
    ]

    /// Names starting with these prefixes (the mds family: mds, mds_stores, mdsync…).
    public static let namePrefixes: [String] = ["mds"]

    /// The daemon's own pid(s) and executable paths (never block ourselves).
    public var selfPIDs: Set<Int32>
    public var selfExecutablePrefixes: [String]

    public init(selfPIDs: Set<Int32> = [], selfExecutablePrefixes: [String] = []) {
        self.selfPIDs = selfPIDs
        self.selfExecutablePrefixes = selfExecutablePrefixes.map(PathNormalizer.fold)
    }

    public func contains(_ p: ProcessRecord) -> Bool {
        if p.pid == 0 || p.pid == 1 { return true }
        if selfPIDs.contains(p.pid) { return true }
        if !selfExecutablePrefixes.isEmpty {
            let key = PathNormalizer.fold(p.executablePath)
            if selfExecutablePrefixes.contains(where: { key == $0 || key.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) {
                return true
            }
        }
        guard p.isPlatformBinary, IdentitySpec.isSystemLocation(p.executablePath) else { return false }
        let name = p.name
        if NeverBlockList.exactNames.contains(name) { return true }
        return NeverBlockList.namePrefixes.contains { name.hasPrefix($0) }
    }
}
