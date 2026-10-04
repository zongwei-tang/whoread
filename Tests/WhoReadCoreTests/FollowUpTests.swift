import XCTest
@testable import WhoReadCore

/// Follow-ups from review round 1 (ingest and native source).
final class FollowUpTests: XCTestCase {
    func testSymlinkToDevNullIsNotMonitored() throws {
        let data = try defaultData()
        // ~/.zsh_history -> /dev/null (a common way to turn history off).
        let links = MapSymlinkResolver(["/Users/alice/.zsh_history": "/dev/null"],
                                       links: ["/Users/alice/.aws": [(link: "/Users/alice/.aws/x", target: "/dev/zero")]])
        let c = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: [home]), symlinks: links)
        XCTAssertFalse(c.mutePaths.contains { $0 == "/dev/null" || $0.hasPrefix("/dev/") })
        XCTAssertFalse(c.prefixes.contains { $0.path.hasPrefix("/dev") })
        XCTAssertNil(c.classify("/dev/null"))
        XCTAssertEqual(c.classify("/Users/alice/.zsh_history")?.categoryID, "shell-history")
    }

    func testDirectoryListingIsNeverWouldBlock() throws {
        let rule = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .any, action: .deny,
                        includePlatformBinaries: true)
        let h = try Harness(rules: [rule])
        h.analyzer.readdirEnabled = true
        let ls = h.spawn(P.terminal, ProcessRecord(pid: 700, ppid: 100, executablePath: "/bin/ls", isPlatformBinary: true), 1)
        let out = h.file(.readdir, ls, OperationSemantics.readdir(path: "/Users/alice/.ssh"), 2)
        XCTAssertEqual(out.events.first?.decision, .observed, "listings are never blocked, so never 'would block'")
        XCTAssertNil(out.events.first?.ruleID, "deny rules do not apply to listings")
        XCTAssertNotEqual(out.alerts.first?.alert.kind, .wouldBlock)
    }
}

final class CloseDoesNotConsumeTests: XCTestCase {
    /// A modified close reports a write an earlier open already decided; it must not use up an
    /// "allow once" meant for the next open (monitor-only path too).
    func testModifiedCloseKeepsTheAllowOnce() throws {
        let now = t0
        var rule = Rule(id: "deny", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .any,
                        action: .deny, includePlatformBinaries: true)
        rule.exceptions = [RuleException(subject: .anyNonOwner, expiresAt: now.addingTimeInterval(3600), remainingUses: 1, createdAt: now)]
        let h = try Harness(rules: [rule])
        let vim = h.spawn(P.terminal, ProcessRecord(pid: 710, ppid: 100, executablePath: "/usr/bin/vim", isPlatformBinary: true), 1)
        _ = h.file(.close, vim, OperationSemantics.close(path: "/Users/alice/.ssh/config", modified: true), 2)
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 1)
    }
}
