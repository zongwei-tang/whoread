import Foundation
import XCTest
@testable import WhoReadCore

// Review of the native source (files-10): a mount on a directory above monitored prefixes hides
// every one of them, and eslogger's setattrlist shape is unverified. Regression tests for the fixes.

private func rvLine(_ event: String) -> String {
    #"{"schema_version":1,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/sbin\/mount_hfs"}},"event":{\#(event)}}"#
}

private func rvMount(_ point: String, _ t: TimeInterval = 1) -> FileActivity {
    FileActivity(time: at(t), operation: .mount, process: proc(700, "/sbin/mount_hfs", platform: true),
                 targets: OperationSemantics.mount(mountPoint: point))
}

final class MountOverAncestorReviewTests: XCTestCase {
    func testMountOverAnAncestorIsAWriteToEveryCategoryBelowIt() throws {
        // hdiutil attach -mountpoint ~/.config evil.dmg: gh, gcloud… now show the image's files. Before: nothing.
        let h = try Harness()
        for point in ["/Users/alice/.config", "/System/Volumes/Data/Users/alice/.config"] {
            let classified = h.analyzer.classify(rvMount(point)).filter(\.isSensitive)
            XCTAssertEqual(classified.count, 1, point)
            XCTAssertEqual(classified.first?.path, "/Users/alice/.config", point)
            XCTAssertTrue(classified.first?.viaAncestor ?? false, point)
            XCTAssertTrue(classified.first?.categories.contains { $0.id == "gh" } ?? false, point)
            XCTAssertEqual(classified.first?.target.access, .write, "hidden, not read: \(point)")
        }
        // Recorded as an event of each category below.
        let out = h.analyzer.handle(.file(rvMount("/Users/alice/.config")))
        XCTAssertTrue(out.events.contains { $0.categoryID == "gh" && $0.operation == .mount && $0.access == .write })
        // ~/Library hides every app data category below it.
        let library = h.analyzer.classify(rvMount("/Users/alice/Library")).filter(\.isSensitive)
        XCTAssertTrue(library.first?.categories.contains { $0.id == "chrome" } ?? false)
    }

    func testAWriteDenyRuleDecidesAMountOverAnAncestor() throws {
        var rule = Rule(id: "no-gh-writes", target: .category("gh"), subject: .anyNonOwner, access: .write, action: .deny,
                        includePlatformBinaries: true)
        rule.enforce = true
        let h = try Harness(rules: [rule])
        let mount = rvMount("/Users/alice/.config")
        let targets = h.analyzer.classify(mount).filter(\.isSensitive).map(\.evaluationTarget)
        let chain = h.tree.chain(for: mount.process, at: mount.time)
        let d = h.rules.evaluate(process: chain.first?.image ?? mount.process, chain: chain, targets: targets,
                                 enforcementActive: true, now: mount.time)
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "no-gh-writes")
    }

    func testMountOverACategoryDirectoryIsJudgedByItsWorstFile() throws {
        // The mounted file system replaces Cookies too: critical, as for a profile folder moved away.
        let h = try Harness()
        let profile = "/Users/alice/Library/Application Support/Google/Chrome/Default"
        let classified = h.analyzer.classify(rvMount(profile)).filter(\.isSensitive)
        XCTAssertEqual(classified.first?.categories.map(\.id), ["chrome"])
        XCTAssertEqual(classified.first?.categories.map(\.severity), [.critical])
        XCTAssertEqual(classified.first?.target.access, .write)
    }

    func testMountOnAHomeOrAboveIsNotJudged() throws {
        // Network, auto_home and FileVault homes are mounted on the home or above it at every login.
        let h = try Harness()
        for point in ["/Users/alice", "/Users/alice/", "/Users", "/System/Volumes/Data/Users/alice", "/System/Volumes/Data", "/"] {
            XCTAssertFalse(h.analyzer.classify(rvMount(point)).contains(where: \.isSensitive), point)
        }
        // auto_home: /home/bob is a link into the data volume's autofs mount point.
        let n = PathNormalizer(homeDirectories: ["/home/bob", "/System/Volumes/Data/home/bob"])
        h.analyzer.replace(classifier: PathClassifier(catalog: h.data.catalog, normalizer: n))
        for point in ["/System/Volumes/Data/home/bob", "/System/Volumes/Data/home", "/home", "/home/bob"] {
            XCTAssertFalse(h.analyzer.classify(rvMount(point)).contains(where: \.isSensitive), point)
        }
        let config = h.analyzer.classify(rvMount("/System/Volumes/Data/home/bob/.config")).filter(\.isSensitive)
        XCTAssertTrue(config.first?.categories.contains { $0.id == "gh" } ?? false, "inside the home it is judged")
    }

    func testOnlyMountsCoverWhatIsBelow() throws {
        // A permission change of an ancestor changes that directory only.
        let h = try Harness()
        let chmod = FileActivity(time: at(1), operation: .setmode, process: proc(700, "/bin/chmod", platform: true),
                                 targets: OperationSemantics.attributes(ReportedPath("/Users/alice/.config", isDirectory: true)))
        XCTAssertFalse(h.analyzer.classify(chmod).contains(where: \.isSensitive))
        // And chmod of a category directory stays at the directory's own severity.
        let profile = "/Users/alice/Library/Application Support/Google/Chrome/Default"
        let dir = FileActivity(time: at(1), operation: .setmode, process: proc(700, "/bin/chmod", platform: true),
                               targets: OperationSemantics.attributes(ReportedPath(profile, isDirectory: true)))
        let own = try XCTUnwrap(h.classifier.classify(profile)?.severity)
        XCTAssertLessThan(own, .critical)
        XCTAssertEqual(h.analyzer.classify(dir).first?.categories.map(\.severity), [own])
    }

    func testEsloggerMountOverAnAncestorReachesTheParser() throws {
        // The line names no monitored prefix: the prefilter must not drop it.
        let line = rvLine(#""mount":{"statfs":{"f_mntonname":"\/Users\/alice\/.config","f_mntfromname":"\/dev\/disk4s1"},"disposition":3}"#)
        let filter = LinePrefilter(prefixes: ["/Users/alice/.config/gh", "/Users/alice/.ssh"])
        XCTAssertEqual(filter.verdict(line), .parse)
        guard case .event(.file(let activity)) = EsloggerParser().parse(line: line) else { return XCTFail("not parsed") }
        let h = try Harness()
        XCTAssertTrue(h.analyzer.classify(activity).contains { $0.categories.contains { $0.id == "gh" } })
        // An unmount or remount line is no mount.
        XCTAssertEqual(filter.verdict(rvLine(#""unmount":{"statfs":{"f_mntonname":"\/Volumes\/x"}}"#)), .drop)
    }
}

final class SetattrlistShapeReviewTests: XCTestCase {
    func testSetattrlistWithoutCommonAttributesIsMalformedNotIgnored() {
        // eslogger's setattrlist JSON is unverified: a shape without attrlist.commonattr must show in the
        // parser's malformed count instead of silently dropping every chmod made through setattrlist.
        for body in [#""setattrlist":{"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519"}}"#,
                     #""setattrlist":{"attrlist":{"bitmapcount":5},"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519"}}"#] {
            guard case .malformed = EsloggerParser().parse(line: rvLine(body)) else { return XCTFail(body) }
        }
        // Present but naming none of the permission attributes: ignored, as before.
        let times = #""setattrlist":{"attrlist":{"bitmapcount":5,"commonattr":1024},"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519"}}"#
        guard case .ignored = EsloggerParser().parse(line: rvLine(times)) else { return XCTFail("times only") }
    }
}
