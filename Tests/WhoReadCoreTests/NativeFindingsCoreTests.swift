import Foundation
import XCTest
@testable import WhoReadCore

// Regression tests for the native source findings, Core side: open(O_RDONLY|O_TRUNC)
// (files-8), a rename onto an existing directory (files-5), permission, owner, ACL and mount changes
// (files-10), and the normalizer's home list (files-4). The native ES conversion and mute plan are
// tested in WhoReadEngineTests (NativeFindingsEngineTests).

private let nfKey = "/Users/alice/.ssh/id_ed25519"

private func nfEnforced(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

/// Rule decision for an AUTH event (what Enforcer.decide evaluates once classification is done).
private func nfDecide(_ h: Harness, _ activity: FileActivity) -> RuleDecision {
    let targets = h.analyzer.classify(activity).filter(\.isSensitive).map(\.evaluationTarget)
    let chain = h.tree.chain(for: activity.process, at: activity.time)
    return h.rules.evaluate(process: chain.first?.image ?? activity.process, chain: chain, targets: targets,
                            enforcementActive: true, now: activity.time)
}

/// Terminal → zsh → node running Claude Code → leaf.
private func nfAgentLeaf(_ h: Harness, _ leaf: ProcessRecord) -> ProcessRecord {
    let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
    let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]))
    return h.spawn(claude, leaf)
}

private func nfLine(_ event: String) -> String {
    #"{"schema_version":1,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/bin\/chmod"}},"event":{\#(event)}}"#
}

private func nfFile(_ line: String) -> FileActivity? {
    if case .event(.file(let f)) = EsloggerParser().parse(line: line) { return f }
    return nil
}

// MARK: - files-8: O_TRUNC

final class OpenTruncFindingTests: XCTestCase {
    func testReadOnlyOpenWithTruncIsAWrite() {
        // O_RDONLY|O_TRUNC is FREAD|O_TRUNC in the kernel fflag: it empties the file.
        XCTAssertEqual(OperationSemantics.openAccess(fflag: 0x1 | 0x400), [.read, .write])
        XCTAssertEqual(OperationSemantics.openAccess(fflag: 0x400), .write)
        XCTAssertEqual(OperationSemantics.openAccess(fflag: 0x1), .read, "a plain read stays a read")
        XCTAssertEqual(OperationSemantics.openAccess(fflag: 0x1 | 0x0100_0000 | 0x0010_0000), .read, "O_CLOEXEC/O_DIRECTORY are no write")
        let (op, targets) = OperationSemantics.open(ReportedPath(nfKey, isDirectory: false), fflag: 0x401)
        XCTAssertEqual(op, .open)
        XCTAssertEqual(targets.map(\.access), [[.read, .write]])
    }

    func testTruncatingOpenOfAnUnknownTypeIsNotAListing() {
        // O_DIRECTORY with O_TRUNC fails on a directory; with no stat it must not be dropped as a readdir.
        let (op, targets) = OperationSemantics.open(ReportedPath(nfKey), fflag: 0x1 | 0x400 | 0x0010_0000)
        XCTAssertEqual(op, .open)
        XCTAssertEqual(targets.first?.access.contains(.write), true)
        XCTAssertEqual(OperationSemantics.open(ReportedPath("/Users/alice/.ssh"), fflag: 0x1 | 0x0010_0000).0, .readdir)
    }

    func testEsloggerTruncatingOpenIsRecordedAndDecidedAsAWrite() throws {
        let line = nfLine(#""open":{"fflag":1025,"file":{"path":"\/Users\/alice\/.ssh\/authorized_keys","stat":{"st_mode":33188}}}"#)
        let activity = try XCTUnwrap(nfFile(line))
        XCTAssertEqual(activity.targets.map(\.access), [[.read, .write]])
        // A write-only deny rule now decides it (before: recorded and judged as a read).
        let h = try Harness(rules: [nfEnforced(Rule(id: "no-writes", target: .category("ssh"), subject: .anyNonOwner,
                                                    access: .write, action: .deny, includePlatformBinaries: true))])
        let cat = h.spawn(P.terminal, P.cat(700, parent: 100))
        var a = activity
        a.process = cat
        XCTAssertEqual(nfDecide(h, a).verdict, .deny)
        let out = h.analyzer.handle(.file(a))
        XCTAssertEqual(out.events.first?.access, [.read, .write])
    }
}

// MARK: - files-5: rename onto an existing directory

final class RenameSwapFindingTests: XCTestCase {
    func testExistingDirectoryDestinationIsReadAndCarried() {
        let targets = OperationSemantics.rename(ReportedPath("/private/tmp/empty", isDirectory: true),
                                                ReportedPath("/Users/alice/.config", isDirectory: true))
        XCTAssertEqual(targets[1].access, .readWrite)
        XCTAssertEqual(targets[1].isDirectory, true, "the destination's stat is kept")
        XCTAssertTrue(targets[1].carriesContent(in: .rename))
        XCTAssertTrue(targets[0].carriesContent(in: .rename))
        XCTAssertFalse(targets[1].carriesContent(in: .clone), "only a rename can land on a directory")
    }

    func testExistingFileDestinationStaysAnOverwrite() throws {
        // Atomic saves rename a temp file over the real one: not a read of it.
        let targets = OperationSemantics.rename(ReportedPath("/Users/alice/.aws/credentials.tmp", isDirectory: false),
                                                ReportedPath("/Users/alice/.aws/credentials", isDirectory: false))
        XCTAssertEqual(targets[1].access, .write)
        XCTAssertFalse(targets[1].carriesContent(in: .rename))
        let unknown = OperationSemantics.rename(ReportedPath("/private/tmp/x"), ReportedPath("/Users/alice/.aws/credentials"))
        XCTAssertEqual(unknown[1].access, .write, "unknown type: taken as a file")
        let h = try Harness()
        let classified = h.analyzer.classify(FileActivity(time: at(1), operation: .rename, process: P.cat(700, parent: 1), targets: targets))
        XCTAssertEqual(classified[1].categories.map(\.id), ["aws"])
        XCTAssertEqual(classified[1].target.access, .write)
    }

    func testSwapOntoAnAncestorCarriesEveryCategoryBelowIt() throws {
        // renamex_np("/private/tmp/empty", "~/.config", RENAME_SWAP) reported as one rename: ~/.config ends up at
        // /private/tmp/empty. Before: no sensitive target at all.
        let h = try Harness()
        let swap = FileActivity(time: at(1), operation: .rename, process: P.cat(700, parent: 1),
                                targets: OperationSemantics.rename(ReportedPath("/private/tmp/empty", isDirectory: true),
                                                                   ReportedPath("/Users/alice/.config", isDirectory: true)))
        let classified = h.analyzer.classify(swap).filter(\.isSensitive)
        XCTAssertEqual(classified.count, 1)
        XCTAssertEqual(classified.first?.path, "/Users/alice/.config")
        XCTAssertTrue(classified.first?.viaAncestor ?? false)
        XCTAssertTrue(classified.first?.categories.contains { $0.id == "gh" } ?? false)
        XCTAssertEqual(classified.first?.target.access, .readWrite)
    }

    func testSwapOntoTheSSHDirectoryIsAReadOfTheKeys() throws {
        // The "block AI agents from reading critical files" template is read-only: it must cover the swap.
        let h = try Harness(rules: [nfEnforced(RuleTemplates.blockAgentsFromCritical())])
        let mv = nfAgentLeaf(h, proc(700, "/bin/mv", platform: true))
        let swap = FileActivity(time: at(1), operation: .rename, process: mv,
                                targets: OperationSemantics.rename(ReportedPath("/private/tmp/decoy", isDirectory: true),
                                                                   ReportedPath("/Users/alice/.ssh", isDirectory: true)))
        let classified = h.analyzer.classify(swap).filter(\.isSensitive)
        XCTAssertEqual(classified.first?.categories.map(\.severity), [.critical], "judged by the worst file it can hold")
        let d = nfDecide(h, swap)
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "template.block-agents-critical")
    }

    func testEsloggerRenameKeepsTheDestinationsType() throws {
        let line = nfLine(#""rename":{"source":{"path":"\/private\/tmp\/empty","stat":{"st_mode":16877}},"destination_type":0,"destination":{"existing_file":{"path":"\/Users\/alice\/.config","stat":{"st_mode":16877}}}}"#)
        let a = try XCTUnwrap(nfFile(line))
        XCTAssertEqual(a.targets[1].isDirectory, true)
        XCTAssertEqual(a.targets[1].access, .readWrite)
        let h = try Harness()
        var activity = a
        activity.process = h.spawn(P.terminal, P.cat(700, parent: 100))
        let out = h.analyzer.handle(.file(activity))
        XCTAssertTrue(out.events.contains { $0.categoryID == "gh" && $0.access.contains(.read) })
    }
}

// MARK: - files-10: permission, owner, ACL and mount changes

final class AttributeChangeFindingTests: XCTestCase {
    func testEsloggerParsesPermissionOwnerAndACLChanges() throws {
        for (kind, op) in [("setmode", FileOperation.setmode), ("setowner", .setowner), ("setacl", .setacl)] {
            let a = try XCTUnwrap(nfFile(nfLine(#""\#(kind)":{"mode":420,"uid":502,"gid":20,"set_or_clear":0,"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519","stat":{"st_mode":33152}}}"#)), kind)
            XCTAssertEqual(a.operation, op)
            XCTAssertEqual(a.targets.map(\.path), [nfKey])
            XCTAssertEqual(a.targets.map(\.access), [.write])
            XCTAssertEqual(a.targets.first?.isDirectory, false)
        }
        XCTAssertNil(nfFile(nfLine(#""setmode":{"mode":420}"#)), "no target: malformed")
    }

    func testEsloggerSetattrlistCountsOnlyPermissionAndOwnerAttributes() throws {
        func line(_ common: UInt32) -> String {
            nfLine(#""setattrlist":{"attrlist":{"bitmapcount":5,"commonattr":\#(common),"volattr":0,"dirattr":0,"fileattr":0,"forkattr":0},"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519"}}"#)
        }
        XCTAssertEqual(nfFile(line(0x20000))?.operation, .setmode, "ATTR_CMN_ACCESSMASK")
        XCTAssertEqual(nfFile(line(0x8000))?.operation, .setowner, "ATTR_CMN_OWNERID")
        XCTAssertEqual(nfFile(line(0x10000))?.operation, .setowner, "ATTR_CMN_GRPID")
        XCTAssertEqual(nfFile(line(0x400000))?.operation, .setacl, "ATTR_CMN_EXTENDED_SECURITY")
        XCTAssertEqual(nfFile(line(0x400 | 0x20000))?.operation, .setmode)
        // Times and Finder info only: not recorded.
        guard case .ignored = EsloggerParser().parse(line: line(0x400 | 0x4000)) else { return XCTFail("modtime/finderinfo recorded") }
        XCTAssertEqual(OperationSemantics.setattrlistOperation(commonattr: 0x800000), .setowner, "ATTR_CMN_UUID")
        XCTAssertEqual(OperationSemantics.setattrlistOperation(commonattr: 0x1000000), .setowner, "ATTR_CMN_GRPUUID")
        XCTAssertNil(OperationSemantics.setattrlistOperation(commonattr: 0x40000), "ATTR_CMN_FLAGS (chflags) is not a permission change")
    }

    func testEsloggerParsesAMountByItsMountPoint() throws {
        let a = try XCTUnwrap(nfFile(nfLine(#""mount":{"statfs":{"f_mntonname":"\/Users\/alice\/.ssh","f_mntfromname":"\/dev\/disk4s1","f_fstypename":"hfs"},"disposition":3}"#)))
        XCTAssertEqual(a.operation, .mount)
        XCTAssertEqual(a.targets.map(\.path), ["/Users/alice/.ssh"])
        XCTAssertEqual(a.targets.map(\.access), [.write])
        guard case .malformed = EsloggerParser().parse(line: nfLine(#""mount":{"disposition":3}"#)) else { return XCTFail("no statfs") }
    }

    func testPermissionChangesOfAKeyAreRecordedAndDecidedAsWrites() throws {
        let h = try Harness(rules: [nfEnforced(Rule(id: "no-writes", target: .category("ssh"), subject: .anyNonOwner,
                                                    access: .write, action: .deny, includePlatformBinaries: true))])
        let chmod = h.spawn(P.terminal, proc(700, "/bin/chmod", platform: true))
        for op in [FileOperation.setmode, .setowner, .setacl] {
            let a = FileActivity(time: at(1), operation: op, process: chmod,
                                 targets: OperationSemantics.attributes(ReportedPath(nfKey, isDirectory: false)))
            XCTAssertEqual(nfDecide(h, a).verdict, .deny, "\(op)")
            let out = h.analyzer.handle(.file(a))
            XCTAssertEqual(out.events.map(\.categoryID), ["ssh"])
            XCTAssertEqual(out.events.first?.severity, .critical)
            XCTAssertEqual(out.events.first?.operation, op)
            XCTAssertEqual(out.events.first?.access, .write)
        }
        // chmod 755 ~/.ssh: the directory itself is the ssh category.
        let dir = FileActivity(time: at(2), operation: .setmode, process: chmod,
                               targets: OperationSemantics.attributes(ReportedPath("/Users/alice/.ssh", isDirectory: true)))
        XCTAssertEqual(h.analyzer.classify(dir).first?.categories.map(\.id), ["ssh"])
    }

    func testMountOverAMonitoredDirectoryIsAWriteButNotOverAnAncestor() throws {
        let h = try Harness()
        let mounter = proc(700, "/sbin/mount_hfs", platform: true)
        let over = FileActivity(time: at(1), operation: .mount, process: mounter,
                                targets: OperationSemantics.mount(mountPoint: "/Users/alice/.ssh"))
        XCTAssertEqual(h.analyzer.classify(over).first?.categories.map(\.id), ["ssh"])
        XCTAssertEqual(h.analyzer.classify(over).first?.target.access, .write)
        // A home mounted at login is not every category's write.
        for point in ["/Users/alice", "/System/Volumes/Data/home/alice"] {
            let a = FileActivity(time: at(1), operation: .mount, process: mounter, targets: OperationSemantics.mount(mountPoint: point))
            XCTAssertFalse(h.analyzer.classify(a).contains(where: \.isSensitive), point)
        }
        // Nor a disk, image or share arriving where volumes are mounted (although that folder is a category).
        for point in ["/Volumes/USB", "/System/Volumes/Data/Volumes/Backup Disk", "/volumes/x"] {
            XCTAssertTrue(OperationSemantics.mount(mountPoint: point).isEmpty, point)
        }
        // A mount over a monitored folder inside a volume is still one.
        let inside = FileActivity(time: at(1), operation: .mount, process: mounter,
                                  targets: OperationSemantics.mount(mountPoint: "/Volumes/USB/vault"))
        XCTAssertEqual(h.analyzer.classify(inside).first?.categories.map(\.id), ["volumes"])
        XCTAssertTrue(OperationSemantics.mount(mountPoint: "").isEmpty)
    }

    func testPrefilterPassesTheNewEventsOnMonitoredPaths() {
        let filter = LinePrefilter(prefixes: ["/Users/alice/.ssh"])
        XCTAssertEqual(filter.verdict(nfLine(#""setmode":{"mode":420,"target":{"path":"\/Users\/alice\/.ssh\/id_ed25519"}}"#)), .parse)
        XCTAssertEqual(filter.verdict(nfLine(#""mount":{"statfs":{"f_mntonname":"\/Users\/alice\/.ssh"}}"#)), .parse)
        XCTAssertEqual(filter.verdict(nfLine(#""setmode":{"mode":420,"target":{"path":"\/Users\/alice\/notes.txt"}}"#)), .drop)
    }
}

// MARK: - files-4: normalizer homes

final class HomeSpellingFindingTests: XCTestCase {
    func testAHomeAndItsDataVolumeSpellingNormalizeToOneHome() {
        // HomeDirectories adds a home and its realpath; both normalize to /home/bob.
        let n = PathNormalizer(homeDirectories: ["/home/bob", "/System/Volumes/Data/home/bob", "/Users/alice"])
        XCTAssertEqual(n.homeDirectories, ["/home/bob", "/Users/alice"])
        XCTAssertEqual(n.expand("~/.ssh"), ["/home/bob/.ssh", "/Users/alice/.ssh"])
        let c = PathClassifier(catalog: try! defaultData().catalog, normalizer: n)
        XCTAssertEqual(c.classify("/System/Volumes/Data/home/bob/.ssh/id_ed25519")?.categoryID, "ssh")
    }

    func testLinkWalkIgnoresLinksInsideTheDirectoryWhateverItsSpelling() throws {
        // The walk gets a normalized prefix; a link's target is a realpath. When the prefix is reached through
        // a symlink (/home -> /System/Volumes/Data/home), a link to a sibling inside it is still inside.
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        let base = (tmp as NSString).appendingPathComponent("wr-links-\(UUID().uuidString.prefix(8))")
        let real = base + "/real"
        let fm = FileManager.default
        try fm.createDirectory(atPath: real + "/.aws/profiles", withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: base) }
        try fm.createSymbolicLink(atPath: base + "/alias", withDestinationPath: real)
        try fm.createSymbolicLink(atPath: real + "/.aws/current", withDestinationPath: real + "/.aws/profiles")
        try fm.createSymbolicLink(atPath: real + "/.aws/outside", withDestinationPath: base)
        let found = RealpathSymlinkResolver().symlinks(under: base + "/alias/.aws", maxDepth: 3, maxEntries: 100)
        XCTAssertEqual(found.map { ($0.link as NSString).lastPathComponent }, ["outside"], "the inside link is not a new prefix")
    }
}
