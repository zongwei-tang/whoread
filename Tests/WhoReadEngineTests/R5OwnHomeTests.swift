import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// ipc-2: without sudo or the app, a path rule may extend monitoring only to the peer's own files: its
/// own home and the external volumes folder, not another user's home on the same Mac.
final class R5OwnHomeTests: XCTestCase {
    private let alice = IPCPeer(pid: 4242, euid: 501, isTrustedCode: true)
    private let root = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)

    private func denyRule(_ id: String, _ prefix: String) -> Rule {
        Rule(id: id, enabled: true, enforce: true, target: .pathPrefix(prefix), subject: .anyNonOwner, access: .any, action: .deny,
             includePlatformBinaries: true)
    }

    private func customPaths(_ core: DaemonCore) -> [String] {
        core.data.catalog.categories.first { $0.kind == .custom }?.paths ?? []
    }

    func testAConsoleUserCannotExtendMonitoringIntoAnotherUsersHome() throws {
        let dir = TempDir()
        let core = try r5Core(dir) { $0.homeDirectories = ["/Users/alice", "/Users/bob"] }
        let rule = denyRule("deny-bob-documents", "/Users/bob/Documents")
        XCTAssertThrowsError(try core.upsert(rule: rule, peer: alice, mustBeNew: true, privileged: false)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .notPermitted, "\(e)")
        }
        XCTAssertFalse(customPaths(core).contains("/Users/bob/Documents"))
        XCTAssertFalse(core.rules.rules.contains { $0.id == rule.id })
        XCTAssertThrowsError(try core.replaceRules([rule], peer: alice, privileged: false)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .notPermitted, "\(e)")
        }
        // Root may.
        XCTAssertNoThrow(try core.upsert(rule: rule, peer: root, privileged: true))
        XCTAssertTrue(customPaths(core).contains("/Users/bob/Documents"))
    }

    /// Two users; the console user is alice (uid 501), whose home the user database gives.
    private func twoUsers(_ dir: TempDir) throws -> DaemonCore {
        try r5Core(dir) { c in
            c.homeDirectories = ["/Users/alice", "/Users/bob"]
            c.homeOf = { $0 == 501 ? "/Users/alice" : ($0 == 502 ? "/Users/bob" : nil) }
        }
    }

    func testAConsoleUserMayExtendMonitoringToItsOwnFiles() throws {
        let dir = TempDir()
        let core = try twoUsers(dir)
        try core.upsert(rule: denyRule("deny-alice-taxes", "/Users/alice/Documents/Taxes"), peer: alice, mustBeNew: true, privileged: false)
        XCTAssertTrue(customPaths(core).contains("/Users/alice/Documents/Taxes"))
        // External volumes too (monitored by the volumes category already).
        try core.upsert(rule: denyRule("deny-usb", "/Volumes/USB/backup"), peer: alice, mustBeNew: true, privileged: false)
        XCTAssertTrue(core.rules.rules.contains { $0.id == "deny-usb" })
        // bob, as the console user, gets his own home and not alice's.
        let bob = IPCPeer(pid: 4243, euid: 502, isTrustedCode: true)
        XCTAssertNoThrow(try core.upsert(rule: denyRule("deny-bob-notes", "/Users/bob/Notes"), peer: bob, mustBeNew: true, privileged: false))
        XCTAssertThrowsError(try core.upsert(rule: denyRule("deny-alice-notes", "/Users/alice/Notes"), peer: bob, mustBeNew: true,
                                             privileged: false))
    }

    /// `~/…` stands for every monitored home: on a Mac with two users it names the other one's too.
    func testAHomeRelativeRuleNeedsSudoWhereItReachesAnotherHome() throws {
        let dir = TempDir()
        let core = try twoUsers(dir)
        XCTAssertThrowsError(try core.upsert(rule: denyRule("deny-taxes", "~/Documents/Taxes"), peer: alice, mustBeNew: true, privileged: false)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .notPermitted, "\(e)")
        }
        let single = TempDir()
        let mine = try r5Core(single) { c in
            c.homeDirectories = ["/Users/alice"]
            c.homeOf = { $0 == 501 ? "/Users/alice" : nil }
        }
        XCTAssertNoThrow(try mine.upsert(rule: denyRule("deny-taxes", "~/Documents/Taxes"), peer: alice, mustBeNew: true, privileged: false))
    }

    func testAPeerWithoutAKnownHomeExtendsNothing() throws {
        let dir = TempDir()
        let core = try twoUsers(dir)
        let unknown = IPCPeer(pid: 4244, euid: nil, isTrustedCode: true)
        XCTAssertThrowsError(try core.upsert(rule: denyRule("a", "/Users/alice/Documents/x"), peer: unknown, mustBeNew: true, privileged: false))
        let homeless = IPCPeer(pid: 4245, euid: 777, isTrustedCode: true)
        XCTAssertThrowsError(try core.upsert(rule: denyRule("b", "/Users/alice/Documents/x"), peer: homeless, mustBeNew: true, privileged: false))
        XCTAssertFalse(customPaths(core).contains("/Users/alice/Documents/x"))
    }

    func testTheUserDatabaseGivesTheHomeOfThisUser() {
        let home = DaemonConfiguration.userDatabaseHome(getuid())
        XCTAssertNotNil(home)
        XCTAssertTrue(home?.hasPrefix("/") == true)
        XCTAssertNil(DaemonConfiguration.userDatabaseHome(uid_t(0x7fff_fff0)), "no such user")
    }
}
