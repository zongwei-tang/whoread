import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// cli-1 (daemon side): a project root the classifier cannot monitor (relative, `~code`, with `.` or
/// `..` in it) or one that would make a whole disk, home or folder of homes "project secrets" is
/// refused, for the CLI and the app alike, instead of being stored and silently monitoring nothing.
/// Roots stored before are never what blocks a change (enforcement and pause go through the same
/// settings update), and can still be removed.
final class R5ProjectRootTests: XCTestCase {
    private let refused = [".", "code", "~code", "./code", "/", "~", "~/", "~/..", "/Users", "/Users/", "~/code/../other",
                           "~/./code", "/Users/alice/src/./app", "/Users/alice/src/..", "~/co\u{0}de"]

    func testRootsThatWouldMonitorNothingOrEverythingAreRefused() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        for root in refused {
            XCTAssertThrowsError(try core.mutateSettings(peer: .inProcess) { $0.projectRoots.append(root) }, root.debugDescription) { e in
                XCTAssertEqual((e as? IPCError)?.code, .invalid, "\(root.debugDescription): \(e)")
            }
            XCTAssertEqual(core.currentSettings.projectRoots, [], "nothing applied for \(root.debugDescription)")
            XCTAssertEqual(try core.store.settings().projectRoots, [], "nothing saved for \(root.debugDescription)")
        }
        try core.mutateSettings(peer: .inProcess) { $0.projectRoots = ["~/code", "/Users/alice/src/", " ~/work "] }
        XCTAssertEqual(core.currentSettings.projectRoots, ["/Users/alice/src/", "~/code", "~/work"])
        let monitored = core.analyzer.classifier.classify(normalized: "/Users/alice/code/app/.env")
        XCTAssertEqual(monitored?.categoryID, "project-secrets")
    }

    func testTheRequestFromAClientIsRefusedAsInvalid() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let handler = ServiceHandler(daemon: core, policy: .strict)
        var s = core.currentSettings
        s.projectRoots = ["."]
        let root = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)
        guard case .error(let e) = handler.handle(.updateSettings(s), peer: root) else { return XCTFail("accepted") }
        XCTAssertEqual(e.code, .invalid)
        XCTAssertTrue(e.message.contains("project root"), e.message)
    }

    func testAStoredRootThatIsRefusedNowBlocksNothingAndCanBeRemoved() throws {
        let dir = TempDir()
        do {
            let core = try r5Core(dir)
            try core.store.saveSettings(Settings(projectRoots: [".", "~/code"]))
        }
        let core = try r5Core(dir)
        XCTAssertEqual(core.currentSettings.projectRoots, [".", "~/code"])
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        try core.mutateSettings(peer: .inProcess) { $0.monitoringPaused = true }
        try core.mutateSettings(peer: .inProcess) { $0.retentionDays = 60 }
        XCTAssertEqual(core.currentSettings.projectRoots, [".", "~/code"])
        try core.mutateSettings(peer: .inProcess) { $0.projectRoots.removeAll { $0 == "." } }
        XCTAssertEqual(core.currentSettings.projectRoots, ["~/code"])
        XCTAssertEqual(try core.store.settings().projectRoots, ["~/code"])
    }
}
