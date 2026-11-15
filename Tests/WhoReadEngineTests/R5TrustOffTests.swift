import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// ipc-3: turning "trust Apple programs" off is open to the console user, also when it is off already
/// (an idempotent hardening script runs `whoread settings set trust-apple off` every time).
final class R5TrustOffTests: XCTestCase {
    private let user = IPCPeer(pid: 4242, euid: 501, isTrustedCode: false)

    private func handler(_ core: DaemonCore) -> ServiceHandler {
        let h = ServiceHandler(daemon: core, policy: .strict)
        h.consoleUID = { 501 }
        return h
    }

    func testTrustOffWhenItIsAlreadyOffIsNotAWeakening() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let h = handler(core)
        var s = core.currentSettings
        XCTAssertFalse(s.trustApplePrograms, "the default")
        s.trustApplePrograms = false
        XCTAssertEqual(h.privilege(of: .updateSettings(s)), .strengthen)
        for attempt in 1...2 {
            guard case .settings(let after) = h.handle(.updateSettings(s), peer: user) else {
                return XCTFail("attempt \(attempt) was refused: \(h.handle(.updateSettings(s), peer: user))")
            }
            XCTAssertFalse(after.trustApplePrograms)
            XCTAssertEqual(after, core.currentSettings)
        }
    }

    func testOnlyTurningTrustOffIsOpenToTheConsoleUser() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let h = handler(core)
        var on = core.currentSettings
        on.trustApplePrograms = true
        XCTAssertEqual(h.privilege(of: .updateSettings(on)), .weaken, "turning it on weakens protection")
        var offAndMore = core.currentSettings
        offAndMore.retentionDays = 5
        XCTAssertEqual(h.privilege(of: .updateSettings(offAndMore)), .weaken, "trust off together with another change")
        // Turned on by root, then off by the console user.
        try core.mutateSettings(peer: .inProcess) { $0.trustApplePrograms = true }
        var off = core.currentSettings
        off.trustApplePrograms = false
        guard case .settings(let after) = h.handle(.updateSettings(off), peer: user) else { return XCTFail("refused") }
        XCTAssertFalse(after.trustApplePrograms)
    }
}
