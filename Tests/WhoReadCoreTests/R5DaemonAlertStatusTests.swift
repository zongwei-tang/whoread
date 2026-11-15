import XCTest
@testable import WhoReadCore

/// daemon-3 (core): a status change applies to the copy the user acted on, compare-and-set against the
/// coalescer's open copy. Every escalation, also one that keeps what the headline names, blocks it.
final class R5DaemonAlertStatusTests: XCTestCase {
    private let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"
    private let knownHosts = "/Users/alice/WhoReadTestVault/ssh/known_hosts"
    private let note = "/Users/alice/WhoReadTestVault/notes/todo.txt"

    private func event(_ id: Int64, _ t: TimeInterval, _ path: String, _ access: AccessSet, _ severity: Severity,
                       decision: EventDecision = .observed, ruleID: String? = nil) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: at(t), operation: .open, access: access, path: path, secondaryPath: nil, categoryID: "test-vault",
                      severity: severity, process: proc(300, "/Applications/zoom.us.app/Contents/MacOS/zoom.us"), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "zoom.us"),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: decision, ruleID: ruleID, chainAgents: [],
                      ancestryKnown: true)
    }

    func testAChangeAppliesToTheOpenCopyAcrossMergedRepeats() throws {
        let c = AlertCoalescer(window: 600)
        let seen = try XCTUnwrap(c.ingest(event(1, 0, knownHosts, .read, .medium), kind: .firstAccess)).alert
        _ = c.ingest(event(2, 30, knownHosts, .read, .medium), kind: nil)
        let changes = c.setStatus(of: [seen], to: .resolved, resolution: .ignore)
        guard case .changed(let a) = try XCTUnwrap(changes.first) else { return XCTFail("\(changes)") }
        XCTAssertEqual(a.status, .resolved)
        XCTAssertEqual(a.resolution, .ignore)
        XCTAssertEqual(a.count, 2, "the open copy, with the repeat merged meanwhile")
        XCTAssertEqual(c.ingest(event(3, 60, knownHosts, .read, .medium), kind: nil)?.alert.status, .resolved)
    }

    func testAnEscalationSinceTheCopyActedOnStaysUnread() throws {
        let c = AlertCoalescer(window: 600)
        let seen = try XCTUnwrap(c.ingest(event(1, 0, knownHosts, .read, .medium), kind: .firstAccess)).alert
        _ = c.ingest(event(2, 30, key, .write, .critical), kind: .criticalNonOwner)
        let changes = c.setStatus(of: [seen], to: .resolved, resolution: .alwaysAllow)
        guard case .escalated(let a) = try XCTUnwrap(changes.first) else { return XCTFail("\(changes)") }
        XCTAssertEqual(a.status, .unread)
        XCTAssertEqual(c.ingest(event(3, 60, key, .write, .critical), kind: nil)?.alert.status, .unread)
    }

    /// An escalation that keeps naming the same file (a rule's would-block, then a write no rule matched)
    /// still moves firstEventID, so it blocks the change too.
    func testAnEscalationThatKeepsTheHeadlinesFileBlocksTheChangeToo() throws {
        let c = AlertCoalescer(window: 600)
        let seen = try XCTUnwrap(c.ingest(event(1, 0, key, .read, .critical, decision: .wouldDeny, ruleID: "deny-vault-reads"),
                                          kind: .wouldBlock)).alert
        let up = try XCTUnwrap(c.ingest(event(2, 30, note, .write, .medium), kind: .firstAccess))
        XCTAssertEqual(up.alert.firstPath, seen.firstPath)
        XCTAssertEqual(up.alert.kind, seen.kind)
        let changes = c.setStatus(of: [seen], to: .read, resolution: nil)
        guard case .escalated = try XCTUnwrap(changes.first) else { return XCTFail("\(changes)") }
    }

    func testAnAlertWhoseWindowClosedIsNotOpenHere() throws {
        let c = AlertCoalescer(window: 600)
        let seen = try XCTUnwrap(c.ingest(event(1, 0, knownHosts, .read, .medium), kind: .firstAccess)).alert
        c.expire(now: at(601))
        XCTAssertEqual(c.setStatus(of: [seen], to: .read, resolution: nil), [.notOpen])
        XCTAssertEqual(c.setStatus(of: [], to: .read, resolution: nil), [])
    }
}
