import XCTest
@testable import WhoReadCore

/// daemon-8: an alert's headline says what was done to the file it names. When an escalation moves
/// it to another file, the window's other accesses are said apart; the answer still covers all of
/// them (the "always allow" title names them). A rule's alert keeps naming an access its rule matched.
final class R5AlertHeadlineTests: XCTestCase {
    private let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"
    private let knownHosts = "/Users/alice/WhoReadTestVault/ssh/known_hosts"
    private let note = "/Users/alice/WhoReadTestVault/notes/todo.txt"

    private func formatter(_ language: Language) -> AlertFormatter {
        AlertFormatter(language: language, categoryName: { $0 == "test-vault" ? LocalizedText(en: "WhoRead test vault", zhHans: "WhoRead 测试保险库") : nil })
    }

    private func event(_ id: Int64, _ t: TimeInterval, _ path: String, _ access: AccessSet, _ severity: Severity,
                       decision: EventDecision = .observed, ruleID: String? = nil) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: at(t), operation: .open, access: access, path: path, secondaryPath: nil, categoryID: "test-vault",
                      severity: severity, process: proc(300, "/Applications/zoom.us.app/Contents/MacOS/zoom.us"), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "zoom.us"),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: decision, ruleID: ruleID, chainAgents: [],
                      ancestryKnown: true)
    }

    func testAnEscalationToAnotherFileNamesWhatWasDoneToIt() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, knownHosts, .read, .medium), kind: .firstAccess, firstTime: true)
        let up = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical), kind: .criticalNonOwner, firstTime: true))
        XCTAssertEqual(up.change, .escalated)
        XCTAssertEqual(up.alert.firstPath, key)
        XCTAssertEqual(up.alert.accesses, .readWrite, "the answer covers the window's accesses")
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "zoom.us wrote \(key) for the first time (WhoRead test vault, not an expected owner); "
                       + "also read files in WhoRead test vault (×2)")
        XCTAssertEqual(formatter(.zhHans).headline(up.alert),
                       "zoom.us 第一次写入了 \(key)（WhoRead 测试保险库，不是预期的访问者）；还读取了 WhoRead 测试保险库 中的文件（2 次）")
        // Merged repeats of that file keep it so.
        let merged = try XCTUnwrap(c.ingest(event(3, 120, key, .write, .critical), kind: nil))
        XCTAssertEqual(merged.change, .merged)
        XCTAssertTrue(formatter(.en).headline(merged.alert).hasPrefix("zoom.us wrote \(key) for the first time"))
    }

    func testAccessesOfTheSameFileAreNamedTogether() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, key, .read, .critical), kind: .criticalNonOwner, firstTime: true)
        let up = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical), kind: .criticalNonOwner, firstTime: true))
        XCTAssertEqual(up.change, .escalated, "a new kind of access")
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "zoom.us read and modified \(key) for the first time (WhoRead test vault, not an expected owner) (×2)")
        // A quiet (known) write of the file it names, then a read of another one.
        let d = AlertCoalescer(window: 600)
        _ = d.ingest(event(1, 0, key, .read, .critical), kind: .criticalNonOwner)
        _ = d.ingest(event(2, 30, key, .write, .critical), kind: nil)
        let other = try XCTUnwrap(d.ingest(event(3, 60, knownHosts, .read, .medium), kind: nil))
        XCTAssertEqual(formatter(.en).headline(other.alert),
                       "zoom.us read and modified \(key) (WhoRead test vault, not an expected owner) (×3)")
    }

    func testAWouldBlockAlertKeepsNamingWhatItsRuleMatched() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, key, .read, .critical, decision: .wouldDeny, ruleID: "deny-vault-reads"), kind: .wouldBlock)
        // A first write of another file of the category, which no rule matches.
        let up = try XCTUnwrap(c.ingest(event(2, 60, note, .write, .medium), kind: .firstAccess, firstTime: true))
        XCTAssertEqual(up.change, .escalated, "a new kind of access is news")
        XCTAssertEqual(up.alert.status, .unread)
        XCTAssertEqual(up.alert.kind, .wouldBlock)
        XCTAssertEqual(up.alert.ruleID, "deny-vault-reads")
        XCTAssertEqual(up.alert.firstPath, key, "the access the rule would block")
        XCTAssertEqual(up.alert.firstEventID, 2, "an escalation always moves it (clients notify again on it)")
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "A rule would block zoom.us from reading \(key) (monitor mode); zoom.us also wrote files in WhoRead test vault (×2)")
        XCTAssertEqual(formatter(.zhHans).headline(up.alert),
                       "规则将会拦截：zoom.us 读取 \(key)（当前为监控模式）；zoom.us 还写入了 WhoRead 测试保险库 中的文件（2 次）")
    }

    /// The same file, written by an access no rule matched: the rule's alert still names the read only.
    func testARuleAlertsVerbIsWhatItsRuleMatchedOnItsOwnFileToo() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, key, .read, .critical, decision: .wouldDeny, ruleID: "deny-vault-reads"), kind: .wouldBlock)
        let up = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical), kind: .criticalNonOwner))
        XCTAssertEqual(up.change, .escalated)
        XCTAssertEqual(up.alert.firstPathAccess, .read)
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "A rule would block zoom.us from reading \(key) (monitor mode); zoom.us also wrote files in WhoRead test vault (×2)")
        // A known (quiet) write of it neither.
        let d = AlertCoalescer(window: 600)
        _ = d.ingest(event(1, 0, key, .read, .critical, decision: .wouldDeny, ruleID: "deny-vault-reads"), kind: .wouldBlock)
        let quiet = try XCTUnwrap(d.ingest(event(2, 60, key, .write, .critical), kind: nil))
        XCTAssertEqual(quiet.change, .merged)
        XCTAssertEqual(quiet.alert.firstPathAccess, .read)
    }

    /// Raised to a rule's alert on the same file: what the rule matched, not what was seen of it before.
    func testAnAlertRaisedToARulesAlertNamesWhatTheRuleMatched() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, key, .read, .critical), kind: .criticalNonOwner)
        let up = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical, decision: .wouldDeny, ruleID: "deny-vault-writes"),
                                        kind: .wouldBlock))
        XCTAssertEqual(up.alert.kind, .wouldBlock)
        XCTAssertEqual(up.alert.ruleID, "deny-vault-writes")
        XCTAssertEqual(up.alert.firstPathAccess, .write)
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "A rule would block zoom.us from writing \(key) (monitor mode); zoom.us also read files in WhoRead test vault (×2)")
    }

    func testAnotherRulesAccessMovesTheAlertWithItsRule() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, key, .read, .critical, decision: .wouldDeny, ruleID: "deny-vault-reads"), kind: .wouldBlock)
        let up = try XCTUnwrap(c.ingest(event(2, 60, note, .write, .medium, decision: .wouldDeny, ruleID: "deny-note-writes"), kind: .wouldBlock))
        XCTAssertEqual(up.change, .escalated)
        XCTAssertEqual(up.alert.firstPath, note)
        XCTAssertEqual(up.alert.ruleID, "deny-note-writes", "the rule of the access it names")
        XCTAssertEqual(formatter(.en).headline(up.alert),
                       "A rule would block zoom.us from writing \(note) (monitor mode); zoom.us also read files in WhoRead test vault (×2)")
    }

    /// Blocked attempts and questions say "tried to" and "wants to" for the other files too.
    func testTheOtherAccessesReadAsTheAlertsKind() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, knownHosts, .read, .medium, decision: .denied, ruleID: "deny-vault"), kind: .blocked)
        let blocked = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical, decision: .denied, ruleID: "deny-vault"), kind: .blocked))
        XCTAssertEqual(formatter(.en).headline(blocked.alert),
                       "Blocked: zoom.us tried to write \(key); also tried to read files in WhoRead test vault (×2)")
        XCTAssertEqual(formatter(.zhHans).headline(blocked.alert),
                       "已拦截：zoom.us 试图写入 \(key)；还试图读取 WhoRead 测试保险库 中的文件（2 次）")
        let q = AlertCoalescer(window: 600)
        _ = q.ingest(event(1, 0, knownHosts, .read, .medium, decision: .denied), kind: .ask)
        let ask = try XCTUnwrap(q.ingest(event(2, 60, key, .write, .critical, decision: .denied), kind: .ask))
        XCTAssertEqual(formatter(.en).headline(ask.alert),
                       "zoom.us wants to write \(key): not allowed until you decide; also wants to read files in WhoRead test vault (×2)")
        XCTAssertEqual(formatter(.zhHans).headline(ask.alert),
                       "zoom.us 想要写入 \(key)，你决定之前不会放行；还想要读取 WhoRead 测试保险库 中的文件（2 次）")
    }

    /// Alerts stored before the field existed read as before.
    func testAnOlderAlertReadsAsBefore() throws {
        let c = AlertCoalescer(window: 600)
        _ = c.ingest(event(1, 0, knownHosts, .read, .medium), kind: .firstAccess, firstTime: true)
        let up = try XCTUnwrap(c.ingest(event(2, 60, key, .write, .critical), kind: .criticalNonOwner, firstTime: true))
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONEncoder().encode(up.alert)) as? [String: Any])
        object.removeValue(forKey: "firstPathAccess")
        let old = try JSONDecoder().decode(Alert.self, from: try JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(formatter(.en).headline(old),
                       "zoom.us read and modified \(key) for the first time (WhoRead test vault, not an expected owner) (×2)")
    }
}
