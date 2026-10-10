import XCTest
import WhoReadCore
@testable import WhoReadUIModel

/// A question about a chain whose ancestry is unknown says so in its notification.
final class UnknownAncestryQuestionTests: XCTestCase {
    func testTheNotificationSaysWhoStartedItIsUnknown() {
        let key = AskKey(responsibleKey: "bin:apple:com.apple.cat", categoryID: "ssh", access: .read, chainAgents: [], ancestryKnown: false)
        let t = Date(timeIntervalSince1970: 1_790_000_000)
        let ask = AskRequest(id: 1, key: key, responsible: ResponsibleEntity(kind: .binary, key: key.responsibleKey, displayName: "cat"),
                             severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                             process: ProcessRecord(pid: 42, ppid: 1, executablePath: "/bin/cat"),
                             chain: [ChainLink(pid: 42, name: "cat", path: "/bin/cat", isPlatformBinary: true)],
                             agentID: nil, appleProgram: false, firstAt: t, lastAt: t)
        XCTAssertEqual(ask.asAlert.ancestryKnown, false)
        let plan = NotificationPlanner().plan(asks: [ask], formatter: AlertFormatter(language: .en))
        XCTAssertEqual(plan.post.first?.body.components(separatedBy: "\n").first,
                       "cat wants to read /Users/alice/.ssh/id_ed25519: not allowed until you decide (started by an unknown process, possibly an AI agent)")
    }
}
