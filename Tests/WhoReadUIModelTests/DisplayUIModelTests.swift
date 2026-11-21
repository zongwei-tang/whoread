import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadUIModel

/// guard-4: question banners, the menu, the Alerts tab and the app's tables showed names and paths
/// as the programs and files gave them. Everything shown now goes through `DisplayText`.
final class DisplayUIModelTests: XCTestCase {
    static let t = Date(timeIntervalSince1970: 1_790_000_000)
    /// A bundle named to read like a harmless request, with line breaks and a right-to-left override
    /// that push the real request out of a collapsed banner (U+2215 looks like "/").
    static let lure = "Terminal wants to read ~∕notes\n\n\n\n\u{202E}x"
    static let bundle = "/Users/alice/Projects/x/\(lure).app"
    static let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

    func model(language: Language = .en) -> AppModel {
        let m = AppModel(language: language)
        var s = Snapshot()
        s.status = DaemonStatus(version: "test", pid: 1, startedAt: DisplayUIModelTests.t, mode: .enforcing, source: .native,
                                sourceRunning: true, sourceError: nil, sourceHint: nil, sourceCanEnforce: true, learning: false,
                                learningEndsAt: DisplayUIModelTests.t, monitoringPaused: false, enforcementEnabled: true,
                                enforcementActive: true, enforcementInactiveReasons: [], latencyTripReason: nil,
                                killSwitchFilePresent: false, latency: LatencyStats(), parser: nil,
                                counts: StoreCounts(events: 0, aggregatedDays: 0, alerts: 0, unreadAlerts: 0),
                                unreadAlerts: 0, lastEventAt: nil, eventsProcessed: 0, writerDropped: 0, monitoredPrefixes: 1,
                                homeDirectories: ["/Users/alice"], uncleanStop: nil)
        m.apply(s)
        return m
    }

    var lookalike: ResponsibleEntity {
        ResponsibleEntity(kind: .app, key: "app:" + PathNormalizer.fold(DisplayUIModelTests.bundle), displayName: DisplayUIModelTests.lure,
                          path: DisplayUIModelTests.bundle)
    }

    var chain: [ChainLink] {
        [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd", isPlatformBinary: true),
         ChainLink(pid: 50, name: "claude", path: "/opt/homebrew/bin/claude", agentID: "claude-code", argv: ["claude"]),
         ChainLink(pid: 60, name: "r\r\u{1B}[2K", path: DisplayUIModelTests.bundle + "/Contents/MacOS/r",
                   argv: ["r", "--x", "a\u{1B}]0;evil\u{07}b"])]
    }

    var question: AskRequest {
        AskRequest(id: 7, key: AskKey(responsibleKey: lookalike.key, categoryID: "test-vault", access: .read, chainAgents: ["claude-code"]),
                   responsible: lookalike, severity: .critical, path: DisplayUIModelTests.key,
                   process: ProcessRecord(pid: 60, ppid: 50, executablePath: DisplayUIModelTests.bundle + "/Contents/MacOS/r"),
                   chain: chain, agentID: "claude-code", appleProgram: false, firstAt: DisplayUIModelTests.t,
                   lastAt: DisplayUIModelTests.t, attempts: 1, holding: 1, answerBy: DisplayUIModelTests.t + 5)
    }

    func assertShowable(_ text: String, allowingLineBreaks: Bool = false, file: StaticString = #filePath, line: UInt = #line) {
        let bad = text.unicodeScalars.filter { DisplayText.isHidden($0) && !(allowingLineBreaks && $0 == "\n") }
        XCTAssertTrue(bad.isEmpty, "hidden characters \(bad.map(\.value)) in \(text)", file: file, line: line)
    }

    func testQuestionBannerPutsTheAgentFirstAndShowsTheRealProgram() throws {
        for language in [Language.en, .zhHans] {
            let m = model(language: language)
            let plan = NotificationPlanner().plan(asks: [question], formatter: m.formatter, agentName: { _ in "Claude Code" })
            let body = try XCTUnwrap(plan.post.first?.body)
            assertShowable(body, allowingLineBreaks: true)
            let lines = body.components(separatedBy: "\n")
            XCTAssertEqual(lines.count, 5, body)
            XCTAssertEqual(lines[0], language == .en ? "AI agent in the chain: Claude Code" : "调用链中有 AI agent：Claude Code")
            XCTAssertTrue(lines[1].contains("~/WhoReadTestVault/ssh/id_ed25519"), lines[1])
            XCTAssertTrue(lines[1].hasPrefix("Terminal wants to read ~∕notes\\u{a}\\u{a}\\u{a}\\u{a}\\u{202e}x"), lines[1])
            XCTAssertTrue(lines[2].contains("~/Projects/x/Terminal wants to read"), "where the program really is: \(lines[2])")
            XCTAssertTrue(lines[2].hasSuffix(language == .en ? "(not signed by an identified developer)" : "（没有已识别开发者的签名）"), lines[2])
            // What allowing covers names the app with its escaped name too.
            XCTAssertTrue(lines[3].contains("Terminal wants to read ~∕notes\\u{a}"), lines[3])
            XCTAssertTrue(lines[4].hasSuffix("r\\u{d}\\u{1b}[2K"), lines[4])
        }
    }

    func testAlertBannerShowsTheRealProgramToo() throws {
        let m = model()
        let alert = Alert(id: 3, kind: .criticalNonOwner, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date() + 600,
                          responsible: lookalike, categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                          firstPath: DisplayUIModelTests.key, firstEventID: 1, lastEventID: 1, paths: [DisplayUIModelTests.key],
                          chain: chain, agentID: "claude-code", ruleID: nil)
        let planned = NotificationPlanner(launchedAt: .distantPast).plan([alert], settings: NotificationSettings(), formatter: m.formatter)
        let body = try XCTUnwrap(planned.first?.body)
        assertShowable(body, allowingLineBreaks: true)
        let lines = body.components(separatedBy: "\n")
        XCTAssertEqual(lines.count, 4, body)
        XCTAssertTrue(lines[1].hasPrefix("Program: ~/Projects/x/"), lines[1])
        XCTAssertTrue(lines[2].hasPrefix("Always allow covers: Terminal wants to read"), lines[2])
        XCTAssertEqual(m.identityLine(alert), lines[1])
    }

    func testTablesMenuAndDetailsShowEscapedText() throws {
        let m = model()
        var s = Snapshot()
        s.summaries = [UsageSummary(responsible: lookalike, categoryID: "test-vault", agentID: nil, firstSeen: DisplayUIModelTests.t,
                                    lastSeen: DisplayUIModelTests.t, count: 1, reads: 1, writes: 0, denied: 0, benign: false)]
        m.apply(s)
        let row = try XCTUnwrap(m.appRows.first)
        XCTAssertEqual(row.id, lookalike.key, "identifiers stay exact (rules are made from them)")
        assertShowable(row.name)
        XCTAssertTrue(row.name.hasPrefix("Terminal wants to read"))
        assertShowable(m.displayName(lookalike))
        assertShowable(m.abbreviate("/Users/alice/x\u{202E}y\n"))
        XCTAssertEqual(m.abbreviate("/Users/alice/x\u{202E}y\n"), "~/x\\u{202e}y\\u{a}")
        assertShowable(m.display("a\u{1B}[8mb"))

        let text = m.chainText(chain, responsible: lookalike)
        assertShowable(text)
        XCTAssertTrue(text.hasPrefix("Terminal wants to read"), text)
        let detail = m.chainDetail(chain)
        assertShowable(detail, allowingLineBreaks: true)
        XCTAssertEqual(detail.components(separatedBy: "\n").count, 3, "one line per process: \(detail)")
        XCTAssertTrue(detail.hasSuffix("→ r\\u{d}\\u{1b}[2K --x a\\u{1b}]0;evil\\u{7}b"), detail)

        // A "Block <app> from <category>" rule made from an alert keeps the app's own name.
        let rule = Rule(name: "Block \(DisplayUIModelTests.lure) from SSH keys", target: .category("ssh"),
                        subject: .responsible(key: lookalike.key, teamID: nil, cdhash: nil, exceptOwners: false), action: .deny)
        assertShowable(m.ruleName(rule))
        assertShowable(m.ruleName(Rule(name: "x\u{2028}y", target: .category("ssh"), subject: .anyNonOwner, action: .deny)))
        assertShowable(L10n.message(for: IPCError(.invalid, "no rule \u{1B}[8m"), .en))
        assertShowable(try XCTUnwrap(question.agentsLine(.en, agentName: { _ in "Agent\u{202E}" })))
    }
}
