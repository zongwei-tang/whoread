import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadUIModel

/// What allowing covers, as said before the answer, must be what the daemon saves.
/// - cli-8: an answer given for a chain whose starter is unknown also covers such chains
///   (`Rule.coversUnknownAncestry`), where an AI agent would not be seen.
/// - app-10: an alert's answer is scoped to the AI agents of the whole chain (`Alert.scopeAgents`),
///   not those of the 64 links it stores.
final class R5CoverageLineTests: XCTestCase {
    private static let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app",
                                                    displayName: "Terminal", path: "/System/Applications/Utilities/Terminal.app")
    private static let foo = ResponsibleEntity(kind: .app, key: "app:/applications/foo.app", displayName: "Foo", path: "/Applications/Foo.app")
    private let agentName: (String) -> String = { $0 == "claude-code" ? "Claude Code" : $0 }

    private func formatter(_ language: Language) -> AlertFormatter {
        AlertFormatter(language: language, categoryName: { $0 == "test-vault" ? LocalizedText(en: "WhoRead test vault", zhHans: "WhoRead 测试保险库") : nil })
    }

    private func question(ancestryKnown: Bool, agents: [String] = []) -> AskRequest {
        AskRequest(id: 1, key: AskKey(responsibleKey: Self.terminal.key, categoryID: "test-vault", access: .read, chainAgents: agents,
                                      ancestryKnown: ancestryKnown),
                   responsible: Self.terminal, severity: .critical, path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519",
                   process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/usr/bin/ssh"), chain: [], agentID: nil,
                   appleProgram: false, firstAt: Date(), lastAt: Date())
    }

    // cli-8
    func testAQuestionWithAnUnknownStarterSaysTheAnswerCoversSuchChains() {
        let q = question(ancestryKnown: false)
        XCTAssertEqual(q.allowCoverageLine(formatter(.en)),
                       "Allow once (10 min) and Always allow cover: Terminal (any program run in it) reading WhoRead test vault, "
                       + "only when no AI agent is seen in the chain, including chains whose starter is unknown "
                       + "(an AI agent there would not be seen).")
        XCTAssertEqual(q.allowCoverageLine(formatter(.zhHans)),
                       "「允许一次（10 分钟）」和「始终允许」适用于：Terminal（及在其中运行的任何程序）读取 WhoRead 测试保险库，"
                       + "仅限调用链中没有看到 AI agent 时，包括不知道是谁启动的调用链（那里的 AI agent 看不到）。")
        let withAgent = question(ancestryKnown: false, agents: ["claude-code"])
        XCTAssertEqual(withAgent.allowCoverageLine(formatter(.en), agentName: agentName),
                       "Allow once (10 min) and Always allow cover: Terminal (any program run in it) reading WhoRead test vault, "
                       + "only when no AI agent other than Claude Code is seen in the chain, including chains whose starter is "
                       + "unknown (another AI agent there would not be seen).")
        XCTAssertEqual(withAgent.allowCoverageLine(formatter(.zhHans), agentName: agentName),
                       "「允许一次（10 分钟）」和「始终允许」适用于：Terminal（及在其中运行的任何程序）读取 WhoRead 测试保险库，"
                       + "仅限调用链中除 Claude Code 外没有看到其他 AI agent 时，包括不知道是谁启动的调用链（那里的其他 AI agent 看不到）。")
        // A known chain reads as before.
        XCTAssertEqual(question(ancestryKnown: true).allowCoverageLine(formatter(.en)),
                       "Allow once (10 min) and Always allow cover: Terminal (any program run in it) reading WhoRead test vault, "
                       + "only when the chain has no AI agent.")
    }

    /// Terminal → zsh → claude → 70 nested zsh → Foo.app, reading the key: the stored chain keeps the 64
    /// nearest links, none of them the agent, whose ancestry is cut there (unknown).
    private func deepAlert(ancestryKnown: Bool) -> Alert {
        var chain: [ChainLink] = (0..<63).map { i -> ChainLink in
            ChainLink(pid: Int32(1000 + i), name: "zsh", path: "/bin/zsh", isPlatformBinary: true)
        }
        chain.append(ChainLink(pid: 1063, name: "Foo", path: "/Applications/Foo.app/Contents/MacOS/Foo"))
        return Alert(id: 9, kind: .criticalNonOwner, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date().addingTimeInterval(600),
                     responsible: Self.foo, categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                     firstPath: "/Users/alice/WhoReadTestVault/ssh/id_ed25519", firstEventID: 1, lastEventID: 1,
                     paths: ["/Users/alice/WhoReadTestVault/ssh/id_ed25519"], chain: chain, agentID: "claude-code", ruleID: nil,
                     chainAgents: ["claude-code"], ancestryKnown: ancestryKnown)
    }

    // app-10, and cli-8 for alerts.
    func testAnAlertNamesTheAgentsOfTheWholeChain() throws {
        let alert = deepAlert(ancestryKnown: false)
        XCTAssertTrue(alert.chain.allSatisfy { $0.agentID == nil })
        XCTAssertEqual(try XCTUnwrap(alert.allowCoverageLine(formatter(.en), agentName: agentName)),
                       "Always allow covers: Foo (any program run in it) reading WhoRead test vault, only when no AI agent other "
                       + "than Claude Code is seen in the chain, including chains whose starter is unknown (another AI agent there "
                       + "would not be seen).")
        XCTAssertEqual(try XCTUnwrap(alert.allowCoverageLine(formatter(.zhHans), agentName: agentName)),
                       "「始终允许」适用于：Foo（及在其中运行的任何程序）读取 WhoRead 测试保险库，仅限调用链中除 Claude Code 外没有看到其他 "
                       + "AI agent 时，包括不知道是谁启动的调用链（那里的其他 AI agent 看不到）。")
        XCTAssertEqual(try XCTUnwrap(deepAlert(ancestryKnown: true).allowCoverageLine(formatter(.en), agentName: agentName)),
                       "Always allow covers: Foo (any program run in it) reading WhoRead test vault, only when the chain has no AI agent "
                       + "other than Claude Code.")
    }
}
