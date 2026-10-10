import XCTest
@testable import WhoReadCore

// Ask mode, core side (docs/ASK_MODE.md): the rule engine's decision table, agent-chain scoping,
// chain-scoped rules, cacheability, ask alerts and monitor-only alerts without a learning period.

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let awsCredentials = "/Users/alice/.aws/credentials"
private let history = "/Users/alice/.zsh_history"
private let terminalKey = "app:/system/applications/utilities/terminal.app"
private let zoomKey = "app:/applications/zoom.us.app"
private let ask = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)
private let askTrusting = AskPolicy(enabled: true, trustApplePrograms: true, benignChain: false)

class AskTestCase: XCTestCase {
    var h: Harness!
    /// Terminal → zsh (500).
    var userShell: ProcessRecord!
    /// Terminal → zsh (520) → Claude Code (600) → zsh (601).
    var agentShell: ProcessRecord!

    let zoom = proc(700, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", start: 0, signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3")

    override func setUpWithError() throws {
        h = try Harness(learningDays: 0)
        userShell = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let zsh = h.spawn(P.terminal, P.zsh(520, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 520, argv: ["node", "/opt/homebrew/bin/claude"]), 1)
        agentShell = h.spawn(claude, P.zsh(601, parent: 600), 2)
    }

    /// The user runs `leaf` in Terminal.
    func user(_ leaf: ProcessRecord) -> ProcessRecord { h.spawn(userShell, leaf, 3) }
    /// Claude Code runs `leaf` (in Terminal).
    func agent(_ leaf: ProcessRecord) -> ProcessRecord { h.spawn(agentShell, leaf, 3) }

    func target(_ path: String, _ access: AccessSet = .read) -> EvaluationTarget {
        let c = h.classifier.classify(path)!
        return EvaluationTarget(path: h.normalizer.normalize(path), access: access,
                                categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
    }

    func eval(_ rules: [Rule], _ p: ProcessRecord, _ targets: [EvaluationTarget], ask policy: AskPolicy = ask,
              enforcing: Bool = true, now: Date = at(10)) -> RuleDecision {
        h.rules.replace(rules: rules)
        return h.rules.evaluate(process: p, chain: h.tree.chain(for: p, at: now), targets: targets,
                                enforcementActive: enforcing, now: now, ask: policy)
    }

    func askDenial(_ responsibleKey: String, _ category: String = "ssh", agents: [String] = []) -> RuleDecision {
        RuleDecision(verdict: .deny, reason: .askUser,
                     askKey: AskKey(responsibleKey: responsibleKey, categoryID: category, access: .read, chainAgents: agents))
    }
}

final class AskDecisionTableTests: AskTestCase {
    // Row 1: listings never reach the rules.
    func testDirectoryListingIsNeverAsked() {
        let ls = user(proc(510, "/bin/ls", platform: true))
        let (op, targets) = OperationSemantics.open(ReportedPath("/Users/alice/.ssh", isDirectory: true), fflag: 0x0110_0001)
        XCTAssertTrue(h.analyzer.classify(FileActivity(time: at(5), operation: op, process: ls, targets: targets)).isEmpty)
        XCTAssertEqual(eval([], ls, []).reason, .notSensitive)
    }

    // Row 2.
    func testNeverBlockDaemonsAreNotAsked() {
        let launchd = proc(1, "/sbin/launchd", ppid: 0, platform: true)
        XCTAssertEqual(eval([], launchd, [target(sshKey)]).reason, .neverBlock)
        XCTAssertEqual(eval([], launchd, [target(sshKey)]).verdict, .allow)
    }

    // Row 3: an enforced deny decides; its exceptions are earlier answers.
    func testEnforcedDenyDecidesAndExceptionsCountAsAnswers() {
        var deny = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        var d = eval([deny], zoom, [target(sshKey)])
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.reason, .explicitDeny)
        XCTAssertNil(d.askKey)
        // "Always allow" on a blocked read: allowed without asking again.
        deny.exceptions = [RuleException(subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), categoryID: "ssh", access: .read)]
        d = eval([deny], zoom, [target(sshKey)])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(eval([deny], zoom, [target(sshKey, .write)]).verdict, .deny, "a read approval is not a write approval")
    }

    // Row 4.
    func testAllowRulesDecideOnlyWhatTheyCover() {
        let allowRead = Rule(target: .category("ssh"), subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"),
                             access: .read, action: .allow)
        var d = eval([allowRead], zoom, [target(sshKey)])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .explicitAllow)
        XCTAssertEqual(d.ruleID, allowRead.id)
        XCTAssertTrue(d.suppressAlert)
        // The write half of a read+write open is not covered: asked, about the whole request.
        d = eval([allowRead], zoom, [target(sshKey, .readWrite)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey?.access, .readWrite)
        // An allow for one category does not answer another one the same operation touches.
        d = eval([allowRead], zoom, [target(sshKey), target(awsCredentials, .write)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey?.categoryID, "aws")
        XCTAssertEqual(d.askKey?.access, .write)
        // A path allow answers for what is inside it, not for moving a parent directory.
        let knownHosts = Rule(target: .pathPrefix("~/.ssh/known_hosts"), subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"),
                              action: .allow)
        XCTAssertEqual(eval([knownHosts], zoom, [target("/Users/alice/.ssh/known_hosts", .readWrite)]).verdict, .allow)
        let sshDir = EvaluationTarget(path: "/Users/alice/.ssh", access: .readWrite, categories: [TargetCategory(id: "ssh", severity: .critical)])
        XCTAssertEqual(eval([knownHosts], zoom, [sshDir]).verdict, .ask)
        XCTAssertEqual(eval([knownHosts], zoom, [sshDir], ask: .off).reason, .explicitAllow, "unchanged without ask mode")
    }

    // Row 5.
    func testOwnersAreAllowedOnlyWithoutAnAgent() {
        let ssh = user(proc(510, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        var d = eval([], ssh, [target(sshKey)])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .owner)
        XCTAssertFalse(d.cacheable, "an ES-cached allow would cover ssh run by an agent later")
        let agentSSH = agent(proc(610, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        d = eval([], agentSSH, [target(sshKey)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey, AskKey(responsibleKey: "agent:claude-code", categoryID: "ssh", access: .read, chainAgents: ["claude-code"]))
    }

    // Row 6.
    func testBenignServiceChainsAreNotAsked() {
        let bird = proc(90, "/System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird", platform: true)
        let chain = h.tree.chain(for: bird, at: at(10))
        XCTAssertTrue(h.analyzer.isBenignChain(chain))
        let d = h.rules.evaluate(process: bird, chain: chain, targets: [target(sshKey)], enforcementActive: true, now: at(10),
                                 ask: AskPolicy(enabled: true, trustApplePrograms: false, benignChain: true))
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .benign)
        XCTAssertFalse(d.cacheable)
        // The same binary started from a shell is not a service.
        let shellBird = user(proc(511, bird.executablePath, platform: true))
        XCTAssertFalse(h.analyzer.isBenignChain(h.tree.chain(for: shellBird, at: at(10))))
        XCTAssertEqual(eval([], shellBird, [target(sshKey)], ask: AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)).verdict,
                       .ask)
    }

    // Row 7.
    func testTrustedApplePrograms() {
        let cat = user(P.cat(510, parent: 500))
        XCTAssertEqual(eval([], cat, [target(sshKey)]).verdict, .ask, "off by default")
        let d = eval([], cat, [target(sshKey)], ask: askTrusting)
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .trustedApple)
        XCTAssertFalse(d.cacheable)
        // Never under an AI agent.
        let agentCat = agent(P.cat(610, parent: 601))
        XCTAssertEqual(eval([], agentCat, [target(sshKey)], ask: askTrusting).verdict, .ask)
        // A copied Apple binary keeps its platform flag, not its location.
        for path in ["/private/tmp/cat", "/Users/alice/bin/cat", "/System/Volumes/Data/private/tmp/cat"] {
            let copy = user(proc(511, path, platform: true, signingID: "com.apple.cat"))
            XCTAssertEqual(eval([], copy, [target(sshKey)], ask: askTrusting).verdict, .ask, path)
        }
        // Third-party programs are never "Apple programs".
        XCTAssertEqual(eval([], zoom, [target(sshKey)], ask: askTrusting).verdict, .ask)
    }

    // Row 8.
    func testAnythingElseIsAskedWithItsKey() {
        var d = eval([], zoom, [target(sshKey, .readWrite)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.reason, .askUser)
        XCTAssertNil(d.ruleID)
        XCTAssertFalse(d.cacheable, "questions are never cached")
        XCTAssertEqual(d.askKey, AskKey(responsibleKey: zoomKey, categoryID: "ssh", access: .readWrite, chainAgents: []))
        // Every category and severity is asked; the question is about the most severe one…
        XCTAssertEqual(eval([], zoom, [target(history)]).askKey?.categoryID, "shell-history")
        d = eval([], zoom, [target(history), target(sshKey, .write)])
        XCTAssertEqual(d.askKey?.categoryID, "ssh")
        XCTAssertEqual(d.askKey?.access, .write, "the access asked about is the one on that category")
        // …and on a tie, the first.
        XCTAssertEqual(eval([], zoom, [target(awsCredentials), target(sshKey)]).askKey?.categoryID, "aws")
        // Nothing read or written (a metadata-only open): nothing to ask, nothing cached.
        d = eval([], zoom, [target(sshKey, [])])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertFalse(d.cacheable)
    }

    func testAlertRulesAndDryRunDeniesDoNotDecide() {
        let alert = Rule(target: .category("ssh"), subject: .anyNonOwner, action: .alert)
        let dryRun = Rule(enforce: false, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        XCTAssertEqual(eval([alert], zoom, [target(sshKey)]).verdict, .ask)
        XCTAssertEqual(eval([dryRun], zoom, [target(sshKey)]).verdict, .ask)
        // They still alert on an access something else allows.
        let ssh = user(proc(510, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        let openssh = RuleSubject.signed(signingID: "com.apple.openssh", teamID: nil)
        var d = eval([Rule(enforce: false, target: .category("ssh"), subject: openssh, action: .deny)], ssh, [target(sshKey)])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertTrue(d.wouldDeny)
        XCTAssertTrue(d.forceAlert)
        d = eval([Rule(target: .category("ssh"), subject: openssh, action: .alert)], ssh, [target(sshKey)])
        XCTAssertEqual(d.reason, .alertRule)
        XCTAssertTrue(d.forceAlert)
        let cat = user(P.cat(511, parent: 500))
        d = eval([alert], cat, [target(sshKey)], ask: askTrusting)
        XCTAssertEqual(d.reason, .trustedApple)
        XCTAssertTrue(d.forceAlert)
        XCTAssertEqual(d.ruleID, alert.id)
    }

    func testWithoutAskOrEnforcementNothingChanges() {
        var d = eval([], zoom, [target(sshKey)], ask: .off)
        XCTAssertEqual(d.reason, .defaultAllow)
        XCTAssertTrue(d.cacheable)
        d = eval([], zoom, [target(sshKey)], enforcing: false)
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .defaultAllow)
        XCTAssertNil(d.askKey)
        let agentSSH = agent(proc(610, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        XCTAssertEqual(eval([], agentSSH, [target(sshKey)], ask: .off).reason, .owner)
    }

    func testAnAllowOnceIsNotUsedUpByAQuestion() {
        var deny = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        deny.exceptions = [RuleException(subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), categoryID: "ssh",
                                         access: .read, expiresAt: at(600), remainingUses: 1)]
        h.rules.replace(rules: [deny])
        let chain = h.tree.chain(for: zoom, at: at(10))
        // Copying the key into the AWS credentials: nothing decides the AWS write.
        var d = h.rules.evaluate(process: zoom, chain: chain, targets: [target(sshKey), target(awsCredentials, .write)],
                                 enforcementActive: true, now: at(10), ask: ask)
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey?.categoryID, "aws")
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 1)
        XCTAssertFalse(h.rules.takeConsumed())
        d = h.rules.evaluate(process: zoom, chain: chain, targets: [target(sshKey)], enforcementActive: true, now: at(11), ask: ask)
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(h.rules.rules[0].exceptions[0].remainingUses, 0)
        XCTAssertEqual(h.rules.evaluate(process: zoom, chain: chain, targets: [target(sshKey)], enforcementActive: true, now: at(12),
                                        ask: ask).verdict, .deny)
    }
}

final class AskChainScopingTests: AskTestCase {
    func testAnApprovalForTerminalNeverCoversClaudeCodeInTerminal() {
        let userCat = user(P.cat(510, parent: 500))
        let agentCat = agent(P.cat(610, parent: 601))
        // "Always allow" answered for Terminal (no agent in the chain).
        let answer = Rule(target: .category("ssh"), subject: .responsible(key: terminalKey, teamID: nil), access: .read,
                          action: .allow, template: "ask-answer", chainAgents: [])
        XCTAssertEqual(eval([answer], userCat, [target(sshKey)]).reason, .explicitAllow)
        let d = eval([answer], agentCat, [target(sshKey)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey?.responsibleKey, "agent:claude-code")
        // Not even a rule naming the program itself, when scoped to chains without an agent.
        let catNoAgent = Rule(target: .category("ssh"), subject: .signed(signingID: "com.apple.cat", teamID: nil),
                              action: .allow, chainAgents: [])
        XCTAssertEqual(eval([catNoAgent], userCat, [target(sshKey)]).verdict, .allow)
        XCTAssertEqual(eval([catNoAgent], agentCat, [target(sshKey)]).verdict, .ask)
    }

    func testAnApprovalUnderClaudeCodeCoversOnlyChainsWithThoseAgents() {
        let userCat = user(P.cat(510, parent: 500))
        let agentCat = agent(P.cat(610, parent: 601))
        let codex = h.spawn(agentShell, proc(611, "/opt/homebrew/bin/codex", start: 4), 4)
        let codexCat = h.spawn(codex, P.cat(612, parent: 611), 5)
        let answer = Rule(target: .category("ssh"), subject: .responsible(key: "agent:claude-code", teamID: nil), access: .read,
                          action: .allow, template: "ask-answer", chainAgents: ["claude-code"])
        XCTAssertEqual(eval([answer], agentCat, [target(sshKey)]).verdict, .allow)
        let catUnderClaude = Rule(target: .category("ssh"), subject: .signed(signingID: "com.apple.cat", teamID: nil),
                                  action: .allow, chainAgents: ["claude-code"])
        XCTAssertEqual(eval([catUnderClaude], agentCat, [target(sshKey)]).verdict, .allow)
        XCTAssertEqual(eval([catUnderClaude], userCat, [target(sshKey)]).verdict, .allow, "no agent is a subset")
        // Codex inside Claude Code: an agent the user did not see.
        let d = eval([catUnderClaude], codexCat, [target(sshKey)])
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertEqual(d.askKey?.chainAgents, ["claude-code", "codex"])
        XCTAssertEqual(d.askKey?.responsibleKey, "agent:codex")
    }

    func testChainScopedRulesApplyInEveryMode() {
        let userCat = user(P.cat(510, parent: 500))
        let agentCat = agent(P.cat(610, parent: 601))
        let codex = h.spawn(agentShell, proc(611, "/opt/homebrew/bin/codex", start: 4), 4)
        let codexCat = h.spawn(codex, P.cat(612, parent: 611), 5)
        let cat = RuleSubject.signed(signingID: "com.apple.cat", teamID: nil)
        let deny = Rule(enforce: true, target: .category("ssh"), subject: cat, action: .deny, chainAgents: ["claude-code"])
        XCTAssertEqual(eval([deny], agentCat, [target(sshKey)], ask: .off).verdict, .deny)
        XCTAssertEqual(eval([deny], userCat, [target(sshKey)], ask: .off).verdict, .deny)
        XCTAssertEqual(eval([deny], codexCat, [target(sshKey)], ask: .off).verdict, .allow)
        var any = deny
        any.chainAgents = nil
        XCTAssertEqual(eval([any], codexCat, [target(sshKey)], ask: .off).verdict, .deny, "nil = any chain")
        // A chain-scoped rule makes the decision chain-dependent: never cached.
        let allow = Rule(target: .category("ssh"), subject: cat, action: .allow)
        var scoped = allow
        scoped.chainAgents = []
        XCTAssertTrue(eval([allow], userCat, [target(sshKey)], ask: .off).cacheable)
        XCTAssertFalse(eval([scoped], userCat, [target(sshKey)], ask: .off).cacheable)
        XCTAssertFalse(eval([scoped], userCat, [target(sshKey)]).cacheable)
        // Rules round-trip their scope.
        let back = try? Exporter.decoder().decode([Rule].self, from: Exporter.encoder(pretty: false).encode([scoped, allow]))
        XCTAssertEqual(back?.map(\.chainAgents), [[], nil])
    }

    func testCacheabilityInAskMode() {
        let zoomSubject = RuleSubject.signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3")
        let allowAll = Rule(target: .category("ssh"), subject: zoomSubject, access: .any, action: .allow)
        XCTAssertTrue(eval([allowAll], zoom, [target(sshKey)]).cacheable)
        // A cached open allow covers every later open of the file: a read-only approval must not
        // let a write open through without a question.
        let allowRead = Rule(target: .category("ssh"), subject: zoomSubject, access: .read, action: .allow)
        XCTAssertEqual(eval([allowRead], zoom, [target(sshKey)]).verdict, .allow)
        XCTAssertFalse(eval([allowRead], zoom, [target(sshKey)]).cacheable)
        // "Allow once" answers expire.
        let once = Rule(target: .category("ssh"), subject: zoomSubject, action: .allow, expiresAt: at(600), template: "ask-answer")
        XCTAssertFalse(eval([once], zoom, [target(sshKey)]).cacheable)
        // Answers name the responsible app: chain-dependent.
        let answer = Rule(target: .category("ssh"), subject: .responsible(key: zoomKey, teamID: "BJ4HAAB9B3"), action: .allow,
                          template: "ask-answer", chainAgents: [])
        XCTAssertEqual(eval([answer], zoom, [target(sshKey)]).verdict, .allow)
        XCTAssertFalse(eval([answer], zoom, [target(sshKey)]).cacheable)
    }
}

final class AskAnalyzerTests: AskTestCase {
    func testAnUnansweredQuestionIsADenialWithAnAskAlert() throws {
        let cat = user(P.cat(510, parent: 500))
        let out = h.open(cat, sshKey, 5, context: .decided(askDenial(terminalKey)))
        XCTAssertEqual(out.events.count, 1)
        XCTAssertEqual(out.events[0].decision, .denied)
        XCTAssertNil(out.events[0].ruleID)
        let alert = try XCTUnwrap(out.alerts.first?.alert)
        XCTAssertEqual(alert.kind, .ask)
        XCTAssertNil(alert.ruleID)
        XCTAssertTrue(alert.appleProgram)
        XCTAssertEqual(alert.availableActions, [.allowOnce, .alwaysAllow, .keepBlocking, .blockFromNowOn, .trustApplePrograms])
        XCTAssertNil(h.baseline.entry(BaselineKey(responsibleKey: terminalKey, categoryID: "ssh", access: .read)),
                     "it did not happen")
        // Under an agent, "allow all Apple programs" is not offered.
        let agentCat = agent(P.cat(610, parent: 601))
        let agentAlert = h.open(agentCat, sshKey, 6, context: .decided(askDenial("agent:claude-code", agents: ["claude-code"])))
            .alerts.first?.alert
        XCTAssertEqual(agentAlert?.kind, .ask)
        XCTAssertEqual(agentAlert?.appleProgram, false)
        XCTAssertEqual(agentAlert?.availableActions.contains(.trustApplePrograms), false)
        // Nor for a third-party program.
        XCTAssertEqual(h.open(zoom, sshKey, 7, context: .decided(askDenial(zoomKey))).alerts.first?.alert.appleProgram, false)
        // A stray rule id on an ask denial is dropped: no rule denied it.
        var withRule = askDenial(terminalKey)
        withRule.ruleID = "r1"
        XCTAssertNil(h.open(cat, sshKey, 8, context: .decided(withRule)).events[0].ruleID)
    }

    func testOnlyTheAskedCategoryAlerts() {
        let cp = user(proc(510, "/bin/cp", platform: true))
        let out = h.file(.clone, cp, OperationSemantics.clone(source: sshKey, destination: awsCredentials), 5,
                         context: .decided(askDenial(terminalKey, "aws")))
        XCTAssertEqual(Set(out.events.map(\.categoryID)), ["ssh", "aws"])
        XCTAssertTrue(out.events.allSatisfy { $0.decision == .denied })
        XCTAssertEqual(out.alerts.map(\.alert.categoryID), ["aws"])
        XCTAssertEqual(out.alerts.first?.alert.kind, .ask)
    }

    func testAskAlertsCoalesceApartFromBlocks() throws {
        let cat = user(P.cat(510, parent: 500))
        let blocked = RuleDecision(verdict: .deny, policyDenied: .readWrite, reason: .explicitDeny, ruleID: "r1", forceAlert: true)
        let block = try XCTUnwrap(h.open(cat, sshKey, 5, context: .decided(blocked)).alerts.first)
        XCTAssertEqual(block.alert.kind, .blocked)
        let asked = try XCTUnwrap(h.open(cat, sshKey, 6, context: .decided(askDenial(terminalKey))).alerts.first)
        XCTAssertEqual(asked.change, .created, "a question is not one of the rule's denials")
        XCTAssertNotEqual(asked.alert.id, block.alert.id)
        let again = try XCTUnwrap(h.open(cat, sshKey, 7, context: .decided(askDenial(terminalKey))).alerts.first)
        XCTAssertEqual(again.change, .merged)
        XCTAssertEqual(again.alert.id, asked.alert.id)
        XCTAssertEqual(again.alert.count, 2)
        let blockedAgain = try XCTUnwrap(h.open(cat, sshKey, 8, context: .decided(blocked)).alerts.first)
        XCTAssertEqual(blockedAgain.alert.id, block.alert.id)
        XCTAssertEqual(blockedAgain.alert.kind, .blocked)
    }

    func testAskAlertsAreKeptApartByTheAgentsInTheChain() {
        func event(_ id: Int64, agents: [String?]) -> AnalyzedEvent {
            let chain = agents.enumerated().map { i, a in ChainLink(pid: Int32(10 + i), name: "p\(i)", path: "/x/p\(i)", agentID: a) }
            return AnalyzedEvent(id: id, time: at(Double(id)), operation: .open, access: .read, path: sshKey, secondaryPath: nil,
                                 categoryID: "ssh", severity: .critical, process: proc(1, "/x"), chain: chain,
                                 responsible: ResponsibleEntity(kind: .app, key: "app:/applications/foo.app", displayName: "Foo"),
                                 agentID: agents.compactMap { $0 }.last, isOwner: false, benignServiceID: nil, decision: .denied, ruleID: nil)
        }
        let c = AlertCoalescer(window: 600)
        let plain = c.ingest(event(1, agents: [nil, nil]), kind: .ask)!
        let driven = c.ingest(event(2, agents: ["claude-code", nil]), kind: .ask)!
        XCTAssertNotEqual(plain.alert.id, driven.alert.id)
        XCTAssertEqual(c.ingest(event(3, agents: [nil]), kind: .ask)?.alert.id, plain.alert.id)
        XCTAssertEqual(c.ingest(event(4, agents: [nil, "claude-code"]), kind: .ask)?.alert.id, driven.alert.id)
        // A daemon restart keeps them apart.
        let restored = AlertCoalescer(window: 600)
        restored.restore(openAlerts: [plain.alert, driven.alert], nextID: 10)
        XCTAssertEqual(restored.ingest(event(5, agents: ["claude-code"]), kind: .ask)?.alert.id, driven.alert.id)
        XCTAssertEqual(restored.ingest(event(6, agents: []), kind: .ask)?.alert.id, plain.alert.id)
    }
}

final class AskMonitorOnlyTests: AskTestCase {
    func testThereIsNoLearningPeriodByDefault() {
        XCTAssertEqual(Settings().learningDays, 0)
        XCTAssertFalse(Baseline(learningStartedAt: t0).isLearning(at: t0))
    }

    func testFirstAccessesAlertAtOnce() throws {
        let out = h.open(zoom, history, 1)
        let alert = try XCTUnwrap(out.alerts.first?.alert)
        XCTAssertEqual(alert.kind, .firstAccess)
        XCTAssertTrue(alert.firstTime)
        XCTAssertFalse(alert.appleProgram)
        XCTAssertEqual(alert.availableActions, [.alwaysAllow, .blockFromNowOn, .ignore])
        // Known afterwards: quiet once the window closed.
        XCTAssertTrue(h.open(zoom, history, 700).alerts.isEmpty)
        // A write is a new access.
        XCTAssertEqual(h.open(zoom, history, write: true, 701).alerts.first?.alert.kind, .firstAccess)
    }

    func testAppleProgramsAreOfferedTheTrustAnswer() throws {
        let cat = user(P.cat(510, parent: 500))
        let alert = try XCTUnwrap(h.open(cat, sshKey, 5).alerts.first?.alert)
        XCTAssertEqual(alert.kind, .criticalNonOwner)
        XCTAssertTrue(alert.firstTime)
        XCTAssertTrue(alert.appleProgram)
        XCTAssertEqual(alert.availableActions, [.alwaysAllow, .blockFromNowOn, .ignore, .trustApplePrograms])
        let en = AlertFormatter(language: .en, abbreviate: { [n = h.normalizer] in n.abbreviate($0) })
        XCTAssertTrue(en.line(alert).hasSuffix("Always allow · Block from now on · Ignore · Allow all Apple programs"))
        // An alert rule's alert is about the rule: no trust answer.
        h.rules.replace(rules: [Rule(target: .category("shell-history"), subject: .anyNonOwner, action: .alert)])
        let ruleAlert = try XCTUnwrap(h.open(cat, history, 6).alerts.first?.alert)
        XCTAssertEqual(ruleAlert.kind, .ruleAlert)
        XCTAssertFalse(ruleAlert.appleProgram)
    }

    func testTrustingAppleProgramsSilencesTheirFirstAccesses() {
        h.analyzer.trustApplePrograms = true
        let cat = user(P.cat(510, parent: 500))
        var out = h.open(cat, sshKey, 5)
        XCTAssertEqual(out.events.count, 1)
        XCTAssertTrue(out.alerts.isEmpty)
        XCTAssertTrue(h.open(cat, history, 6, context: .afterAuth).alerts.isEmpty)
        // Never under an agent, never a copy.
        let agentCat = agent(P.cat(610, parent: 601))
        XCTAssertEqual(h.open(agentCat, sshKey, 7).alerts.first?.alert.kind, .criticalNonOwner)
        let copy = user(proc(511, "/private/tmp/cat", platform: true, signingID: "com.apple.cat"))
        XCTAssertEqual(h.open(copy, sshKey, 8).alerts.first?.alert.kind, .criticalNonOwner)
        // Rules still speak.
        h.rules.replace(rules: [Rule(target: .category("ssh"), subject: .anyNonOwner, action: .alert)])
        out = h.open(user(P.cat(512, parent: 500)), sshKey, 700)
        XCTAssertEqual(out.alerts.first?.alert.kind, .ruleAlert)
    }

    func testAnOwnerDrivenByAnAgentIsNotExpected() {
        let ssh = user(proc(510, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        let quiet = h.open(ssh, sshKey, 5)
        XCTAssertTrue(quiet.events[0].isOwner)
        XCTAssertTrue(quiet.alerts.isEmpty)
        let agentSSH = agent(proc(610, "/usr/bin/ssh", platform: true, signingID: "com.apple.openssh"))
        let out = h.open(agentSSH, sshKey, 6)
        XCTAssertTrue(out.events[0].isOwner)
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
        XCTAssertEqual(out.alerts.first?.alert.appleProgram, false)
    }
}

final class AskFormatterTests: XCTestCase {
    func alert(_ kind: AlertKind, count: Int = 1, appleProgram: Bool = false) -> Alert {
        Alert(id: 1, kind: kind, createdAt: t0, updatedAt: t0, windowEndsAt: at(600),
              responsible: ResponsibleEntity(kind: .app, key: terminalKey, displayName: "Terminal"),
              categoryID: "ssh", severity: .critical, count: count, accesses: .read, firstPath: sshKey,
              firstEventID: 1, lastEventID: 1, paths: [sshKey], chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd")],
              agentID: nil, ruleID: nil, appleProgram: appleProgram)
    }

    func testAskWording() {
        let n = PathNormalizer(homeDirectories: [home])
        let zh = AlertFormatter(language: .zhHans, abbreviate: { n.abbreviate($0) })
        let en = AlertFormatter(language: .en, abbreviate: { n.abbreviate($0) })
        XCTAssertEqual(zh.headline(alert(.ask)), "Terminal 想要读取 ~/.ssh/id_ed25519，你决定之前不会放行")
        XCTAssertEqual(en.headline(alert(.ask, count: 3)), "Terminal wants to read ~/.ssh/id_ed25519: not allowed until you decide (×3)")
        XCTAssertEqual(zh.line(alert(.ask, appleProgram: true)),
                       "Terminal 想要读取 ~/.ssh/id_ed25519，你决定之前不会放行｜调用链：launchd｜允许一次 · 始终允许 · 拒绝 · 始终拒绝 · 允许所有 Apple 程序")
        XCTAssertTrue(en.line(alert(.ask)).hasSuffix("| Allow once · Always allow · Deny · Always deny"))
        XCTAssertEqual(zh.kindTitle(.ask), "等你决定")
        XCTAssertEqual(en.kindTitle(.ask), "Needs your decision")
        XCTAssertEqual(en.actionTitle(.trustApplePrograms), "Allow all Apple programs")
        // Other kinds keep their titles.
        XCTAssertEqual(en.actionTitle(.keepBlocking, kind: .blocked), "Keep blocking")
        XCTAssertEqual(zh.actionTitle(.blockFromNowOn, kind: .firstAccess), "以后拦截")
        XCTAssertEqual(en.actionTitle(.keepBlocking), "Keep blocking")
    }
}

// Second review: answers built from the question's key, dead answers pruned, scoping in monitor-only
// mode, and settings saved before ask mode.
final class AskAnswerRoundTripTests: AskTestCase {
    /// The answer rule as docs/ASK_MODE.md describes it, built only from what the question carries.
    func answerRule(_ key: AskKey, _ r: ResponsibleEntity, once: Bool = false) -> Rule {
        let access: RuleAccess = key.access == .read ? .read : (key.access == .write ? .write : .any)
        let pin = r.kind == .binary && r.teamID == nil ? r.cdhash : nil
        return Rule(target: .category(key.categoryID), subject: .responsible(key: key.responsibleKey, teamID: r.teamID, cdhash: pin),
                    access: access, action: .allow, expiresAt: once ? at(600) : nil, template: RuleTemplates.askAnswer,
                    chainAgents: key.chainAgents)
    }

    func askAndAnswer(_ p: ProcessRecord, _ t: [EvaluationTarget], once: Bool = false,
                      file: StaticString = #filePath, line: UInt = #line) -> Rule? {
        let d = eval([], p, t)
        XCTAssertEqual(d.verdict, .ask, file: file, line: line)
        guard let key = d.askKey else { XCTFail("no key", file: file, line: line); return nil }
        let rule = answerRule(key, h.attributor.attribute(chain: h.tree.chain(for: p, at: at(10))), once: once)
        XCTAssertEqual(eval([rule], p, t).verdict, .allow, "the answer decides the access it was asked about", file: file, line: line)
        return rule
    }

    func testAnAnswerDecidesTheAccessItWasAskedAbout() throws {
        let userCat = user(P.cat(510, parent: 500))
        let agentCat = agent(P.cat(610, parent: 601))
        // Terminal: never covers Claude Code in Terminal.
        let forTerminal = try XCTUnwrap(askAndAnswer(userCat, [target(sshKey)]))
        XCTAssertEqual(eval([forTerminal], agentCat, [target(sshKey)]).verdict, .ask)
        // Claude Code: never covers Codex inside it.
        let forClaude = try XCTUnwrap(askAndAnswer(agentCat, [target(sshKey)]))
        let codex = h.spawn(agentShell, proc(611, "/opt/homebrew/bin/codex", start: 4), 4)
        XCTAssertEqual(eval([forClaude], h.spawn(codex, P.cat(612, parent: 611), 5), [target(sshKey)]).verdict, .ask)
        // A read answer does not answer a write.
        XCTAssertEqual(eval([forTerminal], userCat, [target(sshKey, .write)]).verdict, .ask)
        // Read and write together, and a third-party app.
        _ = askAndAnswer(zoom, [target(sshKey, .readWrite)])
        // An unsigned binary charged to itself (no app in its chain) is pinned to its cdhash: a changed
        // binary at the same path is asked again. (Run in Terminal, it is charged to Terminal.)
        var tool = proc(530, "/Users/alice/bin/tool", start: 3)
        tool.cdhash = "abcd"
        let forTool = try XCTUnwrap(askAndAnswer(h.spawn(P.launchd, tool, 3), [target(sshKey)]))
        var rebuilt = tool
        rebuilt.pid = 531
        rebuilt.cdhash = "ef01"
        XCTAssertEqual(eval([forTool], h.spawn(P.launchd, rebuilt, 4), [target(sshKey)]).verdict, .ask)
    }

    func testAllowOnceAnswersExpireAndArePruned() throws {
        let userCat = user(P.cat(510, parent: 500))
        let once = try XCTUnwrap(askAndAnswer(userCat, [target(sshKey)], once: true))
        let always = try XCTUnwrap(askAndAnswer(zoom, [target(sshKey)]))
        var disabled = always
        disabled.id = "disabled"
        disabled.enabled = false
        let mine = Rule(target: .category("ssh"), subject: .anyNonOwner, action: .alert, expiresAt: at(600))
        h.rules.replace(rules: [once, always, disabled, mine])
        XCTAssertFalse(h.rules.pruneDeadExceptions(at: at(599)), "still live")
        XCTAssertEqual(eval(h.rules.rules, userCat, [target(sshKey)], now: at(700)).verdict, .ask, "an allow once runs out")
        h.rules.replace(rules: [once, always, disabled, mine])
        XCTAssertTrue(h.rules.pruneDeadExceptions(at: at(600)))
        // Only expired answers go; a disabled (unexpired) answer and the user's own expired rule stay.
        XCTAssertEqual(h.rules.rules.map(\.id), [always.id, "disabled", mine.id])
        XCTAssertFalse(h.rules.pruneDeadExceptions(at: at(700)))
    }

    func testTrustNeverOverridesADenyRule() {
        let cat = user(P.cat(510, parent: 500))
        let deny = Rule(enforce: true, target: .category("ssh"), subject: .responsible(key: terminalKey, teamID: nil), action: .deny)
        let d = eval([deny], cat, [target(sshKey)], ask: AskPolicy(enabled: true, trustApplePrograms: true, benignChain: true))
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.reason, .explicitDeny)
    }

    func testMonitorOnlyAlertsKeepTheAgentScope() {
        // "Always allow" for Terminal in monitor-only mode: an allow rule with the chain's agents (none),
        // and the baseline approval.
        h.rules.replace(rules: [Rule(target: .category("ssh"), subject: .responsible(key: terminalKey, teamID: nil), action: .allow,
                                     template: RuleTemplates.askAnswer, chainAgents: [])])
        h.baseline.approve(responsibleKey: terminalKey, categoryID: "ssh", at: at(4))
        XCTAssertTrue(h.open(user(P.cat(510, parent: 500)), sshKey, 5).alerts.isEmpty)
        // Terminal → zsh → Claude Code → zsh → cat is charged to Claude Code anyway; a tool inside an app
        // bundle is charged to that app, so only the agent scope keeps the approval away from the agent.
        let bundled = h.spawn(agentShell, proc(620, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/cat",
                                               start: 3, platform: true, signingID: "com.apple.cat"), 3)
        let out = h.open(bundled, sshKey, 6)
        XCTAssertEqual(out.events.first?.responsible.key, terminalKey)
        XCTAssertEqual(out.alerts.first?.alert.kind, .criticalNonOwner)
        // Without the rule, the baseline approval alone does not speak for the agent either.
        h.rules.replace(rules: [])
        XCTAssertEqual(h.open(bundled, sshKey, 700).alerts.first?.alert.kind, .criticalNonOwner)
        XCTAssertTrue(h.open(user(P.cat(511, parent: 500)), sshKey, 1400).alerts.isEmpty, "the user's own access stays approved")
    }

    func testSettingsSavedBeforeAskModeLoseTheOldLearningDefault() throws {
        func decode(_ json: String) throws -> Settings { try JSONDecoder().decode(Settings.self, from: Data(json.utf8)) }
        XCTAssertEqual(try decode(#"{"learningDays": 7, "retentionDays": 30}"#).learningDays, 0)
        XCTAssertEqual(try decode(#"{"learningDays": 3}"#).learningDays, 3, "a value the user chose stays")
        XCTAssertEqual(try decode(#"{"learningDays": 7, "trustApplePrograms": false}"#).learningDays, 7, "chosen after ask mode")
        let saved = Settings(learningDays: 7)
        XCTAssertEqual(try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode(saved)).learningDays, 7)
    }
}
