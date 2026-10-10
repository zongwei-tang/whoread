import XCTest
@testable import WhoReadCore

final class RuleEngineTests: XCTestCase {
    var h: Harness!

    override func setUpWithError() throws { h = try Harness() }

    func target(_ path: String, _ access: AccessSet = .read) -> EvaluationTarget {
        let c = h.classifier.classify(path)!
        return EvaluationTarget(path: h.normalizer.normalize(path), access: access,
                                categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
    }

    func eval(_ rules: [Rule], _ p: ProcessRecord, _ targets: [EvaluationTarget], chain: [ProcessNode]? = nil,
              enforcing: Bool = true, now: Date = at(0)) -> RuleDecision {
        h.rules.replace(rules: rules)
        return h.rules.evaluate(process: p, chain: chain ?? h.tree.chain(for: p, at: now), targets: targets,
                                enforcementActive: enforcing, now: now)
    }

    let zoom = proc(700, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", start: 0, signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3")
    let ssh = proc(701, "/usr/bin/ssh", start: 0, platform: true, signingID: "com.apple.openssh")
    let cat = proc(702, "/bin/cat", start: 0, platform: true, signingID: "com.apple.cat")

    func testNoRulesDefaultAllowAndCacheable() {
        let d = eval([], zoom, [target("/Users/alice/.ssh/id_rsa")])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.reason, .defaultAllow)
        XCTAssertTrue(d.cacheable)
        XCTAssertTrue(d.policyDenied.isEmpty)
    }

    func testOwnerReason() {
        XCTAssertEqual(eval([], ssh, [target("/Users/alice/.ssh/id_rsa")]).reason, .owner)
    }

    func testPriorityDenyBeatsAllowBeatsOwner() {
        let deny = Rule(enforce: true, target: .category("ssh"), subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), action: .deny)
        let allow = Rule(target: .category("ssh"), subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), action: .allow)
        var d = eval([allow, deny], zoom, [target("/Users/alice/.ssh/id_rsa")])
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, deny.id)
        XCTAssertEqual(d.policyDenied, .readWrite)
        d = eval([allow], zoom, [target("/Users/alice/.ssh/id_rsa")])
        XCTAssertEqual(d.reason, .explicitAllow)
        XCTAssertTrue(d.suppressAlert)
        // Explicit deny beats owner status.
        let denySSH = Rule(enforce: true, target: .category("ssh"), subject: .signed(signingID: "com.apple.openssh", teamID: nil), action: .deny)
        XCTAssertEqual(eval([denySSH], ssh, [target("/Users/alice/.ssh/id_rsa")]).verdict, .deny)
    }

    func testDryRunAndInactiveEnforcementOnlyWouldDeny() {
        let dry = Rule(enforce: false, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        var d = eval([dry], zoom, [target("/Users/alice/.ssh/id_rsa")])
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertTrue(d.wouldDeny)
        XCTAssertEqual(d.reason, .wouldDeny)
        XCTAssertTrue(d.forceAlert)
        let live = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        d = eval([live], zoom, [target("/Users/alice/.ssh/id_rsa")], enforcing: false)
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertTrue(d.wouldDeny)
        XCTAssertTrue(d.policyDenied.isEmpty, "inactive enforcement denies nothing")
    }

    func testAnyNonOwnerSkipsPlatformBinariesUnlessOptedIn() {
        var rule = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .read, action: .deny)
        XCTAssertEqual(eval([rule], cat, [target("/Users/alice/.ssh/id_rsa")]).verdict, .allow)
        XCTAssertEqual(eval([rule], zoom, [target("/Users/alice/.ssh/id_rsa")]).verdict, .deny)
        XCTAssertEqual(eval([rule], ssh, [target("/Users/alice/.ssh/id_rsa")]).verdict, .allow, "owner")
        rule.includePlatformBinaries = true
        XCTAssertEqual(eval([rule], cat, [target("/Users/alice/.ssh/id_rsa")]).verdict, .deny)
    }

    func testAgentAncestorRuleHitsPlatformBinariesAndRespectsOwners() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 1)
        let sh = h.spawn(claude, P.zsh(601, parent: 600), 2)
        let agentCat = h.spawn(sh, P.cat(602, parent: 601), 3)
        let agentSSH = h.spawn(sh, proc(603, "/usr/bin/ssh", start: 3, platform: true), 3)
        let userCat = h.spawn(zsh, P.cat(510, parent: 500), 3)
        let rule = RuleTemplates.blockAgentsFromCritical()
        var live = rule
        live.enabled = true
        live.enforce = true
        let key = target("/Users/alice/.ssh/id_rsa")
        XCTAssertEqual(eval([live], agentCat, [key], now: at(4)).verdict, .deny)
        XCTAssertEqual(eval([live], userCat, [key], now: at(4)).verdict, .allow, "no agent in chain")
        // The brief's priority is deny > allow > owner: the template blocks owners under an agent too.
        XCTAssertEqual(eval([live], agentSSH, [key], now: at(4)).verdict, .deny, "deny beats owner")
        var lenient = live
        lenient.subject = .agentAncestor(agentIDs: nil, exceptOwners: true)
        XCTAssertEqual(eval([lenient], agentSSH, [key], now: at(4)).verdict, .allow, "opt-in owner exception")
        // severityAtLeast uses the file-level severity: ~/.ssh/config is medium.
        XCTAssertEqual(eval([live], agentCat, [target("/Users/alice/.ssh/config")], now: at(4)).verdict, .allow)
        // Writes are not covered by a read rule.
        XCTAssertEqual(eval([live], agentCat, [target("/Users/alice/.ssh/id_rsa", .write)], now: at(4)).verdict, .allow)
        // Chain-dependent: never cacheable.
        XCTAssertFalse(eval([live], userCat, [key], now: at(4)).cacheable)
        // Template is disabled by default.
        XCTAssertEqual(eval([rule], agentCat, [key], now: at(4)).reason, .defaultAllow)
    }

    func testNeverBlockList() {
        let rule = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny, includePlatformBinaries: true)
        let launchd = proc(1, "/sbin/launchd", ppid: 0, platform: true)
        let mds = proc(90, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores", platform: true)
        let fakeMds = proc(91, "/tmp/mds_stores", platform: false)
        XCTAssertEqual(eval([rule], launchd, [target("/Users/alice/.ssh/id_rsa")]).reason, .neverBlock)
        XCTAssertEqual(eval([rule], mds, [target("/Users/alice/.ssh/id_rsa")]).reason, .neverBlock)
        XCTAssertEqual(eval([rule], fakeMds, [target("/Users/alice/.ssh/id_rsa")]).verdict, .deny)
        h.rules.setNeverBlock(NeverBlockList(selfPIDs: [702]))
        XCTAssertEqual(eval([rule], cat, [target("/Users/alice/.ssh/id_rsa")]).reason, .neverBlock)
    }

    func testPathPrefixTargetAndAncestors() {
        let rule = Rule(enforce: true, target: .pathPrefix("~/.ssh/id_ed25519"), subject: .anyNonOwner, action: .deny)
        XCTAssertEqual(eval([rule], zoom, [target("/Users/alice/.ssh/id_ed25519")]).verdict, .deny)
        XCTAssertEqual(eval([rule], zoom, [target("/Users/alice/.ssh/id_rsa")]).verdict, .allow)
        // Renaming ~/.ssh (an ancestor of the protected prefix) is covered too.
        let dir = EvaluationTarget(path: "/Users/alice/.ssh", access: .readWrite, categories: [TargetCategory(id: "ssh", severity: .critical)])
        XCTAssertEqual(eval([rule], zoom, [dir]).verdict, .deny)
    }

    func testPartialAccessPolicyIsNeverCachedAsAllow() {
        let denyWrite = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, access: .write, action: .deny)
        let d = eval([denyWrite], zoom, [target("/Users/alice/.ssh/id_rsa", .read)])
        XCTAssertEqual(d.verdict, .allow, "read-only open passes")
        // A cached allow would let a later write open through without an AUTH event, so the native
        // source only caches allows with nothing denied.
        XCTAssertEqual(d.policyDenied, .write)
    }

    func testExceptionsAllowOnceAndAlways() {
        var rule = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        rule.exceptions = [RuleException(subject: .responsible(key: "app:/applications/zoom.us.app", teamID: "BJ4HAAB9B3"),
                                         expiresAt: at(600), remainingUses: 1)]
        let t = [target("/Users/alice/.ssh/id_rsa")]
        h.rules.replace(rules: [rule])
        let chain = h.tree.chain(for: zoom, at: at(0))
        XCTAssertEqual(h.rules.evaluate(process: zoom, chain: chain, targets: t, enforcementActive: true, now: at(1)).verdict, .allow)
        XCTAssertEqual(h.rules.evaluate(process: zoom, chain: chain, targets: t, enforcementActive: true, now: at(2)).verdict, .deny,
                       "allow-once is used up")
        // A non-consuming evaluation (NOTIFY after AUTH) must not burn the use.
        h.rules.replace(rules: [rule])
        _ = h.rules.evaluate(process: zoom, chain: chain, targets: t, enforcementActive: true, now: at(1), consumeExceptions: false)
        XCTAssertEqual(h.rules.evaluate(process: zoom, chain: chain, targets: t, enforcementActive: true, now: at(2)).verdict, .allow)
        // Expired exception.
        h.rules.replace(rules: [rule])
        XCTAssertEqual(h.rules.evaluate(process: zoom, chain: chain, targets: t, enforcementActive: true, now: at(601)).verdict, .deny)
        // Permanent exception narrowed to one path.
        rule.exceptions = [RuleException(subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), pathPrefix: "~/.ssh/known_hosts")]
        XCTAssertEqual(eval([rule], zoom, [target("/Users/alice/.ssh/known_hosts")]).verdict, .allow)
        XCTAssertEqual(eval([rule], zoom, [target("/Users/alice/.ssh/id_rsa")]).verdict, .deny)
    }

    func testExpiredAndUsedUpRulesAreIgnored() {
        let expired = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny, expiresAt: at(-1))
        XCTAssertEqual(eval([expired], zoom, [target("/Users/alice/.ssh/id_rsa")]).verdict, .allow)
        let used = Rule(enforce: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny, remainingUses: 0)
        XCTAssertEqual(eval([used], zoom, [target("/Users/alice/.ssh/id_rsa")]).verdict, .allow)
    }

    func testCacheability() {
        let signed = Rule(enforce: true, target: .category("ssh"), subject: .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"), action: .deny)
        XCTAssertTrue(eval([signed], zoom, [target("/Users/alice/.ssh/id_rsa")]).cacheable)
        let timed = Rule(enforce: true, target: .category("ssh"), subject: .signed(signingID: "x", teamID: nil), action: .allow, expiresAt: at(100))
        XCTAssertFalse(eval([timed], zoom, [target("/Users/alice/.ssh/id_rsa")]).cacheable)
        // Rules on other categories do not affect cacheability here.
        let other = Rule(enforce: true, target: .category("aws"), subject: .anyNonOwner, action: .deny)
        XCTAssertTrue(eval([other], zoom, [target("/Users/alice/.ssh/id_rsa")]).cacheable)
    }

    func testAlertRule() {
        let rule = Rule(target: .category("ssh"), subject: .anyNonOwner, action: .alert)
        let d = eval([rule], zoom, [target("/Users/alice/.ssh/id_rsa")])
        XCTAssertEqual(d.reason, .alertRule)
        XCTAssertTrue(d.forceAlert)
        XCTAssertEqual(d.verdict, .allow)
    }

    func testRuleJSONRoundTrip() throws {
        let rules = RuleTemplates.all + [
            Rule(target: .pathPrefix("~/x"), subject: .unsigned(path: "/opt/x", cdhash: "ab"), action: .alert),
            Rule(target: .category("aws"), subject: .responsible(key: "app:/applications/zoom.us.app", teamID: nil), action: .deny,
                 exceptions: [RuleException(subject: .agentAncestor(agentIDs: ["codex"], exceptOwners: false), remainingUses: 1)]),
        ]
        let data = try Exporter.encoder(pretty: true).encode(rules)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains("\"type\" : \"agentAncestor\""))
        XCTAssertTrue(text.contains("\"severityAtLeast\" : \"critical\""))
        let back = try Exporter.decoder().decode([Rule].self, from: data)
        XCTAssertEqual(back.map(\.id), rules.map(\.id))
        XCTAssertEqual(back[3].subject, rules[3].subject)
        XCTAssertEqual(back[4].exceptions.first?.subject, rules[4].exceptions.first?.subject)
    }
}
