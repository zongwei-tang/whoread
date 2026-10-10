import Foundation
import XCTest
@testable import WhoReadCore

/// Repository root, located from this file.
let repoRoot: URL = {
    var url = URL(fileURLWithPath: #filePath)
    while url.path != "/" {
        url.deleteLastPathComponent()
        if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) { return url }
    }
    fatalError("repo root not found")
}()

let home = "/Users/alice"

func defaultData() throws -> DefaultData {
    try DefaultData.load(directory: repoRoot.appendingPathComponent("Data"))
}

func fixtureURL(_ relative: String) -> URL {
    repoRoot.appendingPathComponent("Tests/Fixtures").appendingPathComponent(relative)
}

let t0 = Date(timeIntervalSince1970: 1_760_000_000)

func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

/// Small process factory.
func proc(
    _ pid: Int32, _ path: String, ppid: Int32 = 1, start: TimeInterval? = 0, platform: Bool = false,
    signingID: String? = nil, teamID: String? = nil, argv: [String]? = nil, originalPPID: Int32? = nil
) -> ProcessRecord {
    ProcessRecord(
        pid: pid, pidVersion: UInt32(pid) * 10, ppid: ppid, originalPPID: originalPPID ?? ppid,
        executablePath: path, signingID: signingID, teamID: teamID, isPlatformBinary: platform,
        argv: argv, startTime: start.map(at))
}

/// A fully wired analyzer over the real Data/ files.
struct Harness {
    let data: DefaultData
    let normalizer: PathNormalizer
    let classifier: PathClassifier
    let detector: AgentDetector
    let tree: ProcessTree
    let attributor: Attributor
    let rules: RuleEngine
    let baseline: Baseline
    let coalescer: AlertCoalescer
    let analyzer: Analyzer

    init(rules ruleList: [Rule] = [], learningStart: Date = t0, learningDays: Double = 7, projectRoots: [String] = [],
         symlinks: SymlinkResolver = NoSymlinkResolver()) throws {
        data = try defaultData()
        normalizer = PathNormalizer(homeDirectories: [home])
        classifier = PathClassifier(catalog: data.catalog, normalizer: normalizer, projectRoots: projectRoots, symlinks: symlinks)
        detector = AgentDetector(catalog: data.agents)
        let n = normalizer
        tree = ProcessTree(detector: detector, normalizePath: { n.normalize($0) })
        attributor = Attributor(agents: detector)
        rules = RuleEngine(rules: ruleList, classifier: classifier, attributor: attributor)
        baseline = Baseline(learningStartedAt: learningStart, learningDuration: learningDays * 86400)
        coalescer = AlertCoalescer(window: 600)
        analyzer = Analyzer(classifier: classifier, tree: tree, attributor: attributor,
                            benign: BenignClassifier(catalog: data.benign), rules: rules, baseline: baseline, coalescer: coalescer)
    }

    @discardableResult
    func fork(_ parent: ProcessRecord, _ child: ProcessRecord, _ t: TimeInterval = 0) -> ProcessRecord {
        _ = analyzer.handle(.fork(parent: parent, child: child, time: at(t)))
        return child
    }

    @discardableResult
    func exec(_ old: ProcessRecord, _ new: ProcessRecord, _ t: TimeInterval = 0) -> ProcessRecord {
        _ = analyzer.handle(.exec(process: old, target: new, time: at(t)))
        return new
    }

    /// fork + exec in one go: `parent` spawns `image` with pid.
    @discardableResult
    func spawn(_ parent: ProcessRecord, _ image: ProcessRecord, _ t: TimeInterval = 0) -> ProcessRecord {
        var child = parent
        child.pid = image.pid
        child.pidVersion = image.pidVersion.map { $0 - 1 }
        child.ppid = parent.pid
        child.originalPPID = parent.pid
        child.startTime = image.startTime
        fork(parent, child, t)
        var img = image
        img.ppid = parent.pid
        img.originalPPID = parent.pid
        return exec(child, img, t)
    }

    func open(_ p: ProcessRecord, _ path: String, write: Bool = false, _ t: TimeInterval = 0,
              context: RuleContext = .monitorOnly) -> AnalysisOutput {
        let fflag: UInt32 = write ? 0x3 : 0x1
        let activity = FileActivity(time: at(t), operation: .open, process: p,
                                    targets: OperationSemantics.open(path: path, fflag: fflag))
        return analyzer.handle(.file(activity), context: context)
    }

    func file(_ op: FileOperation, _ p: ProcessRecord, _ targets: [FileTarget], _ t: TimeInterval = 0,
              context: RuleContext = .monitorOnly) -> AnalysisOutput {
        analyzer.handle(.file(FileActivity(time: at(t), operation: op, process: p, targets: targets)), context: context)
    }
}

/// Common process images.
enum P {
    static let launchd = proc(1, "/sbin/launchd", ppid: 0, platform: true)
    static let terminal = proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", platform: true,
                               signingID: "com.apple.Terminal")
    static func zsh(_ pid: Int32, parent: Int32) -> ProcessRecord { proc(pid, "/bin/zsh", ppid: parent, platform: true, signingID: "com.apple.zsh") }
    static func cat(_ pid: Int32, parent: Int32) -> ProcessRecord { proc(pid, "/bin/cat", ppid: parent, platform: true, signingID: "com.apple.cat", argv: ["cat"]) }
    static func node(_ pid: Int32, parent: Int32, argv: [String]) -> ProcessRecord {
        proc(pid, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: parent, signingID: "node", argv: argv)
    }
}
