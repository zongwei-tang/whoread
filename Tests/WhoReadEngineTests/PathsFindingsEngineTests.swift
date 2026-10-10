import XCTest
import WhoReadCore
@testable import WhoReadEngine

// files-3 (eslogger half): the eslogger and replay sources get the classifier's ancestors, so a
// symlink created at a parent of monitored prefixes reaches the analyzer.

/// NOTIFY_CREATE of a symlink at /Users/alice/.config, as eslogger writes it.
private let configLinkLine =
    #"{"schema_version":1,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\/bin\/ln"}},"event":{"create":{"destination_type":0,"destination":{"existing_file":{"path":"\/Users\/alice\/.config","stat":{"st_mode":41453}}}}}}"#

final class AncestorPrefilterSourceTests: XCTestCase {
    private func isConfigCreate(_ e: SourceEvent) -> Bool {
        if case .file(let f) = e { return f.operation == .create && f.targets.first?.path == "/Users/alice/.config" }
        return false
    }

    func testTheDaemonsReplaySourceRecordsALinkPlantedAtAParent() throws {
        let dir = TempDir()
        let lines = dir.path("lines.jsonl")
        try (configLinkLine + "\n").write(toFile: lines, atomically: false, encoding: .utf8)
        var config = baseConfig(dir, replay: lines)
        config.permissive = true
        let core = try DaemonCore(config: config)
        try core.source.start(sink: core.pipeline)
        XCTAssertTrue((core.source as! ReplaySource).waitUntilFinished())
        core.writer.flush()
        let events = try core.store.events(EventQuery(includeBenign: true))
        XCTAssertEqual(Set(events.map(\.categoryID)), ["gh", "gcloud", "git-credentials"])
        XCTAssertTrue(events.allSatisfy { $0.operation == .create && $0.viaAncestor })
    }

    func testEsloggerSourcePassesAncestorsToItsPrefilter() throws {
        let h = PathClassifier(catalog: try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog,
                               normalizer: PathNormalizer(homeDirectories: ["/Users/alice"]))
        let dir = TempDir()
        let lines = dir.path("lines.jsonl")
        let go = dir.path("go")
        try (configLinkLine + "\n" + exitLine(1) + "\n").write(toFile: lines, atomically: false, encoding: .utf8)
        // Waits until the test has updated the source, then writes the lines.
        let fake = script(dir, "eslogger", "while [ ! -e \(go) ]; do sleep 0.05; done\ncat \(lines)\nexec sleep 600")

        // Built with ancestors.
        try "".write(toFile: go, atomically: false, encoding: .utf8)
        let built = EsloggerSource(executable: fake, prefixes: h.mutePaths, ancestors: h.ancestors)
        let builtSink = RecordingSink()
        try built.start(sink: builtSink)
        defer { built.stop() }
        XCTAssertNotNil(waitFor(5) { builtSink.events.contains(where: self.isConfigCreate) })

        // Given them by updateMonitoring (a classifier swap).
        try FileManager.default.removeItem(atPath: go)
        let updated = EsloggerSource(executable: fake, prefixes: h.mutePaths)
        let sink = RecordingSink()
        try updated.start(sink: sink)
        defer { updated.stop() }
        updated.updateMonitoring(prefixes: h.mutePaths, ancestors: h.ancestors, readdir: false)
        try "".write(toFile: go, atomically: false, encoding: .utf8)
        XCTAssertNotNil(waitFor(5) { sink.events.contains { if case .exit = $0 { return true }; return false } })
        XCTAssertTrue(sink.events.contains(where: isConfigCreate))
    }
}

#if canImport(EndpointSecurity)
import EndpointSecurity

// files-3 (native half): an AUTH_CREATE says what it creates only through `new_path.mode`.
final class NativeCreateTypeTests: XCTestCase {
    /// Zeroed C memory (never freed: a few bytes per test).
    private func zeroed<T>(_ type: T.Type) -> UnsafeMutablePointer<T> {
        let p = UnsafeMutablePointer<T>.allocate(capacity: 1)
        memset(UnsafeMutableRawPointer(p), 0, MemoryLayout<T>.size)
        return p
    }
    private func token(_ s: String) -> es_string_token_t {
        let c = strdup(s)!
        return es_string_token_t(length: strlen(c), data: UnsafePointer(c))
    }
    private func file(_ path: String) -> UnsafeMutablePointer<es_file_t> {
        let f = zeroed(es_file_t.self)
        f.pointee.path = token(path)
        return f
    }

    /// AUTH_CREATE of /Users/alice/.config with this `mode`.
    private func authCreate(mode: mode_t) -> FileActivity? {
        let process = zeroed(es_process_t.self)
        process.pointee.executable = file("/bin/ln")
        let msg = zeroed(es_message_t.self)
        msg.pointee.version = 1
        msg.pointee.event_type = ES_EVENT_TYPE_AUTH_CREATE
        msg.pointee.process = process
        msg.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        msg.pointee.event.create.destination.new_path.dir = file("/Users/alice")
        msg.pointee.event.create.destination.new_path.filename = token(".config")
        msg.pointee.event.create.destination.new_path.mode = mode
        return NativeESSource.activity(UnsafePointer(msg))
    }

    func testAnAuthCreateUsesTheFileTypeInItsModeWhenThereIsOne() throws {
        let link = try XCTUnwrap(authCreate(mode: S_IFLNK | 0o755))
        XCTAssertEqual(link.operation, .create)
        XCTAssertEqual(link.targets.map(\.path), ["/Users/alice/.config"])
        XCTAssertEqual(link.targets.first?.isDirectory, false)
        XCTAssertEqual(try XCTUnwrap(authCreate(mode: S_IFDIR | 0o755)).targets.first?.isDirectory, true)
        XCTAssertNil(try XCTUnwrap(authCreate(mode: 0o755)).targets.first?.isDirectory, "permission bits only: unknown")

        // What the AUTH path then decides about it.
        let data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data"))
        let classifier = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: ["/Users/alice"]))
        let detector = AgentDetector(catalog: data.agents)
        let rules = RuleEngine(rules: [], classifier: classifier)
        let analyzer = Analyzer(classifier: classifier, tree: ProcessTree(detector: detector), attributor: Attributor(agents: detector),
                                benign: BenignClassifier(catalog: data.benign), rules: rules, baseline: Baseline(learningStartedAt: Date()), coalescer: AlertCoalescer())
        XCTAssertEqual(Set(analyzer.classify(link).flatMap(\.categories).map(\.id)), ["gh", "gcloud", "git-credentials"])
        XCTAssertTrue(analyzer.classify(try XCTUnwrap(authCreate(mode: S_IFDIR | 0o755))).allSatisfy { !$0.isSensitive })
    }
}
#endif
