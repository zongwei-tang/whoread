import Foundation
import WhoReadCore
import WhoReadIPC
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Feeds an eslogger JSONL file (or stdin with "-") through the pipeline. Used by tests,
/// `whoread replay`, and `whoreadd run --source replay:<file>` for demos without root.
public final class ReplaySource: EventSource, @unchecked Sendable {
    public let kind = SourceKind.replay
    public let canEnforce = false
    public let path: String
    public let realtime: Bool
    private let parser = EsloggerParser()
    private let prefilterLock = NSLock()
    private var prefilter: LinePrefilter?
    private let stateBox = StateBox()
    private var sink: EventSink?
    private var thread: Thread?
    private var cancelled = false
    private let done = DispatchSemaphore(value: 0)

    public init(path: String, realtime: Bool = false, prefixes: [String]? = nil, ancestors: [String] = []) {
        self.path = path
        self.realtime = realtime
        self.prefilter = prefixes.map { LinePrefilter(prefixes: $0, ancestors: ancestors) }
    }

    public var state: SourceState { stateBox.get() }
    public var parserStats: EsloggerParser.Stats? { parser.stats }

    public func start(sink: EventSink) throws {
        self.sink = sink
        let fd: Int32 = path == "-" ? 0 : open(path, O_RDONLY)
        guard fd >= 0 else {
            let s = stateBox.update { $0.error = "cannot open \(path): \(String(cString: strerror(errno)))" }
            sink.sourceStateChanged(s)
            throw IPCError(.unavailable, s.error ?? "open failed")
        }
        sink.sourceStateChanged(stateBox.update { $0.running = true })
        let t = Thread { [weak self] in
            self?.run(fd: fd)
            if fd != 0 { close(fd) }
        }
        t.name = "whoread.replay"
        thread = t
        t.start()
    }

    private func run(fd: Int32) {
        var lastEventTime: Date?
        LineReader(fd: fd).run { line in
            if cancelled { return }
            prefilterLock.lock()
            let skip = prefilter.map { $0.verdict(line) == .drop } ?? false
            prefilterLock.unlock()
            if skip {
                if let g = LinePrefilter.globalSequence(line) { parser.noteSequence(g) }
                return
            }
            let e: SourceEvent
            switch parser.parse(data: Data(line)) {
            case .event(let event):
                e = event
            case .malformed:
                // Not a kernel drop: keep the sequence (harmless if the parser already noted it).
                if let g = LinePrefilter.globalSequence(line) { parser.noteSequence(g) }
                return
            case .ignored:
                return
            }
            if realtime, let last = lastEventTime {
                let gap = e.time.timeIntervalSince(last)
                if gap > 0 { Thread.sleep(forTimeInterval: min(gap, 1)) }
            }
            lastEventTime = e.time
            sink?.receive(e, context: .monitorOnly)
        }
        let s = stateBox.update {
            $0.running = false
            $0.finished = true
        }
        sink?.sourceStateChanged(s)
        done.signal()
    }

    /// Blocks until the file has been fully processed (tests, `whoread replay`).
    public func waitUntilFinished(timeout: TimeInterval = 60) -> Bool {
        let ok = done.wait(timeout: .now() + timeout) == .success
        if ok { done.signal() }
        return ok
    }

    public func stop() { cancelled = true }

    public func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool) {
        prefilterLock.lock()
        if prefilter != nil { prefilter = LinePrefilter(prefixes: prefixes, ancestors: ancestors) }
        prefilterLock.unlock()
    }
}
