import Foundation
import WhoReadCore
import WhoReadIPC

/// Runs `/usr/bin/eslogger` as a child process and turns its JSON Lines into events.
///
/// Monitor-only: eslogger supports NOTIFY events only. Must run as root, and eslogger's
/// responsible process (this daemon) needs Full Disk Access.
///
/// - eslogger suppresses events from its own process group; the daemon and eslogger share one,
///   so the daemon's own file activity never shows up (and tests must run in another group).
/// - Every line goes through the byte-level `LinePrefilter` before JSON parsing.
/// - The child is restarted with exponential backoff if it exits (or fails to start again), and at
///   once, without an error, when a settings change needs a new event list.
public final class EsloggerSource: EventSource, @unchecked Sendable {
    public let kind = SourceKind.eslogger
    public let canEnforce = false

    public let executable: String
    private let parser = EsloggerParser()
    private let filterLock = NSLock()
    private var prefilter: LinePrefilter
    private var readdir: Bool
    private let stateBox = StateBox()
    private let supervisor = DispatchQueue(label: "whoread.eslogger.supervisor")
    private let lock = NSLock()
    private var process: Process?
    private var sink: EventSink?
    private var stopping = false
    /// Set when updateMonitoring interrupts the child to change its event list.
    private var restartRequested = false
    private var restartDelay: TimeInterval = 1
    private var launchedAt = Date()
    private var stderrTail = Data()
    private var droppedByPrefilter: UInt64 = 0
    /// Left by the current reader thread at EOF; the next reader waits on it (see launch()).
    private var readerDone: DispatchGroup?

    public static func eventNames(readdir: Bool) -> [String] {
        ["open", "close", "exec", "fork", "exit", "rename", "clone", "copyfile", "link", "unlink", "truncate", "exchangedata"]
            + (readdir ? ["readdir"] : [])
    }

    public init(executable: String = "/usr/bin/eslogger", prefixes: [String], readdir: Bool = false) {
        self.executable = executable
        self.prefilter = LinePrefilter(prefixes: prefixes)
        self.readdir = readdir
    }

    public var state: SourceState { stateBox.get() }

    public var parserStats: EsloggerParser.Stats? {
        var s = parser.stats
        lock.lock()
        s.ignored += Int(droppedByPrefilter)
        lock.unlock()
        return s
    }

    public func start(sink: EventSink) throws {
        lock.lock()
        self.sink = sink
        stopping = false
        lock.unlock()
        try launch()
    }

    public func stop() {
        lock.lock()
        stopping = true
        let p = process
        lock.unlock()
        if let p, p.isRunning {
            p.interrupt()
            escalate(p)
        }
        publish { $0.running = false }
    }

    /// SIGINT, then SIGTERM, then SIGKILL: a child can inherit the daemon's ignored SIGINT/SIGTERM
    /// (whoreadd ignores them to handle them on a dispatch source), and then only SIGKILL ends it.
    private func escalate(_ p: Process) {
        supervisor.asyncAfter(deadline: .now() + 2) { [supervisor] in
            guard p.isRunning else { return }
            p.terminate()
            supervisor.asyncAfter(deadline: .now() + 2) {
                if p.isRunning { kill(p.processIdentifier, SIGKILL) }
            }
        }
    }

    public func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool) {
        filterLock.lock()
        prefilter = LinePrefilter(prefixes: prefixes)
        filterLock.unlock()
        lock.lock()
        let restart = readdir != self.readdir
        self.readdir = readdir
        let p = process
        if restart, p?.isRunning == true { restartRequested = true }
        lock.unlock()
        // The event list is a command-line argument: changing it needs a new eslogger. childExited
        // relaunches it at once instead of treating the exit as a failure.
        if restart, let p, p.isRunning {
            p.interrupt()
            escalate(p)
        }
    }

    private func publish(_ f: (inout SourceState) -> Void) {
        let s = stateBox.update(f)
        lock.lock()
        let sink = self.sink
        lock.unlock()
        sink?.sourceStateChanged(s)
    }

    private func launch() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        lock.lock()
        p.arguments = EsloggerSource.eventNames(readdir: readdir)
        lock.unlock()
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        let stderrClosed = DispatchSemaphore(value: 0)
        p.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.supervisor.async { self.childExited(proc, stderrClosed: stderrClosed) }
        }
        do {
            try p.run()
        } catch {
            publish {
                $0.running = false
                $0.error = "cannot start \(executable): \(error.localizedDescription)"
                $0.hint = "eslogger ships with macOS 13+ at /usr/bin/eslogger."
            }
            throw error
        }
        let done = DispatchGroup()
        done.enter()
        lock.lock()
        process = p
        launchedAt = Date()
        stderrTail = Data()
        let previous = readerDone
        readerDone = done
        lock.unlock()
        publish {
            $0.running = true
            $0.error = nil
            $0.hint = nil
        }
        // stderr gets a plain blocking reader rather than a readabilityHandler, whose EOF differs by
        // platform (corelibs never reports it, Darwin may keep reporting it): childExited waits for it.
        let errFD = err.fileHandleForReading.fileDescriptor
        let errReader = Thread { [weak self] in
            LineReader(fd: errFD, maxLine: 64 * 1024, chunk: 4096).run { line in
                guard let self else { return }
                self.lock.lock()
                self.stderrTail.append(contentsOf: line)
                self.stderrTail.append(0x0A)
                if self.stderrTail.count > 4096 { self.stderrTail = self.stderrTail.suffix(4096) }
                self.lock.unlock()
            }
            withExtendedLifetime(err) {}
            stderrClosed.signal()
        }
        errReader.name = "whoread.eslogger.stderr"
        errReader.start()
        let fd = out.fileHandleForReading.fileDescriptor
        let reader = Thread { [weak self, parser] in
            // The new eslogger numbers messages from 0. Let the old reader drain its pipe first so
            // the two streams do not interleave in the kernel-drop accounting (bounded wait).
            _ = previous?.wait(timeout: .now() + 2)
            parser.resetSequence()
            LineReader(fd: fd).run { line in self?.handle(line) }
            // The pipe owns fd: keep it open until EOF, even once a relaunch has replaced `process`.
            withExtendedLifetime(out) {}
            done.leave()
        }
        reader.name = "whoread.eslogger.reader"
        reader.qualityOfService = .userInitiated
        reader.start()
    }

    private func handle(_ line: UnsafeRawBufferPointer) {
        filterLock.lock()
        let verdict = prefilter.verdict(line)
        filterLock.unlock()
        guard verdict == .parse else {
            lock.lock(); droppedByPrefilter += 1; lock.unlock()
            if let g = LinePrefilter.globalSequence(line) { parser.noteSequence(g) }
            return
        }
        switch parser.parse(data: Data(line)) {
        case .event(let e):
            lock.lock()
            let sink = self.sink
            lock.unlock()
            sink?.receive(e, context: .monitorOnly)
        case .malformed:
            // Not a kernel drop: keep the sequence (harmless if the parser already noted it).
            if let g = LinePrefilter.globalSequence(line) { parser.noteSequence(g) }
        case .ignored:
            break
        }
    }

    private func childExited(_ p: Process, stderrClosed: DispatchSemaphore) {
        // The exit can overtake the stderr reader: let it reach EOF (bounded, in case a grandchild
        // keeps the pipe open) so the error and hint see everything eslogger printed.
        _ = stderrClosed.wait(timeout: .now() + 0.5)
        lock.lock()
        let stopping = self.stopping
        let requested = restartRequested
        restartRequested = false
        let uptime = Date().timeIntervalSince(launchedAt)
        let stderr = String(decoding: stderrTail, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if uptime > 60 { restartDelay = 1 }
        lock.unlock()
        if stopping {
            publish { $0.running = false }
            return
        }
        if requested {
            // Asked for by updateMonitoring: not a failure, so no error and no backoff.
            do { try launch() } catch { scheduleRelaunch() }
            return
        }
        let status = p.terminationStatus
        publish {
            $0.running = false
            $0.error = "eslogger exited (status \(status)) after \(Int(uptime)) s" + (stderr.isEmpty ? "" : ": " + stderr)
            if uptime < 5 {
                $0.hint = EsloggerSource.diagnose(stderr: stderr, euid: geteuid())
            }
        }
        scheduleRelaunch()
    }

    /// Relaunches after the current backoff delay, doubling it (max 60 s). A launch that fails
    /// (posix_spawn EAGAIN, EMFILE…) has no terminationHandler to retry from, so it reschedules.
    private func scheduleRelaunch() {
        lock.lock()
        let delay = restartDelay
        restartDelay = min(restartDelay * 2, 60)
        lock.unlock()
        supervisor.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let stop = self.stopping
            self.lock.unlock()
            guard !stop else { return }
            do { try self.launch() } catch { self.scheduleRelaunch() }
        }
    }

    /// Best-effort explanation for an immediate exit. The exact stderr text of eslogger is not
    /// documented (UNVERIFIED), so this keys on the documented failure causes.
    static func diagnose(stderr: String, euid: uid_t) -> String {
        let s = stderr.lowercased()
        if euid != 0 || s.contains("not_privileged") || s.contains("root") || s.contains("super-user") {
            return "eslogger must run as root (start whoreadd with sudo or as a LaunchDaemon)."
        }
        if s.contains("not_permitted") || s.contains("permitted") || s.contains("tcc") || s.contains("full disk") {
            return "Full Disk Access is missing for the process that started eslogger (the WhoRead daemon, or Terminal when run by hand). System Settings → Privacy & Security → Full Disk Access."
        }
        return "eslogger exited immediately. Check that whoreadd runs as root and has Full Disk Access."
    }
}
