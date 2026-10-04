import Foundation

/// Parses eslogger JSON Lines into `SourceEvent`s.
///
/// Apple documents eslogger's output as *not* a stable interface, so this parser:
/// - reads `schema_version` and counts versions it has no fixtures for,
/// - finds the event by the key under `event` (`open`, `exec`, …), not by the numeric
///   `event_type` (that is an internal enum),
/// - treats every field as optional and ignores unknown fields,
/// - never fails a whole stream because of one bad line.
public final class EsloggerParser: @unchecked Sendable {
    /// Schema versions with fixtures under Tests/Fixtures/eslogger/.
    public static let knownSchemaVersions: Set<Int> = [1]

    public struct Stats: Codable, Sendable, Hashable {
        public var lines = 0
        public var events = 0
        public var ignored = 0
        public var malformed = 0
        public var unknownSchemaLines = 0
        public var schemaVersions: [String: Int] = [:]
        public var unknownEventKinds: [String: Int] = [:]
        /// Messages the kernel dropped, from gaps in global_seq_num.
        public var droppedByKernel: UInt64 = 0
    }

    public enum Result: Sendable {
        case event(SourceEvent)
        case ignored(String)
        case malformed(String)
    }

    private let lock = NSLock()
    private var _stats = Stats()
    private var lastGlobalSeq: UInt64?

    public init() {}

    public var stats: Stats {
        lock.lock(); defer { lock.unlock() }
        return _stats
    }

    private func bump(_ f: (inout Stats) -> Void) {
        lock.lock(); f(&_stats); lock.unlock()
    }

    /// Lines skipped by the prefilter still carry a sequence number; feeding it here keeps the
    /// kernel-drop counter honest (a prefiltered line is not a dropped event).
    public func noteSequence(_ g: UInt64) {
        lock.lock()
        if let last = lastGlobalSeq, g > last + 1 { _stats.droppedByKernel += g - last - 1 }
        if lastGlobalSeq.map({ g > $0 }) ?? true { lastGlobalSeq = g }
        lock.unlock()
    }

    public func parse(line: String) -> Result {
        parse(data: Data(line.utf8))
    }

    public func parse(data: Data) -> Result {
        bump { $0.lines += 1 }
        guard !data.isEmpty else {
            bump { $0.ignored += 1 }
            return .ignored("empty line")
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            bump { $0.malformed += 1 }
            return .malformed("invalid JSON: \(error.localizedDescription)")
        }
        guard let root = object as? [String: Any] else {
            bump { $0.malformed += 1 }
            return .malformed("top level is not an object")
        }
        let result = parse(root: root)
        switch result {
        case .event: bump { $0.events += 1 }
        case .ignored: bump { $0.ignored += 1 }
        case .malformed: bump { $0.malformed += 1 }
        }
        return result
    }

    func parse(root: [String: Any]) -> Result {
        let schema = J.int(root["schema_version"])
        bump { s in
            let k = schema.map(String.init) ?? "missing"
            s.schemaVersions[k, default: 0] += 1
            if let schema, !EsloggerParser.knownSchemaVersions.contains(schema) { s.unknownSchemaLines += 1 }
        }
        guard let event = root["event"] as? [String: Any], let kind = event.keys.first(where: { event[$0] is [String: Any] }),
              let body = event[kind] as? [String: Any]
        else {
            return .malformed("no event object")
        }
        guard let processObject = root["process"] as? [String: Any], let process = EsloggerParser.process(processObject) else {
            return .malformed("no process")
        }
        let time = J.string(root["time"]).flatMap(RFC3339.parse) ?? Date()
        let globalSeq = J.uint64(root["global_seq_num"])
        let seq = globalSeq ?? J.uint64(root["seq_num"])
        if let g = globalSeq {
            lock.lock()
            if let last = lastGlobalSeq, g > last + 1 { _stats.droppedByKernel += g - last - 1 }
            if lastGlobalSeq.map({ g > $0 }) ?? true { lastGlobalSeq = g }
            lock.unlock()
        }

        func file(_ op: FileOperation, _ targets: [FileTarget]) -> Result {
            guard !targets.isEmpty else { return .ignored("\(kind) without sensitive-capable targets") }
            return .event(.file(FileActivity(time: time, sequence: seq, operation: op, process: process, targets: targets)))
        }

        switch kind {
        case "open":
            guard let f = J.file(body["file"]) else { return .malformed("open without file") }
            let fflag = UInt32(truncatingIfNeeded: J.int(body["fflag"]) ?? 0)
            return file(.open, OperationSemantics.open(path: f.path, fflag: fflag, truncated: f.truncated))
        case "close":
            guard let f = J.file(body["target"]) else { return .malformed("close without target") }
            let modified = J.bool(body["modified"]) ?? false
            if !modified { return .ignored("close without modification") }
            return file(.close, OperationSemantics.close(path: f.path, modified: true, truncated: f.truncated))
        case "rename":
            guard let src = J.file(body["source"]) else { return .malformed("rename without source") }
            guard let dst = EsloggerParser.destination(body) else { return .malformed("rename without destination") }
            return file(.rename, OperationSemantics.rename(source: src.path, destination: dst))
        case "clone":
            guard let src = J.file(body["source"]), let dir = J.file(body["target_dir"]), let name = J.string(body["target_name"]) else {
                return .malformed("clone missing fields")
            }
            return file(.clone, OperationSemantics.clone(source: src.path, destination: OperationSemantics.join(dir: dir.path, name: name)))
        case "copyfile":
            guard let src = J.file(body["source"]) else { return .malformed("copyfile without source") }
            let dst: String
            if let existing = J.file(body["target_file"]) {
                dst = existing.path
            } else if let dir = J.file(body["target_dir"]), let name = J.string(body["target_name"]) {
                dst = OperationSemantics.join(dir: dir.path, name: name)
            } else {
                return .malformed("copyfile without target")
            }
            return file(.copyfile, OperationSemantics.copyfile(source: src.path, destination: dst))
        case "link":
            guard let src = J.file(body["source"]), let dir = J.file(body["target_dir"]),
                  let name = J.string(body["target_filename"]) ?? J.string(body["target_name"]) else {
                return .malformed("link missing fields")
            }
            return file(.link, OperationSemantics.link(source: src.path, destination: OperationSemantics.join(dir: dir.path, name: name)))
        case "unlink":
            guard let t = J.file(body["target"]) else { return .malformed("unlink without target") }
            return file(.unlink, OperationSemantics.unlink(path: t.path))
        case "truncate":
            guard let t = J.file(body["target"]) else { return .malformed("truncate without target") }
            return file(.truncate, OperationSemantics.truncate(path: t.path))
        case "exchangedata":
            guard let a = J.file(body["file1"]), let b = J.file(body["file2"]) else { return .malformed("exchangedata missing files") }
            return file(.exchangedata, OperationSemantics.exchangedata(a.path, b.path))
        case "readdir":
            guard let t = J.file(body["target"]) else { return .malformed("readdir without target") }
            return file(.readdir, OperationSemantics.readdir(path: t.path))
        case "create":
            guard let dst = EsloggerParser.destination(body) else { return .malformed("create without destination") }
            return file(.create, OperationSemantics.create(path: dst))
        case "exec":
            guard let targetObject = body["target"] as? [String: Any], var target = EsloggerParser.process(targetObject) else {
                return .malformed("exec without target")
            }
            if let args = body["args"] as? [Any] {
                target.argv = args.compactMap { $0 as? String }
            }
            return .event(.exec(process: process, target: target, time: time))
        case "fork":
            guard let childObject = body["child"] as? [String: Any], let child = EsloggerParser.process(childObject) else {
                return .malformed("fork without child")
            }
            return .event(.fork(parent: process, child: child, time: time))
        case "exit":
            return .event(.exit(process: process, time: time))
        default:
            bump { $0.unknownEventKinds[kind, default: 0] += 1 }
            return .ignored("unsupported event \(kind)")
        }
    }

    /// rename/create destination: `destination.existing_file` or `destination.new_path{dir, filename}`.
    static func destination(_ body: [String: Any]) -> String? {
        guard let dest = body["destination"] as? [String: Any] else { return nil }
        if let existing = J.file(dest["existing_file"]) { return existing.path }
        if let newPath = dest["new_path"] as? [String: Any], let dir = J.file(newPath["dir"]),
           let name = J.string(newPath["filename"]) {
            return OperationSemantics.join(dir: dir.path, name: name)
        }
        return nil
    }

    static func process(_ o: [String: Any]) -> ProcessRecord? {
        let token = o["audit_token"] as? [String: Any]
        guard let pid = J.int(token?["pid"]) ?? J.int(o["pid"]) else { return nil }
        guard let exe = J.file(o["executable"]) else { return nil }
        let responsible = o["responsible_audit_token"] as? [String: Any]
        return ProcessRecord(
            pid: Int32(truncatingIfNeeded: pid),
            pidVersion: J.int(token?["pidversion"]).map { UInt32(truncatingIfNeeded: $0) },
            ppid: Int32(truncatingIfNeeded: J.int(o["ppid"]) ?? 0),
            originalPPID: J.int(o["original_ppid"]).map { Int32(truncatingIfNeeded: $0) },
            responsiblePID: J.int(responsible?["pid"]).map { Int32(truncatingIfNeeded: $0) },
            executablePath: exe.path,
            pathTruncated: exe.truncated,
            signingID: J.string(o["signing_id"]).flatMap { $0.isEmpty ? nil : $0 },
            teamID: J.string(o["team_id"]).flatMap { $0.isEmpty ? nil : $0 },
            cdhash: J.hex(o["cdhash"]),
            isPlatformBinary: J.bool(o["is_platform_binary"]) ?? false,
            argv: nil,
            startTime: J.string(o["start_time"]).flatMap(RFC3339.parse),
            euid: J.int(token?["euid"]).map { UInt32(truncatingIfNeeded: $0) })
    }
}

/// Tolerant accessors for JSONSerialization output, which differs between Darwin (NSNumber for
/// numbers and booleans) and swift-corelibs-foundation.
enum J {
    static func int(_ v: Any?) -> Int? {
        switch v {
        case let i as Int: return i
        case let i as Int64: return Int(i)
        case let u as UInt64: return Int(exactly: u)
        case let d as Double: return d.isFinite ? Int(exactly: d.rounded()) : nil
        case let n as NSNumber: return n.intValue
        case let s as String: return Int(s)
        default: return nil
        }
    }

    static func uint64(_ v: Any?) -> UInt64? {
        switch v {
        case let u as UInt64: return u
        case let i as Int: return i >= 0 ? UInt64(i) : nil
        case let n as NSNumber: return n.uint64Value
        case let s as String: return UInt64(s)
        default: return nil
        }
    }

    static func bool(_ v: Any?) -> Bool? {
        switch v {
        case let b as Bool: return b
        case let n as NSNumber: return n.boolValue
        case let i as Int: return i != 0
        case let s as String: return s == "true" || s == "1"
        default: return nil
        }
    }

    static func string(_ v: Any?) -> String? {
        if let s = v as? String { return s }
        return nil
    }

    /// es_file_t as JSON: {"path": "...", "path_truncated": false, "stat": {...}}.
    static func file(_ v: Any?) -> (path: String, truncated: Bool)? {
        guard let o = v as? [String: Any], let path = o["path"] as? String else { return nil }
        return (path, bool(o["path_truncated"]) ?? false)
    }

    /// cdhash as hex string, or as an array of byte values.
    static func hex(_ v: Any?) -> String? {
        if let s = v as? String { return s.isEmpty ? nil : s.lowercased() }
        if let a = v as? [Any] {
            let bytes = a.compactMap { int($0) }
            guard bytes.count == a.count, !bytes.isEmpty else { return nil }
            return bytes.map { String(format: "%02x", $0 & 0xff) }.joined()
        }
        return nil
    }
}
