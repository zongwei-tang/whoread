import Foundation
import WhoReadCore

/// Turns a raw eslogger capture into a small fixture that is safe to commit.
///
/// Keeps:
/// - every event that touches the test vault;
/// - fork/exec/exit events of the processes involved and their ancestors (chain reconstruction);
/// - up to `samplePerKind` other events per event kind, only if all their paths, the process's
///   included, are system paths after firmlink normalization (structure coverage without personal data).
///
/// Rewrites, on the raw line so eslogger's exact shape (`\/` escaping, key order) survives:
/// - the home directory → `/Users/alice`, the user name → `alice`, the per-user
///   `/private/var/folders/<xx>/<id>` (or `/var/folders/…`) → `…/folders/xx/alice`;
/// - exec `env` arrays → `[]` (eslogger emits the full environment, which may hold secrets);
/// - exec `args` of sampled events → only argv[0]; vault-related argv kept (test commands).
public struct FixtureSanitizer {
    public var home: String
    public var vault: String
    public var samplePerKind: Int
    public var replacementHome = "/Users/alice"

    public init(home: String, vault: String? = nil, samplePerKind: Int = 40) {
        self.home = home
        self.vault = vault ?? (home + "/" + WhoReadPaths.testVaultName)
        self.samplePerKind = samplePerKind
    }

    public struct Report: Sendable {
        public var inputLines = 0
        public var kept = 0
        public var vaultEvents = 0
        public var lifecycle = 0
        public var samples = 0
        public var byKind: [String: Int] = [:]
    }

    /// Apple-managed roots. Deliberately absent: /Applications/Utilities (Apple's utilities live in
    /// /System/Applications/Utilities; the data-volume folder holds third-party apps) and /Library/Preferences
    /// (third-party file names there are the installed-app inventory).
    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/", "/dev/",
                                 "/private/etc/", "/System/Volumes/Preboot/"]
    /// User-writable, per-user or inventory places under the system prefixes (lowercase: compared case-folded,
    /// since APFS is case-insensitive).
    static let nonSystemPrefixes = ["/usr/local/", "/private/var/db/dslocal/", "/private/var/db/sudo/", "/private/var/db/receipts/"]

    /// Checked on the normalized path: `/System/Volumes/Data/…` is the user data volume, not the system.
    static func isSystem(_ path: String, normalizer: PathNormalizer) -> Bool {
        let n = normalizer.normalize(path)
        let key = PathNormalizer.fold(n)
        return systemPrefixes.contains { n.hasPrefix($0) } && !nonSystemPrefixes.contains { key.hasPrefix($0) }
    }

    public func sanitize(lines: [String]) -> (output: [String], report: Report) {
        var report = Report()
        report.inputLines = lines.count
        let vaultVariants = [vault, vault.replacingOccurrences(of: "/", with: "\\/")]

        // Pass 1: parse what we need.
        struct Info {
            var kind: String; var pid: Int32?; var ppid: Int32?; var childPID: Int32?; var paths: [String]; var procPaths: [String]
            var vault: Bool
        }
        var infos: [Info?] = []
        var interesting = Set<Int32>()
        var parent: [Int32: Int32] = [:]
        for line in lines {
            guard let data = line.data(using: .utf8),
                  let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let event = root["event"] as? [String: Any], let kind = event.keys.first,
                  let body = event[kind] as? [String: Any] else {
                infos.append(nil)
                continue
            }
            let process = root["process"] as? [String: Any]
            let pid = FixtureSanitizer.int((process?["audit_token"] as? [String: Any])?["pid"]).map { Int32(truncatingIfNeeded: $0) }
            let ppid = FixtureSanitizer.int(process?["ppid"]).map { Int32(truncatingIfNeeded: $0) }
            let originalPPID = FixtureSanitizer.int(process?["original_ppid"]).map { Int32(truncatingIfNeeded: $0) }
            var childPID: Int32?
            if kind == "fork", let child = body["child"] as? [String: Any] {
                childPID = FixtureSanitizer.int((child["audit_token"] as? [String: Any])?["pid"]).map { Int32(truncatingIfNeeded: $0) }
            }
            var paths: [String] = []
            FixtureSanitizer.collectPaths(body, into: &paths)
            // The process object (executable, tty) is committed with the line too.
            var procPaths: [String] = []
            if let process { FixtureSanitizer.collectPaths(process, into: &procPaths) }
            let touchesVault = vaultVariants.contains { line.contains($0) }
            if touchesVault, let pid { interesting.insert(pid) }
            // A reparented process reports ppid 1: use original_ppid, and never replace known ancestry.
            if let pid, let pp = (ppid == 1 ? originalPPID : ppid) ?? ppid, pp > 1, parent[pid] == nil { parent[pid] = pp }
            if let c = childPID, let pid { parent[c] = pid }
            infos.append(Info(kind: kind, pid: pid, ppid: ppid, childPID: childPID, paths: paths, procPaths: procPaths,
                              vault: touchesVault))
        }
        // Ancestors of interesting processes.
        var frontier = Array(interesting)
        while let p = frontier.popLast() {
            if let pp = parent[p], pp > 1, !interesting.contains(pp) {
                interesting.insert(pp)
                frontier.append(pp)
            }
        }

        // Pass 2: select and rewrite.
        var out: [String] = []
        var sampled: [String: Int] = [:]
        let normalizer = PathNormalizer()
        for (line, info) in zip(lines, infos) {
            guard let info else { continue }
            var keep = false
            var isSample = false
            if info.vault {
                keep = true
                report.vaultEvents += 1
            } else if ["fork", "exec", "exit"].contains(info.kind),
                      (info.pid.map(interesting.contains) ?? false) || (info.childPID.map(interesting.contains) ?? false) {
                keep = true
                report.lifecycle += 1
            } else if sampled[info.kind, default: 0] < samplePerKind,
                      !info.paths.isEmpty, (info.paths + info.procPaths).allSatisfy({ FixtureSanitizer.isSystem($0, normalizer: normalizer) }) {
                keep = true
                isSample = true
                sampled[info.kind, default: 0] += 1
                report.samples += 1
            }
            guard keep else { continue }
            var rewritten = rewrite(line)
            rewritten = FixtureSanitizer.replaceArray(in: rewritten, key: "env", with: "[]")
            if isSample || !info.vault && info.kind == "exec" && !(info.pid.map(interesting.contains) ?? false) {
                rewritten = FixtureSanitizer.truncateArgs(in: rewritten)
            }
            out.append(rewritten)
            report.byKind[info.kind, default: 0] += 1
        }
        report.kept = out.count
        return (out, report)
    }

    /// Home, user-name and per-user temporary folder replacement in both `/` and `\/` spellings.
    func rewrite(_ line: String) -> String {
        var s = line
        let user = (home as NSString).lastPathComponent
        for (from, to) in [(home, replacementHome),
                           (home.replacingOccurrences(of: "/", with: "\\/"), replacementHome.replacingOccurrences(of: "/", with: "\\/"))] {
            s = s.replacingOccurrences(of: from, with: to)
        }
        func replace(_ pattern: String, _ template: String) {
            guard let re = try? NSRegularExpression(pattern: pattern) else { return }
            s = re.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: template)
        }
        if !user.isEmpty && user != "alice" {
            // A whole path component (`/bob/`, `\/bob\/`, `/bob"`, `/bob.plist`) or a whole string.
            replace("(?<=/)" + NSRegularExpression.escapedPattern(for: user) + #"(?=[/\\".]|$)"#, "alice")
            s = s.replacingOccurrences(of: "\"" + user + "\"", with: "\"alice\"")
        }
        // $TMPDIR / confstr folders: /private/var/folders/<xx>/<per-user id>, also spelled /var/folders/…
        // (the $TMPDIR value itself, as in the capture script's cp/ln/rm arguments).
        replace(#"(/(?:private\\?/)?var\\?/folders\\?/)[^/\\"]+(\\?/)[^/\\"]+"#, "$1xx$2alice")
        return s
    }

    static func int(_ v: Any?) -> Int? {
        switch v {
        case let i as Int: return i
        case let n as NSNumber: return n.intValue
        case let s as String: return Int(s)
        default: return nil
        }
    }

    static func collectPaths(_ v: Any, into out: inout [String]) {
        if let d = v as? [String: Any] {
            if let p = d["path"] as? String { out.append(p) }
            for (k, x) in d where k != "stat" { collectPaths(x, into: &out) }
        } else if let a = v as? [Any] {
            for x in a { collectPaths(x, into: &out) }
        }
    }

    /// Replaces the JSON array value of the first `"key":[...]` occurrence (string-aware scan).
    static func replaceArray(in line: String, key: String, with replacement: String) -> String {
        let bytes = Array(line.utf8)
        let needle = Array("\"\(key)\":".utf8)
        guard let start = find(needle, in: bytes) else { return line }
        var i = start + needle.count
        while i < bytes.count && bytes[i] == 0x20 { i += 1 }
        guard i < bytes.count, bytes[i] == UInt8(ascii: "[") else { return line }
        guard let end = matchingBracket(bytes, from: i) else { return line }
        let result = Array(bytes[..<i]) + Array(replacement.utf8) + Array(bytes[(end + 1)...])
        return String(decoding: result, as: UTF8.self)
    }

    /// `"args":["a","b",...]` → `"args":["a"]`.
    static func truncateArgs(in line: String) -> String {
        let bytes = Array(line.utf8)
        let needle = Array("\"args\":".utf8)
        guard let start = find(needle, in: bytes) else { return line }
        var i = start + needle.count
        while i < bytes.count && bytes[i] == 0x20 { i += 1 }
        guard i < bytes.count, bytes[i] == UInt8(ascii: "["), let end = matchingBracket(bytes, from: i) else { return line }
        // First element span.
        var j = i + 1
        while j < end && bytes[j] == 0x20 { j += 1 }
        var firstEnd = j
        if j < end && bytes[j] == UInt8(ascii: "\"") {
            var k = j + 1
            while k < end {
                if bytes[k] == UInt8(ascii: "\\") { k += 2; continue }
                if bytes[k] == UInt8(ascii: "\"") { break }
                k += 1
            }
            firstEnd = k + 1
        }
        let first = firstEnd > j ? Array(bytes[j..<firstEnd]) : []
        let result = Array(bytes[...i]) + first + Array(bytes[end...])
        return String(decoding: result, as: UTF8.self)
    }

    static func find(_ needle: [UInt8], in hay: [UInt8]) -> Int? {
        guard needle.count <= hay.count else { return nil }
        var i = 0
        while i <= hay.count - needle.count {
            if hay[i] == needle[0] && Array(hay[i..<(i + needle.count)]) == needle { return i }
            i += 1
        }
        return nil
    }

    static func matchingBracket(_ b: [UInt8], from open: Int) -> Int? {
        var depth = 0
        var inString = false
        var i = open
        while i < b.count {
            let c = b[i]
            if inString {
                if c == UInt8(ascii: "\\") { i += 2; continue }
                if c == UInt8(ascii: "\"") { inString = false }
            } else if c == UInt8(ascii: "\"") {
                inString = true
            } else if c == UInt8(ascii: "[") || c == UInt8(ascii: "{") {
                depth += 1
            } else if c == UInt8(ascii: "]") || c == UInt8(ascii: "}") {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return nil
    }
}
