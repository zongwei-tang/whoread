import Foundation
import WhoReadCore

/// Turns a raw eslogger capture into a small fixture that is safe to commit.
///
/// Keeps:
/// - every event that touches the test vault, from the capture script's own process tree (`capturePID`)
///   or, except execs, from a system program whose line names only system paths and the vault (another
///   program's vault events would commit its bundle path and team id);
/// - fork/exec/exit events of the capture tree's vault processes and their ancestors (chain
///   reconstruction); never those of a system program outside the tree, whose ancestors may be anyone's;
/// - up to `samplePerKind` other events per event kind, only for kinds whose fields are all known, and
///   only if every path they carry (the process's, `dyld_exec_path` and a path-like argv[0] included) is
///   on Apple's sealed system volume after firmlink normalization, and they name no file outside a
///   path (structure coverage without personal data, device identifiers or installed-software names).
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
    /// The capture script's pid. Set: vault events of processes outside its tree are dropped unless they
    /// come from a system program, are not execs and name nothing but system paths and the vault; the
    /// ones kept bring no ancestry. Nil: every vault event is kept, with its ancestry.
    public var capturePID: Int32?

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
        /// Lines that are not UTF-8 (dropped).
        public var undecodableLines = 0
        /// Vault events of processes outside the capture script's tree (dropped).
        public var foreignVaultEvents = 0
    }

    /// Apple's sealed system volume, plus /Library/Apple (SIP-protected, written only by Apple's
    /// updates). Deliberately absent: /Applications/Utilities (Apple's utilities live in
    /// /System/Applications/Utilities; the data-volume folder holds third-party apps), /Library/Preferences
    /// (third-party file names there are the installed-app inventory), /private/var/db (lockdown records
    /// named by device UDID, DHCP leases by MAC address, per-app caches by bundle id or app name) and
    /// /private/etc (paths.d and manpaths.d name installed tools, resolver/ names VPN domains).
    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"]
    /// Places under the system prefixes that are not on the sealed volume (lowercase: compared case-folded,
    /// since APFS is case-insensitive): /usr/local; every other volume mounted under /System/Volumes (what
    /// is left there after firmlink normalization: Preboot paths start with the volume group UUID); and the
    /// data-volume directories firmlinked into the system tree (/usr/share/firmlinks), which hold caches,
    /// downloaded assets, device icons and third-party printer drivers.
    static let nonSystemPrefixes = ["/usr/local/", "/system/volumes/", "/system/library/caches/", "/system/library/assets/",
                                    "/system/library/assetsv2/", "/system/library/preinstalledassets/",
                                    "/system/library/preinstalledassetsv2/", "/system/library/speech/",
                                    "/system/library/coreservices/coretypes.bundle/contents/library/",
                                    "/usr/libexec/cups/", "/usr/share/snmp/"]
    /// Device nodes whose names say nothing about the machine. Not /dev/cu.* or /dev/tty.*: serial ports
    /// are named after paired Bluetooth devices.
    static let systemDevices: Set<String> = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty",
                                             "/dev/console", "/dev/ptmx", "/dev/dtracehelper", "/dev/autofs_nowait",
                                             "/dev/stdin", "/dev/stdout", "/dev/stderr"]
    /// Event kinds whose every field that can name a file the sanitizer knows (`path`, `dyld_exec_path`,
    /// argv[0], `nameKeys`). Other kinds name files elsewhere (`lookup`'s `relative_target`, `mount`'s
    /// statfs) and are never samples.
    static let sampleKinds: Set<String> = ["open", "close", "exec", "fork", "exit", "rename", "clone", "copyfile", "link",
                                           "unlink", "truncate", "create"]
    /// Keys holding a path in a string (besides the `path` of file objects).
    static let pathKeys: Set<String> = ["path", "dyld_exec_path"]
    /// Keys holding a bare file name next to its directory: rename/create `new_path.filename`, link
    /// `target_filename`, clone/copyfile `target_name`. Events with one are never samples.
    static let nameKeys: Set<String> = ["filename", "target_filename", "target_name"]

    /// Checked on the normalized path: `/System/Volumes/Data/…` is the user data volume, not the system.
    /// The line keeps the path as written, so a spelling that normalization would clean (`..`, `.`, `//`,
    /// possible in argv[0] and `dyld_exec_path`) is never system: its removed components are committed.
    static func isSystem(_ path: String, normalizer: PathNormalizer) -> Bool {
        if path.contains("//") || path.contains("/./") || path.contains("/../") || path.hasSuffix("/.") || path.hasSuffix("/..") {
            return false
        }
        let n = normalizer.normalize(path)
        if n.hasPrefix("/dev/") { return isAnonymousDevice(n) }
        let key = PathNormalizer.fold(n)
        return systemPrefixes.contains { n.hasPrefix($0) } && !nonSystemPrefixes.contains { key.hasPrefix($0) }
    }

    /// `systemDevices`, terminals `/dev/ttysNNN` and descriptors `/dev/fd/N`.
    static func isAnonymousDevice(_ n: String) -> Bool {
        if systemDevices.contains(n) { return true }
        for prefix in ["/dev/ttys", "/dev/fd/"] where n.hasPrefix(prefix) {
            let rest = n.utf8.dropFirst(prefix.utf8.count)
            return !rest.isEmpty && rest.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
        }
        return false
    }

    /// Splits a raw capture into lines. A line that is not UTF-8 is dropped and counted, so one odd
    /// byte does not fail the whole run (and leave the raw capture behind).
    public static func lines(from data: Data) -> (lines: [String], undecodable: Int) {
        var lines: [String] = []
        var undecodable = 0
        for chunk in data.split(separator: 0x0A, omittingEmptySubsequences: true) {
            if let line = String(data: Data(chunk), encoding: .utf8) { lines.append(line) } else { undecodable += 1 }
        }
        return (lines, undecodable)
    }

    public func sanitize(data: Data) -> (output: [String], report: Report) {
        let (lines, undecodable) = FixtureSanitizer.lines(from: data)
        var result = sanitize(lines: lines)
        result.report.inputLines += undecodable
        result.report.undecodableLines = undecodable
        return result
    }

    public func sanitize(lines: [String]) -> (output: [String], report: Report) {
        var report = Report()
        report.inputLines = lines.count
        let vaultVariants = [vault, vault.replacingOccurrences(of: "/", with: "\\/")]
        let normalizer = PathNormalizer()

        // Pass 1: parse what we need.
        struct Info {
            var kind: String; var pid: Int32?; var ppid: Int32?; var childPID: Int32?; var paths: [String]; var procPaths: [String]
            var names: Bool; var vault: Bool
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
            var names: [String] = []
            FixtureSanitizer.collectPaths(body, into: &paths, names: &names)
            // Samples keep argv[0], which is whatever the parent passed: checked when it looks like a path,
            // otherwise it must be the executable's name (launchd passes a job's ProgramArguments[0], which
            // can be any label, when its plist also sets Program).
            if kind == "exec", let argv0 = (body["args"] as? [Any])?.first as? String {
                if argv0.contains("/") {
                    paths.append(argv0)
                } else {
                    let exe = (((body["target"] as? [String: Any])?["executable"] as? [String: Any])?["path"] as? String) ?? ""
                    let name = argv0.hasPrefix("-") ? String(argv0.dropFirst()) : argv0
                    if name.isEmpty || name != (exe as NSString).lastPathComponent { names.append(argv0) }
                }
            }
            // The process object (executable, tty) is committed with the line too.
            var procPaths: [String] = []
            if let process { FixtureSanitizer.collectPaths(process, into: &procPaths, names: &names) }
            let touchesVault = vaultVariants.contains { line.contains($0) }
            // A reparented process reports ppid 1: use original_ppid, and never replace known ancestry.
            if let pid, let pp = (ppid == 1 ? originalPPID : ppid) ?? ppid, pp > 1, parent[pid] == nil { parent[pid] = pp }
            if let c = childPID, let pid { parent[c] = pid }
            infos.append(Info(kind: kind, pid: pid, ppid: ppid, childPID: childPID, paths: paths, procPaths: procPaths,
                              names: !names.isEmpty, vault: touchesVault))
        }
        // Vault events: the capture script's own tree, or system programs (mds, mdworker). Another program's
        // would commit its bundle path and team id, and make its exec a kept lifecycle event. A system
        // program outside the tree may have been started by anyone (an agent's node running /bin/zsh -c
        // 'cat …'): its line must name only system paths and the vault, an exec's command line is not
        // kept, and its ancestry never becomes lifecycle (the starter's fork, path, team id and argv).
        let vaultKey = PathNormalizer.fold(normalizer.normalize(vault))
        func inVault(_ path: String) -> Bool {
            let key = PathNormalizer.fold(normalizer.normalize(path))
            return key == vaultKey || key.hasPrefix(vaultKey + "/")
        }
        func isSystem(_ path: String) -> Bool { FixtureSanitizer.isSystem(path, normalizer: normalizer) }
        func descends(_ pid: Int32, from root: Int32) -> Bool {
            var p = pid
            for _ in 0..<64 {
                if p == root { return true }
                guard let pp = parent[p], pp > 1 else { return false }
                p = pp
            }
            return false
        }
        for i in infos.indices {
            guard let info = infos[i], info.vault else { continue }
            guard let root = capturePID, !(info.pid.map { descends($0, from: root) } ?? false) else {
                if let pid = info.pid { interesting.insert(pid) }
                continue
            }
            // Kept, but not made interesting: no ancestry.
            if !(info.kind != "exec" && !info.procPaths.isEmpty && info.procPaths.allSatisfy(isSystem)
                 && info.paths.allSatisfy({ isSystem($0) || inVault($0) })) {
                infos[i] = nil
                report.foreignVaultEvents += 1
            }
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
            } else if FixtureSanitizer.sampleKinds.contains(info.kind), !info.names, sampled[info.kind, default: 0] < samplePerKind,
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

    /// Strings under `pathKeys` into `out`, under `nameKeys` into `names`, at any depth.
    static func collectPaths(_ v: Any, into out: inout [String], names: inout [String]) {
        if let d = v as? [String: Any] {
            for (k, x) in d where k != "stat" {
                if let s = x as? String {
                    if pathKeys.contains(k) { out.append(s) } else if nameKeys.contains(k) { names.append(s) }
                } else {
                    collectPaths(x, into: &out, names: &names)
                }
            }
        } else if let a = v as? [Any] {
            for x in a { collectPaths(x, into: &out, names: &names) }
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
