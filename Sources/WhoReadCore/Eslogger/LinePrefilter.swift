import Foundation

/// Cheap byte-level test run on every eslogger line before JSON parsing.
///
/// eslogger has no target-path filter, so it emits every open on the system. Parsing all of them
/// would dominate CPU; instead one Aho–Corasick pass over the raw bytes decides whether a line
/// can possibly matter:
/// - process lifecycle (`"exec":`, `"fork":`, `"exit":`) → always parse (the process tree needs them)
/// - rename/clone/copyfile/link/exchangedata → always parse (split dir+name destinations;
///   parents of sensitive dirs may be moved); mount → always parse (on a parent, it hides them)
/// - create → its `existing_file` destination carries the full path, so it goes through the prefix
///   test like an open (every file creation on the system is a create event), or, at exactly a
///   proper ancestor of a prefix (a symlink planted at `~/.config`), through the ancestor test. A
///   `new_path` destination is a create another ES client denied (nothing was created): the parser
///   ignores it, so it gets no rule of its own
/// - `close` with `"modified":false` → drop
/// - any JSON string starting with a monitored prefix (or, on a create line, equal to an ancestor),
///   plain or under `/System/Volumes/Data` (ASCII case-insensitive, `/` or `\/` escaped, `"`, `\` and control
///   characters JSON-escaped) → parse. A non-ASCII path is spelled with each component in NFC and in
///   NFD (`spellings`); one with letters that have case (é and É are other bytes, and the scan folds
///   only ASCII) is matched by its longest ASCII fragment instead
/// - lines containing `\u` escapes → parse (non-ASCII paths may be escaped)
///
/// False positives only cost a parse; false negatives would lose events, so every rule errs open.
public final class LinePrefilter: @unchecked Sendable {
    public enum Verdict: Sendable { case parse, drop }

    private enum Tag: UInt8 {
        case lifecycle = 1
        case multiPath = 2
        case close = 3
        case notModified = 4
        case prefix = 5
        case escape = 6
        case create = 7
        /// A JSON string equal to an ancestor of a prefix: only matters on a create line.
        case ancestor = 9
    }

    private var automaton: AhoCorasick
    /// Set when some prefix can be matched neither exactly nor by an ASCII fragment: every file event
    /// must then be parsed.
    private var parseAllFileEvents = false
    /// Set when some ancestor cannot be matched exactly (`spellings`): every create is parsed.
    private var parseAllCreates = false

    /// `ancestors`: proper ancestors of the prefixes (`PathClassifier.ancestors`). Only a create at
    /// exactly one of them matters here (rename and clone lines are always parsed).
    public init(prefixes: [String], ancestors: [String] = []) {
        (automaton, parseAllFileEvents, parseAllCreates) = LinePrefilter.build(prefixes, ancestors)
    }

    public func update(prefixes: [String], ancestors: [String] = []) {
        (automaton, parseAllFileEvents, parseAllCreates) = LinePrefilter.build(prefixes, ancestors)
    }

    /// At most this many spellings of one path (see `spellings`).
    static let maxSpellings = 8

    /// Every byte spelling of `path` that exact needles must cover, or nil when they cannot be listed.
    /// An ASCII path is its only spelling (the scan folds ASCII case). APFS keeps a name in the normal
    /// form it was created in, and the folders of one path can come from different programs (Finder
    /// and Terminal differ): so every combination of each component in NFC and in NFD, up to
    /// `maxSpellings`. None when a non-ASCII character has case variants: APFS ignores case, but é and
    /// É are other bytes, so the spellings in which a path can be reported cannot be listed.
    static func spellings(_ path: String) -> [String]? {
        if path.utf8.allSatisfy({ $0 < 0x80 }) { return [path] }
        var out = [""]
        for (i, scalars) in path.unicodeScalars.split(separator: "/", omittingEmptySubsequences: false).enumerated() {
            let component = String(String.UnicodeScalarView(scalars))
            var forms: [String] = []
            for form in [component, component.precomposedStringWithCanonicalMapping, component.decomposedStringWithCanonicalMapping] {
                if form.unicodeScalars.contains(where: { !$0.isASCII && $0.properties.changesWhenCaseMapped }) { return nil }
                // By bytes: String equality would take NFC and NFD for one.
                if !forms.contains(where: { $0.utf8.elementsEqual(form.utf8) }) { forms.append(form) }
            }
            guard out.count * forms.count <= maxSpellings else { return nil }
            out = out.flatMap { head in forms.map { i == 0 ? $0 : head + "/" + $0 } }
        }
        return out
    }

    /// Needle for a prefix whose spellings cannot be listed (`spellings`): its longest ASCII fragment,
    /// which every spelling contains (given in NFC); over-matching just costs a parse.
    static func needle(for prefix: String) -> String? {
        if prefix.utf8.allSatisfy({ $0 < 0x80 }) { return prefix }
        var best = ""
        var current = ""
        for scalar in prefix.unicodeScalars {
            if scalar.isASCII {
                current.unicodeScalars.append(scalar)
            } else {
                if current.count > best.count { best = current }
                current = ""
            }
        }
        if current.count > best.count { best = current }
        return best.count >= 4 ? best : nil
    }

    /// How `s` appears inside a JSON string: `\` and `"` escaped, control characters as their short
    /// escape (`\n`, `\r`, `\t`, `\b`, `\f`) or `\u00XX` (a line with `\u` is parsed anyway). Escaping
    /// is per character, so it also holds for a fragment taken from the middle of a path.
    static func jsonEscaped(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{8}": out += "\\b"
            case "\u{C}": out += "\\f"
            case _ where scalar.value < 0x20: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    private static func build(_ prefixes: [String], _ ancestors: [String]) -> (AhoCorasick, Bool, Bool) {
        var parseAll = false
        var parseAllCreates = false
        var patterns: [(bytes: [UInt8], tag: UInt8)] = []
        func add(_ s: String, _ tag: Tag) {
            let bytes = Array(s.utf8).map(lower)
            if !bytes.isEmpty { patterns.append((bytes, tag.rawValue)) }
        }
        /// `s` as JSON writes it, with `/` plain and escaped as `\/` (eslogger has used both).
        func addJSON(_ s: String, before: String = "", after: String = "", _ tag: Tag) {
            let escaped = jsonEscaped(s)
            add(before + escaped + after, tag)
            if escaped.contains("/") { add(before + escaped.replacingOccurrences(of: "/", with: "\\/") + after, tag) }
        }
        for key in ["\"exec\":", "\"fork\":", "\"exit\":"] { add(key, .lifecycle) }
        // A mount on an ancestor of monitored prefixes (~/.config) names no prefix; mounts are rare.
        for key in ["\"rename\":", "\"clone\":", "\"copyfile\":", "\"link\":", "\"exchangedata\":", "\"mount\":"] {
            add(key, .multiPath)
        }
        add("\"create\":", .create)
        add("\"close\":", .close)
        add("\"modified\":false", .notModified)
        add("\"modified\": false", .notModified)
        add("\\u", .escape)
        for prefix in prefixes {
            if let listed = LinePrefilter.spellings(prefix) {
                // A whole path: anchor it to the start of a JSON string so that e.g. /Volumes does not
                // match every /System/Volumes/… path (process executables included), and ~/项目 not every
                // path in the home. The firmlinked spelling is added explicitly instead.
                for s in listed {
                    for v in [s] + PathNormalizer.defaultFirmlinkRoots.map({ $0 + s }) {
                        addJSON(v, before: "\"", .prefix)
                    }
                }
                continue
            }
            let nfc = prefix.precomposedStringWithCanonicalMapping
            guard let p = needle(for: nfc) else {
                parseAll = true
                continue
            }
            if nfc.utf8.starts(with: p.utf8) {
                // The start of the prefix: anchored like a whole path.
                for v in [p] + PathNormalizer.defaultFirmlinkRoots.map({ $0 + p }) {
                    addJSON(v, before: "\"", .prefix)
                }
            } else {
                // A fragment from the middle of the prefix can start mid-string: keep it unanchored.
                addJSON(p, .prefix)
            }
        }
        // An ancestor is matched as a whole JSON string, and only on a create line: `"/Users/alice"`
        // must not let every event in the home through, and opening (listing) the home or its
        // Library folder is frequent and never sensitive.
        for ancestor in ancestors {
            guard let listed = LinePrefilter.spellings(ancestor) else {
                parseAllCreates = true
                continue
            }
            for s in listed {
                for v in [s] + PathNormalizer.defaultFirmlinkRoots.map({ $0 + s }) {
                    addJSON(v, before: "\"", after: "\"", .ancestor)
                }
            }
        }
        return (AhoCorasick(patterns: patterns), parseAll, parseAllCreates)
    }

    @inline(__always)
    static func lower(_ b: UInt8) -> UInt8 { (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b }

    public func verdict(_ line: UnsafeRawBufferPointer) -> Verdict {
        var seen: UInt16 = 0 // bitmask of tags
        automaton.scan(line, transform: LinePrefilter.lower) { tag in
            seen |= UInt16(1) << tag
            // Lifecycle / multi-path lines are decided immediately.
            return tag == Tag.lifecycle.rawValue || tag == Tag.multiPath.rawValue
        }
        func has(_ t: Tag) -> Bool { seen & (1 << t.rawValue) != 0 }
        if has(.lifecycle) || has(.multiPath) { return .parse }
        if has(.create) && (has(.ancestor) || parseAllCreates) { return .parse }
        if has(.close) && has(.notModified) { return .drop }
        if has(.prefix) || has(.escape) || parseAllFileEvents { return .parse }
        return .drop
    }

    /// Cheap extraction of `"global_seq_num":<digits>` from a raw line (no JSON parse).
    public static func globalSequence(_ line: UnsafeRawBufferPointer) -> UInt64? {
        let key = Array("\"global_seq_num\":".utf8)
        guard line.count > key.count else { return nil }
        var i = 0
        let end = line.count - key.count
        while i <= end {
            if line[i] == key[0] {
                var match = true
                for j in 1..<key.count where line[i + j] != key[j] {
                    match = false
                    break
                }
                if match {
                    var k = i + key.count
                    while k < line.count && line[k] == 0x20 { k += 1 }
                    var value: UInt64 = 0
                    var digits = 0
                    while k < line.count, line[k] >= 0x30, line[k] <= 0x39 {
                        value = value &* 10 &+ UInt64(line[k] - 0x30)
                        k += 1
                        digits += 1
                    }
                    return digits > 0 ? value : nil
                }
            }
            i += 1
        }
        return nil
    }

    public func verdict(_ data: Data) -> Verdict {
        data.withUnsafeBytes { verdict($0) }
    }

    public func verdict(_ line: String) -> Verdict {
        verdict(Data(line.utf8))
    }
}

/// Byte-level Aho–Corasick automaton with a dense goto table (bytes are small, patterns few).
struct AhoCorasick {
    private var next: [[Int32]] = []     // state -> 256 transitions (full DFA after build)
    private var outputs: [[UInt8]] = []  // state -> tags ending here (incl. via failure links)

    init(patterns: [(bytes: [UInt8], tag: UInt8)]) {
        next = [Array(repeating: -1, count: 256)]
        outputs = [[]]
        for (bytes, tag) in patterns {
            var s = 0
            for b in bytes {
                let t = next[s][Int(b)]
                if t >= 0 {
                    s = Int(t)
                } else {
                    next.append(Array(repeating: -1, count: 256))
                    outputs.append([])
                    let ns = next.count - 1
                    next[s][Int(b)] = Int32(ns)
                    s = ns
                }
            }
            if !outputs[s].contains(tag) { outputs[s].append(tag) }
        }
        // BFS to compute failure links and complete the DFA.
        var fail = Array(repeating: 0, count: next.count)
        var queue: [Int] = []
        for b in 0..<256 {
            let t = next[0][b]
            if t >= 0 {
                fail[Int(t)] = 0
                queue.append(Int(t))
            } else {
                next[0][b] = 0
            }
        }
        var head = 0
        while head < queue.count {
            let s = queue[head]
            head += 1
            for tag in outputs[fail[s]] where !outputs[s].contains(tag) { outputs[s].append(tag) }
            for b in 0..<256 {
                let t = next[s][b]
                if t >= 0 {
                    fail[Int(t)] = Int(next[fail[s]][b])
                    queue.append(Int(t))
                } else {
                    next[s][b] = next[fail[s]][b]
                }
            }
        }
    }

    /// Calls `onMatch` for every tag found; stop early by returning true.
    func scan(_ buffer: UnsafeRawBufferPointer, transform: (UInt8) -> UInt8, onMatch: (UInt8) -> Bool) {
        var s = 0
        for raw in buffer {
            s = Int(next[s][Int(transform(raw))])
            let out = outputs[s]
            if !out.isEmpty {
                for tag in out where onMatch(tag) { return }
            }
        }
    }
}
