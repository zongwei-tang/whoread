import Foundation

/// Cheap byte-level test run on every eslogger line before JSON parsing.
///
/// eslogger has no target-path filter, so it emits every open on the system. Parsing all of them
/// would dominate CPU; instead one Aho–Corasick pass over the raw bytes decides whether a line
/// can possibly matter:
/// - process lifecycle (`"exec":`, `"fork":`, `"exit":`) → always parse (the process tree needs them)
/// - rename/clone/link/exchangedata → always parse (parents of sensitive dirs may be moved)
/// - `close` with `"modified":false` → drop
/// - anything containing a monitored prefix (ASCII case-insensitive, `/` or `\/` escaped) → parse
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
    }

    private var automaton: AhoCorasick
    /// Set when some prefix has no usable ASCII fragment: every file event must then be parsed.
    private var parseAllFileEvents = false

    public init(prefixes: [String]) {
        (automaton, parseAllFileEvents) = LinePrefilter.build(prefixes)
    }

    public func update(prefixes: [String]) {
        (automaton, parseAllFileEvents) = LinePrefilter.build(prefixes)
    }

    /// Needle for a prefix. Non-ASCII prefixes (e.g. a project root under a Chinese folder name)
    /// may appear in NFD, NFC or with different case in the raw JSON, so use their longest ASCII
    /// fragment instead; over-matching just costs a parse.
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

    private static func build(_ prefixes: [String]) -> (AhoCorasick, Bool) {
        var parseAll = false
        var patterns: [(bytes: [UInt8], tag: UInt8)] = []
        func add(_ s: String, _ tag: Tag) {
            let bytes = Array(s.utf8).map(lower)
            if !bytes.isEmpty { patterns.append((bytes, tag.rawValue)) }
        }
        for key in ["\"exec\":", "\"fork\":", "\"exit\":"] { add(key, .lifecycle) }
        for key in ["\"rename\":", "\"clone\":", "\"link\":", "\"exchangedata\":"] { add(key, .multiPath) }
        add("\"close\":", .close)
        add("\"modified\":false", .notModified)
        add("\"modified\": false", .notModified)
        add("\\u", .escape)
        for prefix in prefixes {
            guard let p = needle(for: prefix) else {
                parseAll = true
                continue
            }
            add(p, .prefix)
            if p.contains("/") { add(p.replacingOccurrences(of: "/", with: "\\/"), .prefix) }
        }
        return (AhoCorasick(patterns: patterns), parseAll)
    }

    @inline(__always)
    static func lower(_ b: UInt8) -> UInt8 { (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b }

    public func verdict(_ line: UnsafeRawBufferPointer) -> Verdict {
        var seen: UInt8 = 0 // bitmask of tags
        automaton.scan(line, transform: LinePrefilter.lower) { tag in
            seen |= 1 << tag
            // Lifecycle / multi-path lines are decided immediately.
            return tag == Tag.lifecycle.rawValue || tag == Tag.multiPath.rawValue
        }
        func has(_ t: Tag) -> Bool { seen & (1 << t.rawValue) != 0 }
        if has(.lifecycle) || has(.multiPath) { return .parse }
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
