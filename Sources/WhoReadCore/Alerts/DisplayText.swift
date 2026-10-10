import Foundation

/// File names, process names, bundle names and argv are attacker-controlled: any program can name
/// itself `Terminal\n\n\u{202E}…`. Everything WhoRead shows a person (question and alert text,
/// notification banners, the menu, the app's tables, the CLI's tables and tail) goes through here,
/// so such a name can neither forge or hide lines, nor reorder text, nor send a terminal escape
/// sequence, nor push the real path or the AI agent out of view. JSON output stays exact (JSON
/// escaping covers it); identifiers (rule subjects, keys, paths sent back to the daemon) are never
/// passed through this.
///
/// Hidden characters become visible `\u{…}` escapes (as in the daemon's log): C0/C1 controls and
/// DEL (`.control`), bidi overrides and isolates, zero-width characters, U+FEFF, U+061C and other
/// invisible formatting characters (`.format`), U+2028/U+2029, private-use characters (U+F8FF
/// renders as the Apple logo on macOS), and the other default-ignorable characters, which render as
/// nothing or as blank space (Hangul fillers such as U+3164, the combining grapheme joiner, variation
/// selectors; the emoji presentation selectors U+FE0E/U+FE0F only pick a glyph and stay). Everything
/// else, Chinese included, is kept.
public enum DisplayText {
    /// Longest app, process, agent or category name shown. A long lookalike name cannot fill a
    /// banner by itself.
    public static let nameLimit = 64
    /// Longest path in a headline or banner. The middle is cut, so the file name stays visible.
    public static let pathLimit = 160
    /// Longest call chain in one line ("launchd → … → cat"), cut in the middle.
    public static let chainLimit = 400
    public static let ellipsis: Unicode.Scalar = "…"

    /// True for a character that is invisible or changes how other text is laid out.
    public static func isHidden(_ u: Unicode.Scalar) -> Bool {
        switch u.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate: return true
        default: return u.properties.isDefaultIgnorableCodePoint && u.value != 0xFE0E && u.value != 0xFE0F
        }
    }

    /// `s` with hidden characters escaped. `limit` caps the result (escapes included) at that many
    /// Unicode scalars, ending in "…" (`keepEnd`: the "…" goes in the middle and the end is kept).
    /// An escape is never cut. Escaping twice changes nothing.
    public static func escaped(_ s: String, limit: Int? = nil, keepEnd: Bool = false) -> String {
        let scalars = s.unicodeScalars
        if !scalars.contains(where: isHidden), limit.map({ scalars.count <= $0 }) ?? true { return s }
        // Pieces: one scalar each, or one whole escape.
        var pieces: [String.UnicodeScalarView] = []
        pieces.reserveCapacity(scalars.count)
        var total = 0
        for u in scalars {
            let piece = isHidden(u) ? "\\u{\(String(u.value, radix: 16))}".unicodeScalars : String.UnicodeScalarView([u])
            total += piece.count
            pieces.append(piece)
        }
        var out = String.UnicodeScalarView()
        guard let limit, total > limit else {
            pieces.forEach { out.append(contentsOf: $0) }
            return String(out)
        }
        let budget = max(limit - 1, 0)
        // Whole pieces from the front within `n` scalars.
        func head(_ n: Int) -> (Int, Int) {
            var used = 0, count = 0
            for p in pieces { guard used + p.count <= n else { break }; used += p.count; count += 1 }
            return (count, used)
        }
        guard keepEnd else {
            pieces.prefix(head(budget).0).forEach { out.append(contentsOf: $0) }
            out.append(ellipsis)
            return String(out)
        }
        let (front, used) = head(budget / 3)
        var back: [String.UnicodeScalarView] = []
        var left = budget - used
        for p in pieces.dropFirst(front).reversed() {
            guard p.count <= left else { break }
            left -= p.count
            back.append(p)
        }
        pieces.prefix(front).forEach { out.append(contentsOf: $0) }
        out.append(ellipsis)
        back.reversed().forEach { out.append(contentsOf: $0) }
        return String(out)
    }

    /// An app, process, agent or category name. Runs of spaces (U+0020, no-break, ideographic and
    /// the other space separators) are shown as one space: within the cap, a name could otherwise
    /// push the rest of a banner line out of view with blanks (an ideographic space is two columns
    /// wide), or fake the columns of a CLI table ("Terminal  SSH keys  read").
    public static func name(_ s: String) -> String { escaped(collapsingSpaces(s), limit: nameLimit) }

    static func collapsingSpaces(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var changed = false
        var afterSpace = false
        for u in s.unicodeScalars {
            guard u.properties.generalCategory == .spaceSeparator else {
                out.append(u)
                afterSpace = false
                continue
            }
            if afterSpace || u != " " { changed = true }
            if !afterSpace { out.append(" ") }
            afterSpace = true
        }
        return changed ? String(out) : s
    }

    /// A path in a headline or banner (abbreviate it first: `~/…` needs the raw path).
    public static func path(_ s: String) -> String { escaped(s, limit: pathLimit, keepEnd: true) }

    /// Text WhoRead laid out in lines itself (a status report, an error with a hint below it): each
    /// line escaped, the line breaks kept. Values inside it should be escaped where they are put in.
    public static func lines(_ s: String) -> String {
        s.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: false)
            .map { escaped(String(String.UnicodeScalarView($0))) }.joined(separator: "\n")
    }

    /// "Claude Code → zsh → cat": the chain trimmed to the responsible entity (`displayString`),
    /// each name escaped and capped, the whole cut in the middle when long (the leaf stays).
    public static func chain(_ chain: [ChainLink], responsible: ResponsibleEntity) -> String {
        var names = chain.trimmed(to: responsible).map { name($0.name) }
        if names.isEmpty { names = [name(responsible.displayName)] } else { names[0] = name(responsible.displayName) }
        return escaped(names.joined(separator: " → "), limit: chainLimit, keepEnd: true)
    }
}
