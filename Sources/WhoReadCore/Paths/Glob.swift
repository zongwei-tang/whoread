import Foundation

/// Minimal, case-insensitive glob used for catalog file patterns and identity paths.
///
///   `*`  any run of characters except `/`
///   `**` any run of characters including `/`
///   `?`  one character except `/`
///
/// No character classes or braces: catalog data stays readable and the matcher stays obviously
/// correct.
public struct Glob: Hashable, Codable, Sendable, CustomStringConvertible {
    public let pattern: String
    private let tokens: [Token]

    private enum Token: Hashable, Sendable {
        case literal(Character)
        case star
        case doubleStar
        case question
    }

    public init(_ pattern: String) {
        self.pattern = pattern
        var tokens: [Token] = []
        let chars = Array(PathNormalizer.fold(pattern))
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if c == "*" {
                if i + 1 < chars.count && chars[i + 1] == "*" {
                    tokens.append(.doubleStar)
                    i += 2
                    // "**/" also matches zero directories: "a/**/b" matches "a/b".
                    continue
                }
                tokens.append(.star)
            } else if c == "?" {
                tokens.append(.question)
            } else {
                tokens.append(.literal(c))
            }
            i += 1
        }
        self.tokens = tokens
    }

    public init(from decoder: Decoder) throws {
        self.init(try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(pattern)
    }

    public var description: String { pattern }

    public var hasWildcards: Bool {
        tokens.contains { if case .literal = $0 { return false } else { return true } }
    }

    /// Matches a whole string (already folded or not; folding is applied here).
    public func matches(_ string: String) -> Bool {
        let s = Array(PathNormalizer.fold(string))
        // Iterative DP over (token index, string index) with memo; patterns are tiny.
        var memo = [Int: Bool]()
        func match(_ ti: Int, _ si: Int) -> Bool {
            let key = ti &* (s.count + 1) &+ si
            if let m = memo[key] { return m }
            var result: Bool
            if ti == tokens.count {
                result = si == s.count
            } else {
                switch tokens[ti] {
                case .literal(let c):
                    result = si < s.count && s[si] == c && match(ti + 1, si + 1)
                case .question:
                    result = si < s.count && s[si] != "/" && match(ti + 1, si + 1)
                case .star:
                    result = false
                    var k = si
                    while true {
                        if match(ti + 1, k) { result = true; break }
                        if k >= s.count || s[k] == "/" { break }
                        k += 1
                    }
                case .doubleStar:
                    result = false
                    // "**/" may match zero directories.
                    if ti + 1 < tokens.count, case .literal("/") = tokens[ti + 1], match(ti + 2, si) {
                        result = true
                    } else {
                        var k = si
                        while k <= s.count {
                            if match(ti + 1, k) { result = true; break }
                            k += 1
                        }
                    }
                }
            }
            memo[key] = result
            return result
        }
        return match(0, 0)
    }
}
