import Foundation

/// Command lines are metadata, but they routinely carry secrets (`curl -H "Authorization: …"`,
/// `--token=…`, `AKIA…`). Agent detection uses the raw argv in memory; anything stored, exported
/// or shown goes through this redactor first. eslogger also emits the full environment on exec;
/// WhoRead never reads it.
public enum ArgvRedactor {
    public static let placeholder = "‹redacted›"

    static let secretFlags: Set<String> = [
        "--token", "--password", "--passwd", "--pass", "--passphrase", "--secret", "--client-secret",
        "--api-key", "--apikey", "--access-token", "--auth", "--auth-token", "--authorization", "--key",
        "--private-key", "--bearer", "-H", "--header", "-u", "--user", "--oauth2-bearer", "--cookie", "-b",
    ]

    static let secretKeyFragments = ["token", "secret", "password", "passwd", "pwd", "apikey", "api_key", "api-key",
                                     "auth", "credential", "private", "session", "cookie", "bearer"]

    static let tokenPrefixes = ["AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
                                "sk-", "sk_live_", "rk_live_", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "AIza", "ya29.",
                                "npm_", "pypi-", "hf_", "eyJ"]

    public static func redact(_ argv: [String]?, maxArgs: Int = 8, maxLength: Int = 256) -> [String]? {
        guard let argv else { return nil }
        var out: [String] = []
        var redactNext = false
        for (i, raw) in argv.enumerated() {
            if i >= maxArgs {
                out.append("…(+\(argv.count - maxArgs))")
                break
            }
            if redactNext {
                out.append(placeholder)
                redactNext = false
                continue
            }
            if i > 0 && secretFlags.contains(raw) {
                out.append(raw)
                redactNext = true
                continue
            }
            out.append(truncate(redactOne(raw, isArgv0: i == 0), maxLength))
        }
        return out
    }

    static func redactOne(_ arg: String, isArgv0: Bool) -> String {
        if isArgv0 { return arg }
        // "Authorization: Bearer xyz", "Cookie: a=b"
        if let colon = arg.firstIndex(of: ":"), arg[..<colon].count < 40 {
            let name = arg[..<colon].lowercased()
            if secretKeyFragments.contains(where: { name.contains($0) }) {
                return String(arg[...colon]) + " " + placeholder
            }
        }
        // --token=xyz, API_KEY=xyz
        if let eq = arg.firstIndex(of: "=") {
            let key = arg[..<eq].lowercased()
            if secretKeyFragments.contains(where: { key.contains($0) }) {
                return String(arg[...eq]) + placeholder
            }
        }
        // Bare tokens.
        let trimmed = arg.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
        if tokenPrefixes.contains(where: { trimmed.hasPrefix($0) }) && trimmed.count >= 16 && !trimmed.contains("/") {
            return placeholder
        }
        if looksLikeHighEntropySecret(trimmed) { return placeholder }
        return arg
    }

    /// Long unbroken base64/hex-ish strings without path separators.
    static func looksLikeHighEntropySecret(_ s: String) -> Bool {
        guard s.count >= 32, !s.contains("/"), !s.contains(" "), !s.contains(".") || s.hasPrefix("eyJ") else { return false }
        var classes = 0
        if s.contains(where: \.isLowercase) { classes += 1 }
        if s.contains(where: \.isUppercase) { classes += 1 }
        if s.contains(where: \.isNumber) { classes += 1 }
        return classes >= 3 && s.allSatisfy { $0.isLetter || $0.isNumber || "-_+=".contains($0) }
    }

    static func truncate(_ s: String, _ n: Int) -> String {
        s.count > n ? String(s.prefix(n)) + "…" : s
    }

    /// Redacts the argv of a stored process record.
    public static func redact(_ p: ProcessRecord) -> ProcessRecord {
        var r = p
        r.argv = redact(p.argv)
        return r
    }
}
