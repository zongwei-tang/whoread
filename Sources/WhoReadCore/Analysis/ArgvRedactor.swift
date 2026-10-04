import Foundation

/// Command lines are metadata, but they routinely carry secrets (`curl -H "Authorization: …"`,
/// `--token=…`, `https://user:token@host`, `AKIA…`). Agent detection uses the raw argv in memory;
/// anything stored, exported or shown goes through this redactor first. eslogger also emits the
/// full environment on exec; WhoRead never reads it.
///
/// AI agents run commands as `zsh -c "<whole command>"`, so an element containing whitespace is
/// tokenized like a shell command line and every token gets the same treatment as an argv element.
/// File paths are evidence and are kept wherever a secret is not expected.
public enum ArgvRedactor {
    public static let placeholder = "‹redacted›"

    /// Elements longer than this are cut (at a word boundary) before redaction. Stored values are
    /// much shorter anyway, argv can hold ~1 MB, and the regular expressions below are superlinear on
    /// adversarial input: one huge argument must not stall the analyzer for every event of its chain.
    static let maxElementLength = 1024
    /// Command lines inside command lines (`zsh -c "bash -c '…'"`) are unwrapped this deep, then
    /// treated as plain tokens (bounded recursion on the analyzer's stack).
    static let maxNesting = 4

    /// How the value after a flag is redacted.
    enum ValueRule: Equatable {
        /// The whole value.
        case secret
        /// The whole value unless it is a file path (`--key ~/.ssh/client.key` is evidence).
        case unlessPath
        /// Only what follows the first colon (`-u alice:hunter2` → `alice:‹redacted›`).
        case afterColon
        /// A header: redacted only if its name is sensitive.
        case header
        /// openssl pass phrase arguments: `pass:x` is redacted, `env:`/`file:`/`fd:` are kept.
        case opensslPass
        /// The value after `Bearer`: redacted unless it is an ordinary word.
        case bearer
    }

    /// Flags whose next argument is a secret, for every program.
    static let secretFlags: Set<String> = [
        "--token", "--password", "--passwd", "--pass", "--passphrase", "--secret", "--client-secret",
        "--api-key", "--apikey", "--access-token", "--refresh-token", "--id-token", "--session-token",
        "--auth-token", "--authorization", "--bearer", "--oauth2-bearer", "--secret-key", "--secret-access-key",
        "--key", "--private-key",
    ]

    /// A long flag or key containing one of these names a secret (`--http-password`, `GITHUB_TOKEN`)…
    static let strongFragments = ["password", "passwd", "passphrase", "secret", "token", "apikey", "api-key", "api_key",
                                  "authorization", "bearer", "private_key", "private-key", "privatekey"]
    /// …unless it only points at one.
    static let referenceSuffixes = ["-file", "_file", "-fd", "_fd", "-stdin", "-env", "_env", "-path", "_path", "-cmd",
                                    "-command", "-helper", "-id", "_id", "-url", "_url", "-type", "_type", "-name",
                                    "_name", "-length", "-ttl", "-expiry", "-expiration", "_expiry"]
    /// Keys that are secrets only when their value is not a file path.
    static let softKeys: Set<String> = ["key", "credential", "credentials", "cookie", "cookies", "session", "private",
                                        "pwd", "pw", "pass"]

    /// Values that are flags or switches, never secrets.
    static let switchValues: Set<String> = ["", "true", "false", "yes", "no", "on", "off", "0", "1", "-"]

    /// Programs that run another program (`sudo curl …`).
    static let wrappers: Set<String> = ["sudo", "doas", "env", "exec", "nohup", "time", "command", "builtin", "nice",
                                        "caffeinate", "arch", "timeout", "gtimeout", "xargs", "stdbuf", "chronic"]
    /// sudo options that take a value.
    static let sudoValueOptions: Set<String> = ["-u", "-g", "-U", "-C", "-D", "-h", "-p", "-r", "-t", "-T"]

    static let httpClients: Set<String> = ["curl", "wget", "http", "https", "xh", "httpie", "curlie"]
    static let mysqlClients: Set<String> = ["mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport",
                                            "mysqlshow", "mysqlcheck", "mysqlsh"]

    /// Program-specific flags: separate value (`-p value`) and attached value (`-pvalue`).
    static func programFlags(_ program: String, command: ArraySlice<String>) -> (next: [String: ValueRule], attached: [String: ValueRule]) {
        switch program {
        case _ where httpClients.contains(program):
            return (["-H": .header, "--header": .header, "--proxy-header": .header,
                     "-u": .afterColon, "--user": .afterColon, "-U": .afterColon, "--proxy-user": .afterColon,
                     "-E": .afterColon, "--cert": .afterColon, "-b": .unlessPath, "--cookie": .unlessPath],
                    ["-u": .afterColon, "-U": .afterColon, "-H": .header, "-b": .unlessPath])
        case _ where mysqlClients.contains(program):
            // `-p value` prompts and names a database; only the attached form carries the password.
            return ([:], ["-p": .secret])
        case "sshpass":
            return (["-p": .secret], ["-p": .secret])
        case "redis-cli", "valkey-cli", "keydb-cli":
            return (["-a": .secret], [:])
        case "security":
            // add-generic-password -w, unlock-keychain / create-keychain -p (a keychain path is kept).
            return (["-w": .secret, "-p": .unlessPath], [:])
        case "ssh-keygen":
            // New and old key passphrases.
            return (["-N": .secret, "-P": .secret], [:])
        case "keytool":
            return (["-storepass": .secret, "-keypass": .secret, "-srcstorepass": .secret, "-deststorepass": .secret,
                     "-srckeypass": .secret, "-destkeypass": .secret, "-new": .secret], [:])
        case "openssl":
            return (["-pass": .opensslPass, "-passin": .opensslPass, "-passout": .opensslPass, "-k": .secret, "-K": .secret], [:])
        case "ldapsearch", "ldapmodify", "ldapadd", "ldapdelete", "ldapwhoami", "ldappasswd":
            return (["-w": .secret], [:])
        case "mongo", "mongosh", "mongodump", "mongorestore", "mongoexport", "mongoimport":
            return (["-p": .secret], [:])
        case "az":
            return (["-p": .secret], [:])
        case "zip", "unzip", "zipcloak":
            return (["-P": .secret], [:])
        case "7z", "7za", "7zz", "7zr", "rar", "unrar":
            return ([:], ["-p": .secret])
        case "docker", "podman", "nerdctl", "helm", "oras", "skopeo", "buildah", "crane", "finch":
            return command.contains("login") ? (["-p": .secret], [:]) : ([:], [:])
        default:
            return ([:], [:])
        }
    }

    // MARK: - Patterns

    private static func regex(_ pattern: String) -> NSRegularExpression {
        // The patterns are constants; a typo is a programming error caught by the tests.
        try! NSRegularExpression(pattern: pattern)
    }

    static let headerNames = #"authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|private-token|x-[a-z0-9-]*-(?:token|key|secret)|[a-z-]*token|[a-z-]*secret"#
    /// An element that is a header: `Authorization: Bearer xyz`.
    /// Also `http.extraHeader=Authorization: Basic …` (git -c). A closing quote at the end is kept.
    static let wholeHeader = regex(#"(?i)^(\s*["']?(?:[a-z0-9_.\-]+=["']?)?)("# + headerNames + #")(\s*:\s*)\S.*?(["']?\s*)$"#)
    /// A quoted header inside a command line: `-H "Authorization: Bearer xyz"`.
    static let quotedHeader = regex(#"(?i)(["'])("# + headerNames + #")(\s*:\s*)[^"'\r\n]+"#)
    /// `scheme://user:password@host`.
    static let urlUserinfo = regex(#"(?i)\b([a-z][a-z0-9+.\-]*://[^/@\s:'"]*):([^/@\s'"]+)@"#)
    /// `scheme://<long token>@host`.
    static let urlTokenUserinfo = regex(#"(?i)\b([a-z][a-z0-9+.\-]*://)([^/@\s:'"]{20,})@"#)
    /// A quoted secret key and its quoted value (JSON, Python dicts, YAML): `{"client_secret":"x"}`.
    static let quotedPair = regex(#"(?i)(["'])([a-z0-9_.\-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|authorization|private[_-]?key|access[_-]?key|credentials?)[a-z0-9_.\-]*)(["']\s*:\s*["'])([^"'\\\r\n]+)(["'])"#)
    /// Sensitive query parameters: `?access_token=…`, `&sig=…`.
    static let queryParam = regex(#"(?i)([?&;][^=&\s#'"]*?(?:token|secret|passw|pwd|api[_-]?key|apikey|auth|sig|signature|credential|session|key|code)[^=&\s#'"]*=)[^&\s#'"]+"#)
    /// Well-known token formats, anywhere in an element.
    static let knownTokens = regex(
        #"(?<![A-Za-z0-9_])(?:(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|"#
            + #"glpat-[A-Za-z0-9_\-]{20,}|gldt-[A-Za-z0-9_\-]{20,}|xox[abprse]-[A-Za-z0-9\-]{10,}|sk-[A-Za-z0-9_\-]{20,}|"#
            + #"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_\-]{40,}|hf_[A-Za-z0-9]{30,}|"#
            + #"AIza[0-9A-Za-z_\-]{35}|hv[sbr]\.[A-Za-z0-9_\-]{20,}|ya29\.[0-9A-Za-z_\-]{20,}|dop_v1_[a-f0-9]{40,}|shp(?:at|ss|ca)_[a-fA-F0-9]{20,}|"#
            + #"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*)"#)

    private static func replace(_ re: NSRegularExpression, in s: String, with template: String) -> String {
        let range = NSRange(s.startIndex..., in: s)
        guard re.firstMatch(in: s, range: range) != nil else { return s }
        return re.stringByReplacingMatches(in: s, range: range, withTemplate: template)
    }

    // MARK: - Entry points

    public static func redact(_ argv: [String]?, maxArgs: Int = 8, maxLength: Int = 256) -> [String]? {
        guard let argv else { return nil }
        let kept = argv.prefix(maxArgs).map(bounded)
        // Every event stores its whole chain, and the same ancestors' argv repeat event after event.
        let key = RedactionCache.Key(argv: kept, count: argv.count, maxArgs: maxArgs, maxLength: maxLength)
        if let hit = cache.value(for: key) { return hit }
        var out = redactSequence(kept, firstIsProgram: true).map { truncate($0, maxLength) }
        if argv.count > maxArgs { out.append("…(+\(argv.count - maxArgs))") }
        cache.store(out, for: key)
        return out
    }

    static let cache = RedactionCache()

    /// A small memo of redacted argv prefixes (bounded; cleared when full).
    final class RedactionCache: @unchecked Sendable {
        struct Key: Hashable {
            var argv: [String]
            var count: Int
            var maxArgs: Int
            var maxLength: Int
        }
        private let lock = NSLock()
        private var entries: [Key: [String]] = [:]
        let capacity = 4096

        func value(for key: Key) -> [String]? {
            lock.lock(); defer { lock.unlock() }
            return entries[key]
        }

        var count: Int {
            lock.lock(); defer { lock.unlock() }
            return entries.count
        }

        func store(_ value: [String], for key: Key) {
            lock.lock(); defer { lock.unlock() }
            if entries.count >= capacity { entries.removeAll(keepingCapacity: true) }
            entries[key] = value
        }
    }

    /// Cuts an overlong element at the last word boundary before `maxElementLength` (a token cut in
    /// half would no longer look like the secret it is); a single overlong token is replaced.
    static func bounded(_ s: String) -> String {
        guard s.utf8.count > maxElementLength else { return s }
        let head = s.prefix(maxElementLength)
        if head.endIndex == s.endIndex { return s }
        if let space = head.lastIndex(where: \.isWhitespace) {
            return String(head[..<space]) + " …"
        }
        return placeholder + "…"
    }

    /// Redacts the argv of a stored process record.
    public static func redact(_ p: ProcessRecord) -> ProcessRecord {
        var r = p
        r.argv = redact(p.argv)
        return r
    }

    // MARK: - Sequences

    /// Redacts a sequence of arguments (an argv, or the tokens of a command line). `firstIsProgram`:
    /// element 0 is the program and is kept as is.
    static func redactSequence(_ tokens: [String], firstIsProgram: Bool, depth: Int = 0) -> [String] {
        var out = tokens
        var pending: ValueRule?
        var program: String?
        var flags: (next: [String: ValueRule], attached: [String: ValueRule]) = ([:], [:])
        var expectProgram = true
        var skipNext = false
        func startProgram(_ name: String, at i: Int) {
            program = name
            expectProgram = wrappers.contains(name)
            flags = programFlags(name, command: tokens[i...])
        }
        for i in tokens.indices {
            let raw = tokens[i]
            if i == 0 && firstIsProgram {
                startProgram(basename(raw), at: 0)
                continue
            }
            if isSeparator(raw) {
                pending = nil; program = nil; expectProgram = true; skipNext = false
                flags = ([:], [:])
                continue
            }
            // `cd /tmp; curl …`: the next word starts a new command.
            var endsCommand = false
            var word = raw
            if raw.count > 1 && raw.hasSuffix(";") && !raw.hasSuffix("\\;") && !isQuoted(raw) {
                word = String(raw.dropLast())
                endsCommand = true
            }
            defer {
                if endsCommand {
                    pending = nil; program = nil; expectProgram = true; skipNext = false
                    flags = ([:], [:])
                }
            }
            let (quote, t) = unquote(word)
            let suffix = endsCommand ? ";" : ""
            func emit(_ value: String) { out[i] = quote + value + quote + suffix }

            if let rule = pending {
                pending = nil
                if !(t.hasPrefix("-") && t.count > 1) {
                    emit(apply(rule, to: t, depth: depth))
                    continue
                }
            }
            if t.contains(where: \.isWhitespace) {
                // A command line passed as one argument (`zsh -c "…"`), or a quoted phrase in one.
                emit(depth < maxNesting ? redactCommandLine(t, depth: depth + 1) : redactToken(t))
                continue
            }
            if expectProgram {
                // `FOO=bar cmd`, `sudo -u root cmd`, `timeout 10 cmd`.
                if skipNext { skipNext = false; continue }
                if t.hasPrefix("-") {
                    if program == "sudo" || program == "doas", sudoValueOptions.contains(t) { skipNext = true }
                    emit(redactToken(t))
                    continue
                }
                if t.contains("=") { emit(redactToken(t)); continue }
                if !t.isEmpty && t.allSatisfy({ $0.isNumber || ".smhd".contains($0) }) { continue }
                startProgram(basename(t), at: i)
                continue
            }
            if t.hasPrefix("-") && t.count > 1 {
                // --flag=value
                if let eq = t.firstIndex(of: "="), t.hasPrefix("--") {
                    let flag = String(t[..<eq]), value = String(t[t.index(after: eq)...])
                    if let rule = flags.next[flag] ?? genericRule(forFlag: flag) {
                        emit(flag + "=" + apply(rule, to: value, depth: depth))
                        continue
                    }
                }
                if !t.contains("="), let rule = flags.next[t] ?? genericRule(forFlag: t) {
                    pending = rule
                    continue
                }
                if !t.hasPrefix("--"),
                   let prefix = flags.attached.keys.sorted(by: { $0.count > $1.count }).first(where: { t.hasPrefix($0) && t.count > $0.count }),
                   let rule = flags.attached[prefix] {
                    emit(prefix + apply(rule, to: String(t.dropFirst(prefix.count)), depth: depth))
                    continue
                }
                emit(redactToken(t))
                continue
            }
            // `Authorization: Bearer x`, `Authorization: Basic dXNlcjpwYXNz` split into words.
            if t.caseInsensitiveCompare("Bearer") == .orderedSame || t.caseInsensitiveCompare("Basic") == .orderedSame {
                pending = .bearer
                continue
            }
            // `aws configure set aws_secret_access_key X`, `npm config set //host/:_authToken X`.
            if isSecretKeyName(t) { pending = .unlessPath }
            emit(redactToken(t))
        }
        return out
    }

    /// A command line in one element: headers first (they span tokens), then token by token.
    static func redactCommandLine(_ s: String, depth: Int = 1) -> String {
        if let header = redactWholeHeader(s) { return header }
        var s = replace(quotedHeader, in: s, with: "$1$2$3" + placeholder)
        s = redactQuotedPairs(s)
        let pieces = tokenize(s)
        let words = pieces.filter { !$0.isSpace }.map(\.text)
        // One word that is the whole string (`print('a b')`: the quote starts mid-word): splitting
        // makes no progress, so it is a token, not a command line.
        if words.count == 1 && words[0] == s.trimmingCharacters(in: .whitespacesAndNewlines) {
            return redactToken(s)
        }
        var redacted = redactSequence(words, firstIsProgram: false, depth: depth)[...]
        var out = ""
        for piece in pieces {
            if piece.isSpace { out += piece.text } else { out += redacted.popFirst() ?? piece.text }
        }
        return out
    }

    // MARK: - Tokens

    /// An argument with no flag context, possibly a command line.
    static func redactFree(_ t: String, depth: Int) -> String {
        t.contains(where: \.isWhitespace) && depth < maxNesting ? redactCommandLine(t, depth: depth + 1) : redactToken(t)
    }

    /// One argument with no flag context.
    static func redactToken(_ t: String, depth: Int = 0) -> String {
        if let header = redactWholeHeader(t) { return header }
        if t.hasPrefix("pass:") && t.count > 5 { return "pass:" + placeholder }
        let t = redactQuotedPairs(t)
        // key=value, --flag=value, and nested `--from-literal=password=x`.
        if let eq = t.firstIndex(of: "="), eq != t.startIndex {
            let key = String(t[..<eq]), value = String(t[t.index(after: eq)...])
            if keyIsSecret(key, value: value) { return key + "=" + placeholder }
            // A URL (`https://h/cb?access_token=x&state=1`) is left whole to the URL rules below:
            // splitting it at its first "=" would hide the first query parameter from them.
            if depth == 0 && value.contains("=") && !value.contains("://") && !key.contains("://") {
                return key + "=" + redactToken(value, depth: 1)
            }
        }
        var s = replace(urlUserinfo, in: t, with: "$1:" + placeholder + "@")
        s = redactTokenUserinfo(s)
        s = replace(queryParam, in: s, with: "$1" + placeholder)
        s = replace(knownTokens, in: s, with: placeholder)
        if looksLikeHighEntropySecret(s) { return placeholder }
        return s
    }

    static func redactWholeHeader(_ s: String) -> String? {
        let range = NSRange(s.startIndex..., in: s)
        guard let m = wholeHeader.firstMatch(in: s, range: range),
              let lead = Range(m.range(at: 1), in: s), let name = Range(m.range(at: 2), in: s),
              let sep = Range(m.range(at: 3), in: s), let close = Range(m.range(at: 4), in: s) else { return nil }
        return String(s[lead]) + String(s[name]) + String(s[sep]) + placeholder + String(s[close])
    }

    /// `"password": "x"` → `"password": "‹redacted›"`, unless the key only refers to a secret
    /// (`"token_file": "/path"`) or the value is a path.
    static func redactQuotedPairs(_ s: String) -> String {
        let ns = s as NSString
        let matches = quotedPair.matches(in: s, range: NSRange(location: 0, length: ns.length))
        guard !matches.isEmpty else { return s }
        var out = s
        for m in matches.reversed() {
            guard let keyRange = Range(m.range(at: 2), in: s), let valueRange = Range(m.range(at: 4), in: out) else { continue }
            let key = s[keyRange].lowercased()
            let value = String(out[valueRange])
            if referenceSuffixes.contains(where: { key.hasSuffix($0) }) || looksLikePath(value) || switchValues.contains(value.lowercased()) {
                continue
            }
            out.replaceSubrange(valueRange, with: placeholder)
        }
        return out
    }

    static func redactTokenUserinfo(_ s: String) -> String {
        let range = NSRange(s.startIndex..., in: s)
        guard let m = urlTokenUserinfo.firstMatch(in: s, range: range), let info = Range(m.range(at: 2), in: s) else { return s }
        let userinfo = String(s[info])
        let classes = [userinfo.contains(where: \.isLowercase), userinfo.contains(where: \.isUppercase),
                       userinfo.contains(where: \.isNumber)].filter { $0 }.count
        guard classes >= 2 && userinfo.contains(where: \.isNumber) else { return s }
        return s.replacingCharacters(in: info, with: placeholder)
    }

    static func apply(_ rule: ValueRule, to value: String, depth: Int = maxNesting) -> String {
        switch rule {
        case .secret:
            return value.isEmpty ? value : placeholder
        case .unlessPath:
            return looksLikePath(value) || value.isEmpty ? value : placeholder
        case .afterColon:
            guard let colon = value.firstIndex(of: ":") else { return value }
            return String(value[...colon]) + placeholder
        case .header:
            return redactWholeHeader(value) ?? redactFree(value, depth: depth)
        case .opensslPass:
            if value.hasPrefix("env:") || value.hasPrefix("file:") || value.hasPrefix("fd:") || value == "stdin" { return value }
            if value.hasPrefix("pass:") { return "pass:" + placeholder }
            return placeholder
        case .bearer:
            let ordinary = value.count < 8 || value.allSatisfy { $0.isLowercase && $0.isLetter }
            return ordinary ? value : placeholder
        }
    }

    /// The rule for a flag no program table knows: names with a strong fragment carry a secret.
    static func genericRule(forFlag flag: String) -> ValueRule? {
        if secretFlags.contains(flag) { return .unlessPath }
        guard flag.hasPrefix("--") else { return nil }
        let name = flag.lowercased()
        if referenceSuffixes.contains(where: { name.hasSuffix($0) }) { return nil }
        return strongFragments.contains(where: { name.contains($0) }) ? .unlessPath : nil
    }

    static func keyIsSecret(_ rawKey: String, value: String) -> Bool {
        if switchValues.contains(value.lowercased()) { return false }
        var key = rawKey.lowercased()
        while key.hasPrefix("-") { key.removeFirst() }
        if key.isEmpty || key.contains(where: \.isWhitespace) { return false }
        // A URL whose path happens to contain "token" is not a key.
        if key.contains("://") || key.contains("?") || key.contains("&") { return false }
        if referenceSuffixes.contains(where: { key.hasSuffix($0) }) { return false }
        if strongFragments.contains(where: { key.contains($0) }) || key == "pass" { return true }
        // Soft names: `--key=hunter2` is a secret, `--credential-file-override=/path/sa.json` is evidence.
        if key.contains("session") && key.hasSuffix("id") { return false }
        let soft = softKeys.contains(key)
            || ["key", "credential", "credentials", "cookie"].contains(where: { key.hasSuffix("_" + $0) || key.hasSuffix("-" + $0) || key.hasSuffix("." + $0) })
            || key.contains("cookie") || key.contains("credential") || key.hasPrefix("private")
        return soft && !looksLikePath(value)
    }

    /// A positional argument naming a secret setting: `aws_secret_access_key`, `//host/:_authToken`.
    /// Plain words ("password" in a commit message) do not count.
    static func isSecretKeyName(_ t: String) -> Bool {
        guard !t.contains("="), !t.isEmpty, !t.contains("://"),
              (!t.contains("/") && !looksLikePath(t)) || t.contains(":") else { return false }
        guard t.contains(where: { "_.:".contains($0) }) else { return false }
        let last = t.lowercased().split(whereSeparator: { "/:.".contains($0) }).last.map(String.init) ?? ""
        if referenceSuffixes.contains(where: { last.hasSuffix($0) }) { return false }
        return strongFragments.contains(where: { last.contains($0) }) || last.hasSuffix("authtoken") || last.hasSuffix("auth_token")
    }

    static func looksLikePath(_ s: String) -> Bool {
        s.hasPrefix("/") || s.hasPrefix("~") || s.hasPrefix("./") || s.hasPrefix("../") || s.hasPrefix("$HOME/")
    }

    /// Long unbroken base64/hex-ish strings. Strings with `/` (AWS secret keys) need higher entropy
    /// so that relative paths survive.
    static func looksLikeHighEntropySecret(_ s: String) -> Bool {
        guard s.count >= 32, !looksLikePath(s), !s.contains(where: \.isWhitespace) else { return false }
        if s.contains(".") && !s.hasPrefix("eyJ") { return false }
        var classes = 0
        if s.contains(where: \.isLowercase) { classes += 1 }
        if s.contains(where: \.isUppercase) { classes += 1 }
        if s.contains(where: \.isNumber) { classes += 1 }
        guard classes >= 3, s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-_+=/".contains($0)) }) else { return false }
        if s.contains("/") { return shannonEntropy(s) >= 4.5 }
        return true
    }

    static func shannonEntropy(_ s: String) -> Double {
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return -counts.values.reduce(0) { acc, c in
            let p = Double(c) / n
            return acc + p * log2(p)
        }
    }

    // MARK: - Lexing

    struct Piece {
        var text: String
        var isSpace: Bool
    }

    /// Splits a command line into words and whitespace runs, keeping quotes inside words.
    static func tokenize(_ s: String) -> [Piece] {
        var pieces: [Piece] = []
        var current = ""
        var quote: Character?
        var escaped = false
        var space = ""
        for c in s {
            if escaped { current.append(c); escaped = false; continue }
            if c == "\\" && quote != "'" { current.append(c); escaped = true; continue }
            if let q = quote {
                current.append(c)
                if c == q { quote = nil }
                continue
            }
            if c.isWhitespace {
                if !current.isEmpty { pieces.append(Piece(text: current, isSpace: false)); current = "" }
                space.append(c)
                continue
            }
            if !space.isEmpty { pieces.append(Piece(text: space, isSpace: true)); space = "" }
            if c == "\"" || c == "'" { quote = c }
            current.append(c)
        }
        if !current.isEmpty { pieces.append(Piece(text: current, isSpace: false)) }
        if !space.isEmpty { pieces.append(Piece(text: space, isSpace: true)) }
        return pieces
    }

    static func isSeparator(_ t: String) -> Bool {
        ["&&", "||", ";", "|", "&", "(", ")", "{", "}", "then", "do", "else", "$("].contains(t)
    }

    static func isQuoted(_ t: String) -> Bool {
        guard t.count >= 2, let f = t.first, f == "\"" || f == "'" else { return false }
        return t.last == f
    }

    /// Strips one level of matching quotes: `"abc"` → (`"`, `abc`).
    static func unquote(_ t: String) -> (String, String) {
        guard isQuoted(t), let f = t.first else { return ("", t) }
        return (String(f), String(t.dropFirst().dropLast()))
    }

    static func basename(_ s: String) -> String {
        let (_, t) = unquote(s)
        return t.split(separator: "/").last.map(String.init) ?? t
    }

    static func truncate(_ s: String, _ n: Int) -> String {
        s.count > n ? String(s.prefix(n)) + "…" : s
    }
}
