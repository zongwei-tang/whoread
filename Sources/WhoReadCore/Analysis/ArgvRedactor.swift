import Foundation

/// Command lines are metadata, but they routinely carry secrets (`curl -H "Authorization: …"`,
/// `--token=…`, `https://user:token@host`, `AKIA…`). Agent detection uses the raw argv in memory;
/// anything stored, exported or shown goes through this redactor first. eslogger also emits the
/// full environment on exec; WhoRead never reads it.
///
/// AI agents run commands as `zsh -c "<whole command>"`, so an element containing whitespace is
/// tokenized like a shell command line and every token gets the same treatment as an argv element.
/// File paths are evidence and are kept wherever a secret is not expected. What a command line
/// writes (echo/printf words sent to a file or a pipe, heredoc bodies written by cat/tee or into a
/// file, here-strings) is file contents, not metadata: it is redacted, and the redirect's target kept.
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
    /// `//user:password@host` with no scheme (`mount -t smbfs //bob:pw@nas/share`).
    static let bareUserinfo = regex(#"(^|[\s='"(])(//[^/@\s:'"]+):([^/@\s'"]+)@"#)
    /// `scheme://<long token>@host`.
    static let urlTokenUserinfo = regex(#"(?i)\b([a-z][a-z0-9+.\-]*://)([^/@\s:'"]{20,})@"#)
    /// A quoted secret key and its quoted value (JSON, Python dicts, YAML): `{"client_secret":"x"}`,
    /// also with escaped quotes (`"{\"password\":\"x\"}"` in a shell command) and `auth` keys
    /// (`{"auths":{"ghcr.io":{"auth":"<base64 user:password>"}}}`, `basic_auth`; not `author`).
    /// `pass` and `pwd` keys as for key=value (`{"user":"bob","pass":"x"}`, `"db_pwd"`; not `bypass`,
    /// `compass` or `passport`).
    static let quotedPair = regex(#"(?i)(\\?["'])([a-z0-9_.\-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|authorization|private[_-]?key|access[_-]?key|credentials?)[a-z0-9_.\-]*|(?:[a-z0-9_.\-]*[_.\-])?(?:auth|pass|pwd))(\\?["']\s*:\s*\\?["'])([^"'\\\r\n]+)(\\?["'])"#)
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
    /// element 0 is the program and is kept as is. `lineStarts`: indices of tokens that begin a new
    /// line of a command line (a new command, or a heredoc's body and end).
    static func redactSequence(_ tokens: [String], firstIsProgram: Bool, depth: Int = 0, lineStarts: Set<Int> = []) -> [String] {
        var out = tokens
        var pending: ValueRule?
        var program: String?
        var flags: (next: [String: ValueRule], attached: [String: ValueRule]) = ([:], [:])
        var expectProgram = true
        var skipNext = false
        // Data a command writes (privacy-2): echo/printf words whose output goes to a file or a pipe,
        // here-strings, and heredoc bodies written by cat/tee or into a file. A file's contents are
        // never stored; where they went (the redirect's target) is kept.
        var dataMode = false
        var dataSeen = false
        var keepNext = false
        var hereString = false
        var heredoc: (delimiter: String?, redactBody: Bool, inBody: Bool)?
        var commandStart = 0
        // `>FILE echo …`: standard output redirected before the program word.
        var outputBeforeProgram = false
        // Redirects, heredocs and pipes mean something only in a command line, not in an argv.
        let shell = !firstIsProgram
        func resetCommand(at i: Int) {
            pending = nil; program = nil; expectProgram = true; skipNext = false
            flags = ([:], [:])
            dataMode = false; dataSeen = false; keepNext = false; hereString = false; outputBeforeProgram = false
            commandStart = i
        }
        func startProgram(_ name: String, at i: Int) {
            program = name
            expectProgram = wrappers.contains(name)
            flags = programFlags(name, command: tokens[i...])
            if shell && dataWriters.contains(name) {
                dataMode = outputBeforeProgram || writesOutput(tokens, after: i, lineStarts: lineStarts)
                dataSeen = false
            }
        }
        for i in tokens.indices {
            let raw = tokens[i]
            if i == 0 && firstIsProgram {
                startProgram(basename(raw), at: 0)
                continue
            }
            if let h = heredoc {
                if h.delimiter == nil {
                    // `<< EOF`: this word is the delimiter (still redacted like any word).
                    heredoc?.delimiter = heredocDelimiter(raw)
                    out[i] = redactToken(raw)
                    continue
                }
                if !h.inBody && lineStarts.contains(i) { heredoc?.inBody = true }
                if heredoc?.inBody == true {
                    if lineStarts.contains(i) && raw == h.delimiter {
                        // The delimiter line ends the command.
                        out[i] = redactToken(raw)
                        heredoc = nil
                        resetCommand(at: i + 1)
                        continue
                    }
                    if h.redactBody {
                        out[i] = placeholder
                        continue
                    }
                    // A script read from the heredoc (`python3 - <<EOF`): its lines are words with no
                    // program of their own.
                    if lineStarts.contains(i) {
                        pending = nil; program = nil; expectProgram = false; skipNext = false; flags = ([:], [:])
                    }
                }
            } else if lineStarts.contains(i) {
                resetCommand(at: i)
            }
            if isSeparator(raw) {
                resetCommand(at: i + 1)
                continue
            }
            // A line continuation (`--password \` + newline + value) is not a word.
            if raw.first == "\\" && raw.count > 1 && raw.dropFirst().allSatisfy(\.isNewline) { continue }
            // `cd /tmp; curl …`: the next word starts a new command.
            var endsCommand = false
            var word = raw
            if raw.count > 1 && raw.hasSuffix(";") && !raw.hasSuffix("\\;") && !isQuoted(raw) {
                word = String(raw.dropLast())
                endsCommand = true
            }
            defer {
                if endsCommand { resetCommand(at: i + 1) }
            }
            let (quote, t) = unquote(word)
            let suffix = endsCommand ? ";" : ""
            func emit(_ value: String) { out[i] = quote + value + quote + suffix }

            // Redirects: the operator and its target are kept (`> FILE`, `2>/dev/null`). Shell syntax
            // is in single words (an element with spaces is a command line of its own, below).
            if keepNext {
                keepNext = false
                emit(redactToken(t))
                continue
            }
            // A here-string is data, whatever it holds: `<<<'machine … password x'` is one word with
            // spaces in it.
            if shell && quote.isEmpty && t.hasPrefix("<<<") {
                if t.count > 3 { emit("<<<" + placeholder) } else { hereString = true }
                continue
            }
            let shellWord = shell && quote.isEmpty && !t.contains(where: \.isWhitespace)
            if shellWord, t.hasPrefix("<<") {
                let name = heredocDelimiter(String(t.dropFirst(2)))
                let sink = ["cat", "tee"].contains(program ?? "") || writesOutput(tokens, after: commandStart, lineStarts: lineStarts)
                heredoc = (name.isEmpty ? nil : name, sink, false)
                continue
            }
            if hereString {
                hereString = false
                emit(placeholder)
                continue
            }
            if shellWord, let r = redirect(in: t) {
                if dataMode && !r.data.isEmpty {
                    out[i] = placeholder + r.operatorAndTarget + suffix
                } else if !r.data.isEmpty {
                    out[i] = redactToken(r.data) + r.operatorAndTarget + suffix
                }
                if r.target.isEmpty && !r.duplicatesDescriptor { keepNext = true }
                if program == nil && r.isStandardOutput && !r.duplicatesDescriptor && r.data.isEmpty { outputBeforeProgram = true }
                continue
            }
            if dataMode {
                // `echo -n …`: echo's own options, before the first word of data.
                if !dataSeen && program == "echo" && t.count > 1 && t.hasPrefix("-") && t.dropFirst().allSatisfy({ "neE".contains($0) }) {
                    continue
                }
                dataSeen = true
                // `pw|tee FILE`: the data ends at a pipe in the word, and what follows it is a command
                // of its own.
                if quote.isEmpty, let pipe = unquotedPipe(in: t) {
                    let before = String(t[..<pipe.lowerBound]), after = String(t[pipe.upperBound...])
                    out[i] = (before.isEmpty ? "" : redactedData(before)) + String(t[pipe]) + redactToken(after) + suffix
                    resetCommand(at: i + 1)
                    if !after.isEmpty && !after.contains("=") { startProgram(basename(after), at: i) }
                    continue
                }
                // `(echo pw) > FILE`: the subshell's closing parenthesis is not data.
                let parens = quote.isEmpty ? closingParentheses(in: t) : 0
                emit(parens == t.count ? t : redactedData(String(t.dropLast(parens))) + String(repeating: ")", count: parens))
                continue
            }

            if let rule = pending {
                // `key = value`, `key : value` (INI, YAML, a heredoc): the separator is not the value.
                if quote.isEmpty && (t == "=" || t == ":") { continue }
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
                // `(echo …) > FILE`: a subshell's parenthesis is not part of the program's name.
                startProgram(basename(String(t.drop { $0 == "(" })), at: i)
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
            // `aws configure set aws_secret_access_key X`, `npm config set //host/:_authToken X`;
            // `password = X` (INI, a heredoc) when a lone "=" or ":" follows.
            if isSecretKeyName(t) || (i + 1 < tokens.count && ["=", ":"].contains(tokens[i + 1]) && namesSecret(t)) {
                pending = .unlessPath
            } else if ["password", "passwd"].contains(t.lowercased()), i >= commandStart + 2,
                      tokens[i - 2].lowercased() == "login",
                      tokens[commandStart..<i].contains(where: { ["machine", "default"].contains($0.lowercased()) }) {
                // A netrc line: `machine HOST login USER password SECRET`.
                pending = .secret
            }
            emit(redactToken(t))
        }
        return out
    }

    /// A word of data replaced, its quotes kept (`'pw'` → `'‹redacted›'`).
    static func redactedData(_ word: String) -> String {
        let (quote, _) = unquote(word)
        return quote + placeholder + quote
    }

    /// Programs whose words are data (`echo pw > FILE`, `printf … | git credential approve`).
    static let dataWriters: Set<String> = ["echo", "printf", "print"]

    /// True when the command starting after `start` sends its standard output to a file
    /// (`>`, `>>`, `1>`, `&>`, `>|`, attached or not) or into a pipe (`|`, also inside a word:
    /// `pw|tee FILE`), before the command ends. Inside a `{ …; }` or `( … )` group the group's own
    /// redirect or pipe counts too (`{ echo pw; } > FILE`): the rest of the line is searched.
    static func writesOutput(_ tokens: [String], after start: Int, lineStarts: Set<Int>) -> Bool {
        let grouped = openGroups(tokens, through: start, lineStarts: lineStarts) > 0
        var k = start + 1
        while k < tokens.count {
            let t = tokens[k]
            if lineStarts.contains(k) { return false }
            if t == "|" || t == "|&" { return true }
            if isSeparator(t) && !grouped { return false }
            let word = !isQuoted(t) && !t.contains(where: \.isWhitespace)
            if word, let r = redirect(in: t), r.isStandardOutput { return true }
            if word, unquotedPipe(in: t) != nil { return true }
            if t.hasSuffix(";") && !t.hasSuffix("\\;") && !isQuoted(t) && !grouped { return false }
            k += 1
        }
        return false
    }

    /// Groups (`{`, `(`, `(echo`) opened on the line of `index`, up to and including that word, and
    /// not closed before it.
    static func openGroups(_ tokens: [String], through index: Int, lineStarts: Set<Int>) -> Int {
        guard index < tokens.count else { return 0 }
        var first = index
        while first > 0 && !lineStarts.contains(first) { first -= 1 }
        var depth = 0
        for k in first...index {
            let t = tokens[k]
            if isQuoted(t) { continue }
            if t == "{" || t == "(" { depth += 1; continue }
            if t == "}" || t == ")" { depth = max(0, depth - 1); continue }
            depth += t.prefix { $0 == "(" }.count
            if k < index { depth = max(0, depth - closingParentheses(in: t)) }
        }
        return depth
    }

    /// The first pipe in a word outside quotes (`|` or `|&`; `||` is not one).
    static func unquotedPipe(in t: String) -> Range<String.Index>? {
        var quote: Character?
        var escaped = false
        var j = t.startIndex
        while j < t.endIndex {
            let c = t[j]
            var next = t.index(after: j)
            defer { j = next }
            if escaped { escaped = false; continue }
            if c == "\\" && quote != "'" { escaped = true; continue }
            if let q = quote { if c == q { quote = nil }; continue }
            if c == "\"" || c == "'" { quote = c; continue }
            guard c == "|" else { continue }
            // `a||b`: an "or", not a pipe; skip both.
            if next < t.endIndex && t[next] == "|" { next = t.index(after: next); continue }
            if next < t.endIndex && t[next] == "&" { return j..<t.index(after: next) }
            return j..<next
        }
        return nil
    }

    /// How many `)` end the word outside quotes (`'pw')` → 1).
    static func closingParentheses(in t: String) -> Int {
        var quote: Character?
        var escaped = false
        var run = 0
        for c in t {
            if escaped { escaped = false; run = 0; continue }
            if c == "\\" && quote != "'" { escaped = true; run = 0; continue }
            if let q = quote { if c == q { quote = nil }; run = 0; continue }
            if c == "\"" || c == "'" { quote = c; run = 0; continue }
            run = c == ")" ? run + 1 : 0
        }
        return quote == nil ? run : 0
    }

    /// A redirect in one word, possibly after data written with it (`pw>>FILE`).
    struct Redirect: Equatable {
        /// What precedes the redirect (`pw` in `pw>>FILE`); empty for `>FILE`, `2>`, `&>FILE`.
        var data: String
        /// `>>FILE`, `2>/dev/null`, `>`.
        var operatorAndTarget: String
        var target: String
        var isStandardOutput: Bool
        /// `2>&1`, `>&2`: no file follows.
        var duplicatesDescriptor: Bool
    }

    /// Finds the first unquoted `>` in `t`. A descriptor number right before it (`2>`) belongs to
    /// the operator, so do `&` (`&>`) and a following `>`, `|` or `&` (`>>`, `>|`, `>&`).
    static func redirect(in t: String) -> Redirect? {
        var quote: Character?
        var escaped = false
        var at: String.Index?
        for j in t.indices {
            let c = t[j]
            if escaped { escaped = false; continue }
            if c == "\\" && quote != "'" { escaped = true; continue }
            if let q = quote { if c == q { quote = nil }; continue }
            if c == "\"" || c == "'" { quote = c; continue }
            if c == ">" { at = j; break }
        }
        guard let gt = at else { return nil }
        var data = String(t[..<gt])
        var descriptor = ""
        if data.hasSuffix("&") {
            data.removeLast()
            descriptor = "&"
        } else if !data.isEmpty && data.allSatisfy(\.isNumber) {
            descriptor = data
            data = ""
        }
        var end = t.index(after: gt)
        var dup = false
        if end < t.endIndex, ">|&".contains(t[end]) {
            dup = t[end] == "&"
            end = t.index(after: end)
        }
        let target = String(t[end...])
        let isOut = descriptor.isEmpty || descriptor == "1" || descriptor == "&"
        return Redirect(data: data, operatorAndTarget: descriptor + String(t[gt...]), target: target, isStandardOutput: isOut,
                        duplicatesDescriptor: dup)
    }

    /// `EOF` for `EOF`, `-EOF`, `'EOF'`, `"EOF"`.
    static func heredocDelimiter(_ s: String) -> String {
        var d = s
        if d.hasPrefix("-") { d.removeFirst() }
        return unquote(d).1.replacingOccurrences(of: "\\", with: "")
    }

    /// A word that names a secret on its own (`password`, `DB_PASS`, `client_secret`).
    static func namesSecret(_ t: String) -> Bool {
        let w = t.lowercased()
        guard !w.isEmpty, !w.contains("="), !w.contains("/") else { return false }
        if referenceSuffixes.contains(where: { w.hasSuffix($0) }) { return false }
        return strongFragments.contains(where: { w.contains($0) }) || w == "pass" || w == "pwd" || endsInPass(w)
    }

    /// `smtp-pass`, `DB_PASS`, `mysql_pwd`, `redis.pwd`: "pass" or "pwd" as the last part of a name
    /// (not `bypass` or `compass`).
    static func endsInPass(_ name: String) -> Bool {
        ["_pass", "-pass", ".pass", "_pwd", "-pwd", ".pwd"].contains(where: { name.hasSuffix($0) })
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
        // Words after a line break start a new command (or a heredoc's body or end).
        var lineStarts = Set<Int>()
        var index = 0
        var afterBreak = false
        for piece in pieces {
            if piece.isSpace {
                afterBreak = afterBreak || piece.text.contains(where: \.isNewline)
            } else {
                if afterBreak { lineStarts.insert(index) }
                afterBreak = false
                index += 1
            }
        }
        var redacted = redactSequence(words, firstIsProgram: false, depth: depth, lineStarts: lineStarts)[...]
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
        s = replace(bareUserinfo, in: s, with: "$1$2:" + placeholder + "@")
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

    /// The rule for a flag no program table knows: names with a strong fragment, or ending in a
    /// "pass"/"pwd" part (`--smtp-pass`, `--db_pwd`), carry a secret. Single-dash long flags too
    /// (`-password`, `-passwd`, `-pass`: Java, Go and ffmpeg style), but not short ones (`-p`).
    static func genericRule(forFlag flag: String) -> ValueRule? {
        if secretFlags.contains(flag) { return .unlessPath }
        let name = flag.lowercased()
        let bare: String
        if name.hasPrefix("--") {
            bare = String(name.dropFirst(2))
        } else if name.hasPrefix("-") && name.count > 3 {
            bare = String(name.dropFirst())
        } else {
            return nil
        }
        if referenceSuffixes.contains(where: { name.hasSuffix($0) }) { return nil }
        let names = strongFragments.contains(where: { bare.contains($0) }) || endsInPass(bare)
            || (!name.hasPrefix("--") && (bare == "pass" || bare == "pwd"))
        return names ? .unlessPath : nil
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
        // `MYSQL_PWD=x`, `DB_PASS=x` (but `PROJECT_PWD=/srv/p`, `OLDPWD=/Users/x` are paths).
        let soft = softKeys.contains(key) || endsInPass(key)
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
            if quote == nil && c.isWhitespace {
                if !current.isEmpty { pieces.append(Piece(text: current, isSpace: false)); current = "" }
                space.append(c)
                continue
            }
            // Before a backslash too: `echo \$HOME` stays `echo \$HOME`, not `echo\$HOME `.
            if !space.isEmpty { pieces.append(Piece(text: space, isSpace: true)); space = "" }
            if c == "\\" && quote != "'" { current.append(c); escaped = true; continue }
            if let q = quote {
                current.append(c)
                if c == q { quote = nil }
                continue
            }
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
