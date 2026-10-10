import Foundation

/// Command lines are metadata, but they routinely carry secrets (`curl -H "Authorization: …"`,
/// `--token=…`, `https://user:token@host`, `AKIA…`). Agent detection uses the raw argv in memory;
/// anything stored, exported or shown goes through this redactor first. eslogger also emits the
/// full environment on exec; WhoRead never reads it.
///
/// AI agents run commands as `zsh -c "<whole command>"`, so an element containing whitespace is
/// tokenized like a shell command line and every token gets the same treatment as an argv element.
/// File paths are evidence and are kept wherever a secret is not expected. What a command line
/// writes (echo/printf words sent to a file or a pipe, also from inside a loop, group or `if` whose
/// output goes there or after `exec > FILE`; heredoc bodies written by cat/tee or into a file;
/// here-strings) is file contents, not metadata: it is redacted, and the redirect's target kept.
/// Secrets inside the text of a command are redacted by its syntax where it is known: SQL that sets
/// a password, JSON and JavaScript objects, AppleScript's `do shell script … password`, URL userinfo,
/// and the arguments some tools take a password in (`htpasswd -b`, `dscl -passwd`, `sqlplus u/pw`).
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
        /// An Oracle logon, `user/password@db` or `userid=user/password@db`: the password.
        case logon
        /// A Redis ACL rule: `>password`, `<password`, `#hash`, `!hash` keep their first character.
        case redisACL
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
                                        "caffeinate", "arch", "timeout", "gtimeout", "xargs", "stdbuf", "chronic", "repeat"]
    /// sudo options that take a value.
    static let sudoValueOptions: Set<String> = ["-u", "-g", "-U", "-C", "-D", "-h", "-p", "-r", "-t", "-T"]

    static let httpClients: Set<String> = ["curl", "wget", "http", "https", "xh", "httpie", "curlie"]
    static let mysqlClients: Set<String> = ["mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport",
                                            "mysqlshow", "mysqlcheck", "mysqlsh"]

    /// Program-specific flags: separate value (`-p value`) and attached value (`-pvalue`).
    static func programFlags(_ program: String, command: ArraySlice<String>) -> (next: [String: ValueRule], attached: [String: ValueRule]) {
        switch program {
        case "http", "https", "xh", "xhs", "httpie":
            // HTTPie and xh: -a/--auth USER:PASS, or a token with `--auth-type bearer`.
            let bearer = command.contains { $0.lowercased().contains("bearer") }
            let auth: ValueRule = bearer ? .secret : .afterColon
            return (["-H": .header, "--header": .header, "-a": auth, "--auth": auth], [:])
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
            // add-generic-password -w, unlock-keychain / create-keychain -p (a keychain path is kept);
            // the passphrase of import/export -P, the keychain password of set-*-partition-list -k,
            // and set-keychain-password -o OLD -p NEW. Elsewhere -P, -k and -o are a prompt flag, a
            // keychain and an output file.
            var next: [String: ValueRule] = ["-w": .secret, "-p": .unlessPath]
            if command.contains("import") || command.contains("export") { next["-P"] = .secret }
            if command.contains(where: { $0.hasPrefix("set-") && $0.hasSuffix("-partition-list") }) { next["-k"] = .secret }
            if command.contains("set-keychain-password") { next["-o"] = .secret; next["-p"] = .secret }
            return (next, [:])
        case "dscl":
            return (["-P": .secret], [:])
        case "sqlcmd", "bcp", "osql":
            return (["-P": .secret], [:])
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
    /// `scheme://<long token>@host`.
    static let urlTokenUserinfo = regex(#"(?i)\b([a-z][a-z0-9+.\-]*://)([^/@\s:'"]{20,})@"#)
    /// Key names that hold a secret, in JSON, Python dicts, YAML and JavaScript objects.
    static let secretKeyNames = #"[a-z0-9_.\-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|authorization|private[_-]?key|access[_-]?key|credentials?)[a-z0-9_.\-]*|(?:[a-z0-9_.\-]*[_.\-])?(?:auth|pass|pwd)"#
    /// A quoted secret key and the opening quote of its value (JSON, Python dicts, YAML):
    /// `{"client_secret":"x"}`, also with escaped quotes (`"{\"password\":\"x\"}"` in a shell command)
    /// and `auth` keys (`{"auths":{"ghcr.io":{"auth":"<base64 user:password>"}}}`, `basic_auth`; not
    /// `author`). `pass` and `pwd` keys as for key=value (`{"user":"bob","pass":"x"}`, `"db_pwd"`; not
    /// `bypass`, `compass` or `passport`). The value runs to its closing quote (`valueEnd`).
    static let quotedPair = regex(#"(?i)(\\?["'])("# + secretKeyNames + #")(\\?["']\s*:\s*)(\\?["'])"#)
    /// The same key unquoted, with a quoted value: JavaScript objects (`mongosh --eval
    /// 'db.createUser({user: "bob", pwd: "x"})'`, `node -e`) and YAML (`secret: "x"`).
    static let barePair = regex(#"(?i)(?<![a-z0-9_$"'\\.\-])("# + secretKeyNames + #")(\s*:\s*)(\\?["'])"#)
    /// AppleScript run with administrator rights: `do shell script "…" [user name "bob"] password "x"`
    /// (`osascript -e`), and the same inside a double-quoted shell word (`password \"x\"`).
    static let appleScriptPassword = regex(#"(?i)(\bdo\s+shell\s+script\b[^\r\n]*?\bpassword\s+")((?:[^"\\\r\n]|\\.)*)(")"#)
    static let escapedAppleScriptPassword = regex(#"(?i)(\bdo\s+shell\s+script\b[^\r\n]*?\bpassword\s+\\")([^\r\n]*?)(\\")"#)
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
    /// line of a command line (a new command, or a heredoc's body and end). `outputRedirected`: what
    /// the command line writes goes to a file or a pipe (`sh -c '…' > FILE`).
    static func redactSequence(_ tokens: [String], firstIsProgram: Bool, depth: Int = 0, lineStarts: Set<Int> = [],
                               outputRedirected: Bool = false) -> [String] {
        var out = tokens
        var pending: ValueRule?
        var program: String?
        var flags: (next: [String: ValueRule], attached: [String: ValueRule]) = ([:], [:])
        var expectProgram = true
        var skipNext = false
        // Data a command writes (privacy-2): echo/printf words whose output goes to a file or a pipe
        // (their own redirect, the one of a group or loop around them, or an earlier `exec > FILE`),
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
        // Passwords some programs take as plain arguments (`htpasswd -b FILE USER PW`), by index.
        var positional: [Int: ValueRule] = [:]
        // Redirects, heredocs and pipes mean something only in a command line, not in an argv.
        let shell = !firstIsProgram
        // Loops, conditionals, groups and process substitutions whose output goes to a file or a pipe.
        let groups = shell ? compound(tokens, lineStarts: lineStarts) : Compound()
        // `exec > FILE`: from then on the shell's own output goes to FILE, on every later line. A
        // command line run by `sh -c '…' > FILE` writes there from the start.
        var execRedirect = outputRedirected
        // The command a container or remote tool runs (`docker exec db mysql …`), by where it starts.
        var launched: (start: Int, entrypoint: String?)?
        func resetCommand(at i: Int) {
            pending = nil; program = nil; expectProgram = true; skipNext = false
            flags = ([:], [:]); positional = [:]; launched = nil
            dataMode = false; dataSeen = false; keepNext = false; hereString = false; outputBeforeProgram = false
            commandStart = i
        }
        func startProgram(_ name: String, at i: Int) {
            program = name
            expectProgram = wrappers.contains(name)
            flags = programFlags(name, command: tokens[i...])
            positional = positionalSecrets(name, tokens: tokens, program: i, lineStarts: lineStarts, shell: shell)
            launched = launchedCommand(name, tokens: tokens, program: i, lineStarts: lineStarts, shell: shell)
            if shell && dataWriters.contains(name) {
                dataMode = outputBeforeProgram || execRedirect || groups.redirected.contains(i)
                    || writesOutput(tokens, after: i, lineStarts: lineStarts)
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
            } else if lineStarts.contains(i) || groups.commandStarts.contains(i) {
                resetCommand(at: i)
            }
            if let l = launched, i == l.start {
                // `docker exec db mysql -pPW`, `ssh host htpasswd -b …`: the command run there has the
                // rules of its own program.
                resetCommand(at: i)
                if let name = l.entrypoint {
                    // `docker run --entrypoint htpasswd IMAGE ARGS…`: the image's arguments are the
                    // entry point's.
                    startProgram(name, at: i)
                    continue
                }
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
            var suffix = ""
            if raw.count > 1 && raw.hasSuffix(";") && !raw.hasSuffix("\\;") && !isQuoted(raw) {
                // `pw;`, and `pw;;` ending a `case` branch.
                let n = raw.count > 2 && raw.hasSuffix(";;") ? 2 : 1
                word = String(raw.dropLast(n))
                suffix = String(repeating: ";", count: n)
                endsCommand = true
            }
            defer {
                if endsCommand {
                    resetCommand(at: i + 1)
                } else if groups.substitutionEnds.contains(i) {
                    // After `<(echo pw)`: the words of the command around it, with no rules of their own.
                    pending = nil; program = nil; expectProgram = false; dataMode = false; flags = ([:], [:]); positional = [:]
                }
            }
            let (quote, t) = unquote(word)
            func emit(_ value: String) { out[i] = quote + value + quote + suffix }

            // `for l in 'pw'; do echo "$l"; done > FILE`: the loop's words are what it writes.
            if groups.loopData.contains(i) {
                emit(placeholder)
                continue
            }

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
            // `cat <(echo pw)`: a command of its own whose output goes into a pipe.
            if shellWord, t.hasPrefix("<(") || t.hasPrefix(">(") {
                let name = String(t.drop { "<>(".contains($0) })
                resetCommand(at: i)
                if !name.isEmpty { startProgram(basename(name), at: i) }
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
                if program == "exec" && expectProgram && r.isStandardOutput && r.data.isEmpty { execRedirect = true }
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

            if let rule = positional[i] {
                pending = nil
                emit(apply(rule, to: t, depth: depth))
                continue
            }
            if let rule = pending {
                // `key = value`, `key : value` (INI, YAML, a heredoc): the separator is not the value.
                if quote.isEmpty && (t == "=" || t == ":") { continue }
                pending = nil
                // Already redacted by a rule that knew its syntax (`SET PASSWORD = PASSWORD('‹redacted›')`).
                if t.contains(placeholder) { continue }
                if !(t.hasPrefix("-") && t.count > 1) {
                    emit(apply(rule, to: t, depth: depth))
                    continue
                }
            }
            if t.contains(where: \.isWhitespace) {
                // A command line passed as one argument (`zsh -c "…"`), or a quoted phrase in one. One
                // that a shell, eval or ssh runs writes where that command's output goes.
                let writes = shell && commandLineRunners.contains(program ?? "")
                    && (execRedirect || outputBeforeProgram || groups.redirected.contains(i)
                        || writesOutput(tokens, after: commandStart, lineStarts: lineStarts))
                emit(depth < maxNesting ? redactCommandLine(t, depth: depth + 1, outputRedirected: writes) : redactToken(t))
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
                // A count or a duration (`10`, `1.5s`), not `sh`.
                if t.contains(where: \.isNumber) && t.allSatisfy({ $0.isNumber || ".smhd".contains($0) }) { continue }
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
                if !t.contains("="), let colon = t.firstIndex(of: ":") {
                    // `-Password:x`, `--password:x` (PowerShell and .NET style). The name before the
                    // colon decides (`--auth-type:bearer` names no secret).
                    let flag = String(t[..<colon])
                    if let rule = genericRule(forFlag: flag) {
                        emit(flag + ":" + apply(rule, to: String(t[t.index(after: colon)...]), depth: depth))
                        continue
                    }
                } else if !t.contains("="), let rule = flags.next[t] ?? genericRule(forFlag: t) {
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
            // Not a MySQL authentication plugin (`IDENTIFIED WITH caching_sha2_password BY '…'`): the
            // SQL rules redact that value.
            let sqlPlugin = i + 1 < tokens.count && ["by", "as", "using"].contains(tokens[i + 1].lowercased())
            if (isSecretKeyName(t) && !sqlPlugin) || (i + 1 < tokens.count && ["=", ":"].contains(tokens[i + 1]) && namesSecret(t)) {
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

    /// The words of the command whose program is at `program`, up to where that command ends (a
    /// separator, a line break, a word ending in `;` or holding a pipe), without redirects and
    /// their targets (`shell`: in an argv, `>x` is a plain argument).
    static func commandWords(_ tokens: [String], program: Int, lineStarts: Set<Int>, shell: Bool) -> [Int] {
        var words: [Int] = []
        var k = program + 1
        while k < tokens.count && !lineStarts.contains(k) {
            let t = tokens[k]
            if isSeparator(t) { break }
            let plain = shell && !isQuoted(t) && !t.contains(where: \.isWhitespace)
            if plain, t.hasPrefix("<") || redirect(in: t).map({ $0.data.isEmpty }) == true {
                // `> FILE`, `2>/dev/null`, `< FILE`: skip the target too when it is the next word.
                let attached = t.drop { "<>&|0123456789".contains($0) }
                k += attached.isEmpty && !t.hasSuffix("&1") && !t.hasSuffix("&2") ? 2 : 1
                continue
            }
            if plain && unquotedPipe(in: t) != nil { break }
            words.append(k)
            if plain && t.hasSuffix(";") && !t.hasSuffix("\\;") { break }
            k += 1
        }
        return words
    }

    static let oracleClients: Set<String> = ["sqlplus", "sql", "dgmgrl", "expdp", "impdp", "exp", "imp", "sqlldr", "rman"]
    static let redisClients: Set<String> = ["redis-cli", "valkey-cli", "keydb-cli"]
    /// redis-cli options followed by a value (so the value is not taken for the command).
    static let redisValueOptions: Set<String> = ["-h", "-p", "-s", "-a", "-u", "-n", "-r", "-i", "-d", "-D", "--user", "--pass",
                                                  "--cacert", "--cacertdir", "--cert", "--key", "--sni", "--pattern", "--count",
                                                  "--rdb", "--eval", "--tls-ciphers", "--tls-ciphersuites"]

    /// Passwords given as plain arguments, by index into `tokens`:
    /// `htpasswd -b[n] [FILE] USER PW`, `mysqladmin password PW`, `dscl . -passwd PATH [OLD] NEW`,
    /// `dscl . -authonly USER PW`, `dscl . -create PATH Password PW`, `networksetup
    /// -setairportnetwork DEV SSID PW` (and the other Wi-Fi and proxy forms), `openssl passwd PW`,
    /// redis `AUTH [USER] PW`, `CONFIG SET requirepass PW`, `ACL SETUSER … >PW`, Oracle logons
    /// (`sqlplus user/PW@db`, `userid=user/PW`, `rman target user/PW@db`), and `db2 connect to DB
    /// user U using PW`.
    static func positionalSecrets(_ program: String, tokens: [String], program p: Int, lineStarts: Set<Int>,
                                  shell: Bool) -> [Int: ValueRule] {
        let known: Set<String> = ["htpasswd", "mysqladmin", "dscl", "networksetup", "openssl", "db2"]
        guard known.contains(program) || redisClients.contains(program) || oracleClients.contains(program) else { return [:] }
        let words = commandWords(tokens, program: p, lineStarts: lineStarts, shell: shell)
        let text = words.map { word -> String in
            var w = unquote(tokens[word]).1
            if w.hasSuffix(";") && !isQuoted(tokens[word]) { w.removeLast() }
            return w
        }
        var out: [Int: ValueRule] = [:]
        func secret(from start: Int, rule: ValueRule = .secret) {
            for j in start..<words.count where !text[j].hasPrefix("-") { out[words[j]] = rule }
        }
        switch program {
        case "htpasswd":
            // Options come first; -C and -r take a value. With -b the password is the last argument:
            // FILE USER PW, or USER PW with -n (not with -D, which deletes USER).
            var batch = false, display = false, fromStdin = false, skip = false
            var positionals: [Int] = []
            for j in words.indices {
                if skip { skip = false; continue }
                let w = text[j]
                if positionals.isEmpty && w.hasPrefix("-") && w.count > 1 {
                    if w == "-C" || w == "-r" { skip = true; continue }
                    batch = batch || w.contains("b"); display = display || w.contains("n"); fromStdin = fromStdin || w.contains("i")
                    continue
                }
                positionals.append(words[j])
            }
            if batch && !fromStdin && positionals.count >= (display ? 2 : 3), let last = positionals.last { out[last] = .secret }
        case "mysqladmin":
            for j in words.indices.dropLast() where ["password", "old-password"].contains(text[j].lowercased()) && !text[j + 1].hasPrefix("-") {
                out[words[j + 1]] = .secret
            }
        case "db2":
            // `db2 connect to DB user U using PW [new PW confirm PW]` (also `attach to NODE …`).
            let lower = text.map { $0.lowercased() }
            guard let using = lower.indices.first(where: { $0 >= 2 && lower[$0] == "using" && lower[$0 - 2] == "user" }) else { break }
            for j in words.indices.dropLast() where j == using || (j > using && ["new", "confirm"].contains(lower[j])) {
                out[words[j + 1]] = .secret
            }
        case "dscl":
            for j in words.indices {
                switch text[j] {
                case "-passwd", "-authonly":
                    // After the record path or user name: the password(s).
                    if j + 2 < words.count { secret(from: j + 2) }
                case "-create", "-append", "-merge":
                    if j + 3 < words.count, namesSecret(text[j + 2]) { secret(from: j + 3) }
                default:
                    break
                }
            }
        case "networksetup":
            let at: [String: Int] = ["-setairportnetwork": 3, "-addpreferredwirelessnetworkatindex": 5, "-setwebproxy": 6,
                                     "-setsecurewebproxy": 6, "-setftpproxy": 6, "-setsocksfirewallproxy": 6,
                                     "-setstreamingproxy": 6, "-setgopherproxy": 6]
            for j in words.indices {
                if let n = at[text[j].lowercased()], j + n < words.count { out[words[j + n]] = .secret }
            }
        case "openssl":
            guard text.first == "passwd" else { break }
            let valued: Set<String> = ["-salt", "-in", "-rand", "-writerand", "-provider", "-provider-path", "-propquery"]
            var skip = false
            for j in words.indices.dropFirst() {
                if skip { skip = false; continue }
                if valued.contains(text[j]) { skip = true; continue }
                if !text[j].hasPrefix("-") { out[words[j]] = .secret }
            }
        case _ where redisClients.contains(program):
            guard let c = words.indices.first(where: { j in
                !text[j].hasPrefix("-") && !(j > 0 && redisValueOptions.contains(text[j - 1]))
            }) else { break }
            let args = Array(words.indices.dropFirst(c + 1))
            let upper = text.map { $0.uppercased() }
            switch upper[c] {
            case "AUTH":
                if let last = args.last { out[words[last]] = .secret }
            case "CONFIG" where args.first.map({ upper[$0] }) == "SET":
                var j = c + 2
                while j + 1 < words.count {
                    if ["REQUIREPASS", "MASTERAUTH"].contains(upper[j]) { out[words[j + 1]] = .secret }
                    j += 2
                }
            case "ACL" where args.first.map({ upper[$0] }) == "SETUSER":
                for j in args.dropFirst(2) where text[j].count > 1 && ">#<!".contains(text[j].first!) { out[words[j]] = .redisACL }
            case "HELLO", "MIGRATE":
                // HELLO 3 AUTH USER PW, MIGRATE … AUTH PW, MIGRATE … AUTH2 USER PW.
                if let a = args.first(where: { ["AUTH", "AUTH2"].contains(upper[$0]) }) {
                    let n = upper[a] == "AUTH" && upper[c] == "MIGRATE" ? 1 : 2
                    if a + n < words.count { out[words[a + n]] = .secret }
                }
            default:
                break
            }
        default:
            // Oracle tools: the first argument is the logon (rman: after target, catalog or auxiliary),
            // and `userid=` anywhere.
            for j in words.indices where text[j].lowercased().hasPrefix("userid=") { out[words[j]] = .logon }
            if program == "rman" {
                for j in words.indices.dropLast() where ["target", "catalog", "auxiliary"].contains(text[j].lowercased()) {
                    out[words[j + 1]] = .logon
                }
            } else if let first = words.indices.first(where: { !text[$0].hasPrefix("-") }) {
                out[words[first]] = .logon
            }
        }
        return out
    }

    static let containerTools: Set<String> = ["docker", "podman", "nerdctl", "finch"]
    static let composeTools: Set<String> = ["docker-compose", "podman-compose"]
    /// Options of the container tools and of their exec, run and create commands that take a value
    /// (`docker run -e K=V -v A:B IMAGE`). Others are switches (`-it`, `--rm`).
    static let containerValueOptions: Set<String> = [
        "--context", "-c", "-H", "--host", "--config", "-l", "--log-level", "-f", "--file", "-p", "--project-name",
        "--project-directory", "--profile", "--env-file", "--ansi", "--progress", "--parallel", "-e", "--env", "-u",
        "--user", "-w", "--workdir", "--detach-keys", "-v", "--volume", "--publish", "--name", "--network", "--net",
        "--mount", "--label", "--label-file", "--platform", "-h", "--hostname", "--add-host", "--cpus", "--cpu-shares",
        "-m", "--memory", "--memory-swap", "--memory-reservation", "--restart", "--log-driver", "--log-opt", "--device",
        "--cap-add", "--cap-drop", "--security-opt", "--ulimit", "--dns", "--dns-search", "--dns-option", "--ipc",
        "--pid", "--uts", "--userns", "--cgroupns", "--cgroup-parent", "--tmpfs", "--shm-size", "--gpus", "--runtime",
        "--pull", "--health-cmd", "--health-interval", "--health-retries", "--health-timeout", "--health-start-period",
        "--stop-signal", "--stop-timeout", "--volumes-from", "--link", "--expose", "--group-add", "--ip", "--ip6",
        "--mac-address", "--network-alias", "--cidfile", "--cpuset-cpus", "--cpuset-mems", "--blkio-weight",
        "--oom-score-adj", "--isolation", "--storage-opt", "--sysctl", "-a", "--attach", "--annotation", "--domainname",
        "--index", "--pod", "--arch", "--os",
    ]
    /// ssh options that take a value (`-p 2222`, `-i KEY`, `-o Opt=v`).
    static let sshValueOptions = Set("BbcDEeFIiJLlmOoPpQRSWw")

    /// The command a container or remote tool runs, whose words follow the tool's own: `docker exec
    /// [OPTIONS] CONTAINER CMD…`, `docker run|create [OPTIONS] IMAGE CMD…` (also `container exec|run`,
    /// podman, nerdctl, finch), `docker compose exec|run [OPTIONS] SERVICE CMD…`, `kubectl|oc … --
    /// CMD…`, and `ssh [OPTIONS] HOST CMD…` with CMD in separate words (one quoted word is a command
    /// line of its own). `start` is the index of CMD's program; with `--entrypoint PROG`, the image's
    /// (PROG's arguments follow it).
    static func launchedCommand(_ program: String, tokens: [String], program p: Int, lineStarts: Set<Int>,
                                shell: Bool) -> (start: Int, entrypoint: String?)? {
        let isContainer = containerTools.contains(program) || composeTools.contains(program)
        guard isContainer || ["kubectl", "oc", "ssh"].contains(program) else { return nil }
        let words = commandWords(tokens, program: p, lineStarts: lineStarts, shell: shell)
        let text = words.map { unquote(tokens[$0]).1 }
        if program == "kubectl" || program == "oc" {
            guard let dashes = text.firstIndex(of: "--"), dashes + 1 < words.count else { return nil }
            return (words[dashes + 1], nil)
        }
        var j = 0
        if program == "ssh" {
            while j < words.count, text[j].count > 1, text[j].hasPrefix("-") {
                if text[j] == "--" { j += 1; break }
                // `-p 2222`, `-tt`, `-p2222`: the first option letter that takes a value takes the
                // rest of the word, or the next word.
                let letters = text[j].dropFirst()
                let valued = letters.firstIndex { sshValueOptions.contains($0) }
                j += valued.map { letters.index(after: $0) == letters.endIndex } == true ? 2 : 1
            }
            // The host, then the command in words of its own.
            guard j + 1 < words.count, !text[j + 1].contains(where: \.isWhitespace) else { return nil }
            return (words[j + 1], nil)
        }
        var entrypoint: String?
        func options() {
            while j < words.count, text[j].count > 1, text[j].hasPrefix("-") {
                let w = text[j]
                if w == "--" { j += 1; return }
                if w.hasPrefix("--entrypoint=") {
                    entrypoint = String(w.dropFirst("--entrypoint=".count))
                } else if w == "--entrypoint" && j + 1 < words.count {
                    entrypoint = text[j + 1]
                    j += 1
                } else if containerValueOptions.contains(w) || (!w.hasPrefix("--") && w.count > 2
                                                                && containerValueOptions.contains("-" + String(w.last!))) {
                    // `-e K=V`, and `-it` / `-dp 80:80` (a value option last in a group of letters).
                    j += 1
                }
                j += 1
            }
        }
        options()
        var compose = composeTools.contains(program)
        if j < words.count && text[j] == "container" {
            j += 1
        } else if j < words.count && text[j] == "compose" {
            j += 1
            compose = true
            options()
        }
        let commands: Set<String> = compose ? ["exec", "run"] : ["exec", "run", "create"]
        guard j < words.count, commands.contains(text[j]) else { return nil }
        j += 1
        options()
        // The container, image or service.
        guard j < words.count else { return nil }
        if let entrypoint, !entrypoint.isEmpty { return (words[j], basename(entrypoint)) }
        guard j + 1 < words.count else { return nil }
        return (words[j + 1], nil)
    }

    /// A word of data replaced, its quotes kept (`'pw'` → `'‹redacted›'`).
    static func redactedData(_ word: String) -> String {
        let (quote, _) = unquote(word)
        return quote + placeholder + quote
    }

    /// Programs whose words are data (`echo pw > FILE`, `printf … | git credential approve`).
    static let dataWriters: Set<String> = ["echo", "printf", "print"]
    /// Programs that run a command line given as one word, with their own output.
    static let commandLineRunners: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh",
                                                  "eval", "su", "ssh"]

    /// True when the command starting after `start` sends its standard output to a file
    /// (`>`, `>>`, `1>`, `&>`, `>|`, attached or not) or into a pipe (`|`, also inside a word:
    /// `pw|tee FILE`), before the command ends. The output of a group or loop around it is
    /// `compound`'s.
    static func writesOutput(_ tokens: [String], after start: Int, lineStarts: Set<Int>) -> Bool {
        var k = start + 1
        while k < tokens.count {
            let t = tokens[k]
            if lineStarts.contains(k) { return false }
            if t == "|" || t == "|&" { return true }
            if isSeparator(t) { return false }
            let word = !isQuoted(t) && !t.contains(where: \.isWhitespace)
            if word, let r = redirect(in: t), r.isStandardOutput { return true }
            if word, unquotedPipe(in: t) != nil { return true }
            if t.hasSuffix(";") && !t.hasSuffix("\\;") && !isQuoted(t) { return false }
            k += 1
        }
        return false
    }

    /// What the compound commands of a command line do with their output (`redactSequence`).
    struct Compound {
        /// Indices inside a group whose output goes to a file or a pipe: `{ echo pw; } > FILE`,
        /// `while …; do echo pw; done > FILE`, `if …; then printf …; fi | tee FILE`, `case … esac >
        /// FILE`, `f() { echo pw; } > FILE`, `<(echo pw)` (a pipe), over several lines too.
        var redirected = Set<Int>()
        /// The words of a `for` loop whose body writes them there (`for l in 'pw'; do echo "$l"; done
        /// > FILE`).
        var loopData = Set<Int>()
        /// Words that start a command though no separator comes before them: after `if`, `while`,
        /// `until`, `elif` and `!`, and after a `case` pattern.
        var commandStarts = Set<Int>()
        /// Words that end a process substitution (`pw)` in `cat <(echo pw) FILE`).
        var substitutionEnds = Set<Int>()
    }

    /// Finds the compound commands of a command line: `{ … }`, `( … )`, `$( … )`, `<( … )`, loops,
    /// `if … fi` and `case … esac`, by their keywords where a command starts (`echo done` is not
    /// one), across lines and around heredoc bodies (a `done` in a body closes nothing).
    static func compound(_ tokens: [String], lineStarts: Set<Int>) -> Compound {
        enum Kind { case brace, paren, substitution, capture, loop, conditional, choice }
        struct Frame {
            var kind: Kind
            var start: Int
            /// A data writer (echo, printf) runs inside.
            var writes = false
            /// `for NAME in WORDS`: 1 after `for`, 2 after the name, 3 in the words.
            var listState = 0
            var list: [Int] = []
        }
        var result = Compound()
        var stack: [Frame] = []
        var atCommand = true
        var pendingHeredoc: String?
        var body: String?

        func close(_ frame: Frame, at end: Int, tail: String) {
            guard frame.kind != .capture else { return }
            guard frame.kind == .substitution || outputLeaves(tokens, after: end, tail: tail, lineStarts: lineStarts) else { return }
            result.redirected.formUnion(frame.start...end)
            if frame.writes { result.loopData.formUnion(frame.list) }
        }
        func push(_ kind: Kind, at k: Int, listState: Int = 0) { stack.append(Frame(kind: kind, start: k, listState: listState)) }
        func program(_ word: String) {
            if dataWriters.contains(basename(word)) { for j in stack.indices { stack[j].writes = true } }
        }
        /// `(`, `$(`, `$((`, `<(`, `>(` at the front of a word; returns the rest (a program name).
        func openParentheses(_ word: Substring, at k: Int) -> Substring {
            var rest = word
            while true {
                if rest.hasPrefix("<(") || rest.hasPrefix(">(") { push(.substitution, at: k); rest = rest.dropFirst(2) }
                else if rest.hasPrefix("$(") { push(.capture, at: k); rest = rest.dropFirst(2) }
                else if rest.hasPrefix("(") { push(stack.last?.kind == .capture ? .capture : .paren, at: k); rest = rest.dropFirst() }
                else { return rest }
            }
        }
        /// `n` closing parentheses at the end of word `k`; in a `case`, a pattern's `)` starts a command.
        func closeParentheses(_ n: Int, at k: Int) {
            for _ in 0..<n {
                guard let top = stack.last else { return }
                switch top.kind {
                case .paren, .substitution, .capture:
                    stack.removeLast()
                    close(top, at: k, tail: "")
                    if top.kind == .substitution { result.substitutionEnds.insert(k) }
                case .choice:
                    result.commandStarts.insert(k + 1)
                    atCommand = true
                    return
                default:
                    return
                }
            }
        }

        var k = -1
        while k + 1 < tokens.count {
            k += 1
            let t = tokens[k]
            if lineStarts.contains(k) {
                atCommand = true
                if let d = pendingHeredoc { body = d; pendingHeredoc = nil }
                if stack.last?.kind == .loop { stack[stack.count - 1].listState = 0 }
            }
            if let d = body {
                if lineStarts.contains(k) && t == d { body = nil }
                continue
            }
            if [";", "&&", "||", "|", "&", "|&", ";;", ";&", ";;&"].contains(t) {
                atCommand = true
                if stack.last?.kind == .loop { stack[stack.count - 1].listState = 0 }
                continue
            }
            let quoted = isQuoted(t)
            let semicolons = quoted || t.hasSuffix("\\;") ? 0 : t.reversed().prefix { $0 == ";" }.count
            let word = String(t.dropLast(semicolons))
            let endsCommand = semicolons > 0 && !word.isEmpty
            defer { if endsCommand { atCommand = true } }
            // The words of `for NAME in WORDS`.
            if let top = stack.last, top.kind == .loop, top.listState > 0 && !atCommand {
                switch top.listState {
                case 1: stack[stack.count - 1].listState = 2
                case 2: stack[stack.count - 1].listState = word == "in" ? 3 : 0
                default: stack[stack.count - 1].list.append(k)
                }
                if endsCommand { stack[stack.count - 1].listState = 0 }
                continue
            }
            if quoted {
                if atCommand { program(t); atCommand = false }
                continue
            }
            if word.hasPrefix("<<") && !word.hasPrefix("<<<") {
                var name = heredocDelimiter(String(word.dropFirst(2)))
                if name.isEmpty && k + 1 < tokens.count {
                    k += 1
                    name = heredocDelimiter(tokens[k])
                }
                pendingHeredoc = name
                continue
            }
            if atCommand {
                switch word {
                case "{": push(.brace, at: k); continue
                case "if": push(.conditional, at: k); result.commandStarts.insert(k + 1); continue
                case "while", "until": push(.loop, at: k); result.commandStarts.insert(k + 1); continue
                case "for", "select": push(.loop, at: k, listState: 1); atCommand = false; continue
                case "case": push(.choice, at: k); atCommand = false; continue
                case "do", "then", "else": continue
                case "elif", "!": result.commandStarts.insert(k + 1); continue
                case "function": if k + 1 < tokens.count { k += 1 }; continue
                default: break
                }
                // `}`, `done`, `fi`, `esac`, with what follows attached (`done>FILE`, `fi;`, `})`).
                var closed = false
                for (keyword, kind) in [("}", Kind.brace), ("done", .loop), ("fi", .conditional), ("esac", .choice)] {
                    guard t == keyword || (t.hasPrefix(keyword) && ";>|&)<".contains(t[t.index(t.startIndex, offsetBy: keyword.count)])) else { continue }
                    let tail = String(t.dropFirst(keyword.count))
                    if let at = stack.lastIndex(where: { $0.kind == kind }) {
                        let frame = stack[at]
                        stack.removeSubrange(at...)
                        close(frame, at: k, tail: tail)
                    }
                    closeParentheses(closingParentheses(in: String(tail.prefix { $0 == ")" })), at: k)
                    atCommand = false
                    closed = true
                    break
                }
                if closed { continue }
                // `f() { …; }`: a function header, then its body.
                if word.count > 2 && word.hasSuffix("()") { continue }
                let rest = openParentheses(Substring(word), at: k)
                if rest.contains("$(") {
                    // `x=$(echo …`: an assignment around a command.
                    let inner = openParentheses(rest[rest.range(of: "$(")!.lowerBound...], at: k)
                    program(String(inner))
                    atCommand = false
                } else if !rest.isEmpty && !(rest.contains("=") && !rest.hasPrefix("-")) && !wrappers.contains(String(rest)) {
                    program(String(rest))
                    atCommand = false
                }
            } else if word.hasPrefix("<(") || word.hasPrefix(">(") || word.contains("$(") {
                // `cat <(echo pw)`, `x$(echo`: a command inside an argument.
                let start = word.hasPrefix("<(") || word.hasPrefix(">(") ? word.startIndex : word.range(of: "$(")!.lowerBound
                program(String(openParentheses(word[start...], at: k)))
            }
            closeParentheses(closingParentheses(in: word), at: k)
        }
        return result
    }

    /// True when the words after a group's closing word send the group's output to a file or a pipe:
    /// `} > FILE`, `done | tee FILE`, `fi>>FILE` (`tail`: what is attached to the closing word),
    /// `done 2>/dev/null >FILE`, `done < <(…) > FILE`; not `done; ls > FILE`.
    static func outputLeaves(_ tokens: [String], after k: Int, tail: String, lineStarts: Set<Int>) -> Bool {
        var j = k + 1
        var attached: String? = tail.isEmpty ? nil : tail
        while true {
            let t: String
            if let a = attached {
                t = a
                attached = nil
            } else {
                guard j < tokens.count, !lineStarts.contains(j) else { return false }
                t = tokens[j]
                j += 1
            }
            if isQuoted(t) || t.hasPrefix(";") || t.hasPrefix("&&") || t.hasPrefix("||") || t == "&" || t.hasPrefix(")") { return false }
            if t.hasPrefix("|") { return true }
            if t.hasPrefix("<") && !t.hasPrefix("<(") {
                // Input: `< FILE`, `< <(cmd …)` (the whole substitution).
                if t == "<" && j < tokens.count {
                    let next = tokens[j]
                    j += 1
                    if next.hasPrefix("<(") {
                        var depth = next.filter { $0 == "(" }.count - closingParentheses(in: next)
                        while depth > 0 && j < tokens.count && !lineStarts.contains(j) {
                            depth += tokens[j].filter { $0 == "(" }.count - closingParentheses(in: tokens[j])
                            j += 1
                        }
                    }
                }
                continue
            }
            guard let r = redirect(in: t), r.data.isEmpty else { return false }
            if r.isStandardOutput { return true }
            if r.target.isEmpty && !r.duplicatesDescriptor { j += 1 }
        }
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
    /// `outputRedirected`: see `redactSequence`.
    static func redactCommandLine(_ line: String, depth: Int = 1, outputRedirected: Bool = false) -> String {
        if let header = redactWholeHeader(line) { return header }
        // Words that put a single quote inside single quotes (`'… PASSWORD '\''pw'\'''`, as commands
        // are quoted for `sh -c` or `eval`) or use ANSI-C quoting are read as the same value in double
        // quotes, which the rules below understand. A word nothing was redacted in is written back as
        // it was.
        var asWritten: [Int: String] = [:]
        var read = line
        if line.contains("'") {
            var normalized = ""
            var index = 0
            for piece in tokenize(line) {
                if !piece.isSpace, let word = doubleQuoted(piece.text) {
                    asWritten[index] = piece.text
                    normalized += word
                } else {
                    normalized += piece.text
                }
                if !piece.isSpace { index += 1 }
            }
            if !asWritten.isEmpty { read = normalized }
        }
        let s = redactAcrossWords(read)
        let pieces = tokenize(s)
        let words = pieces.filter { !$0.isSpace }.map(\.text)
        // One word that is the whole string (`print('a b')`: the quote starts mid-word): splitting
        // makes no progress, so it is a token, not a command line.
        if words.count == 1 && words[0] == s.trimmingCharacters(in: .whitespacesAndNewlines) {
            let token = redactToken(s)
            return token == read ? line : token
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
        var redacted = redactSequence(words, firstIsProgram: false, depth: depth, lineStarts: lineStarts,
                                      outputRedirected: outputRedirected)
        if !asWritten.isEmpty {
            let normalized = tokenize(read).filter { !$0.isSpace }.map(\.text)
            if normalized.count == words.count {
                for (k, word) in asWritten where redacted[k] == normalized[k] { redacted[k] = word }
            }
        }
        var rest = redacted[...]
        var out = ""
        for piece in pieces {
            if piece.isSpace { out += piece.text } else { out += rest.popFirst() ?? piece.text }
        }
        return out
    }

    /// The rules that read a command line's text across its words: quoted headers, JSON and
    /// JavaScript pairs, SQL and AppleScript.
    static func redactAcrossWords(_ s: String) -> String {
        var t = replace(quotedHeader, in: s, with: "$1$2$3" + placeholder)
        t = redactQuotedPairs(t)
        t = redactSQLCredentials(t)
        t = replace(appleScriptPassword, in: t, with: "$1" + placeholder + "$3")
        return replace(escapedAppleScriptPassword, in: t, with: "$1" + placeholder + "$3")
    }

    /// `word` as one double-quoted word with the same value (`"it's"`), when it puts a single quote
    /// inside single quotes (`'it'\''s'`, `'it'"'"'s'`) or is ANSI-C quoted (`$'it\'s'`); nil for any
    /// other word, which the rules read as written. A `;` ending the word stays after it.
    static func doubleQuoted(_ word: String) -> String? {
        var core = word
        var end = ""
        while core.hasSuffix(";") && !core.hasSuffix("\\;") {
            core.removeLast()
            end += ";"
        }
        guard let value = shellWordValue(core) else { return nil }
        var out = "\""
        for c in value {
            if "\"\\$`".contains(c) { out.append("\\") }
            out.append(c)
        }
        return out + "\"" + end
    }

    // MARK: - SQL

    /// SQL that sets a password, wherever the statement is (`psql -c`, `mysql -e`, `sqlcmd -Q`, a
    /// heredoc fed to a client): `ALTER USER bob [WITH] PASSWORD 'x'`, `CREATE USER 'bob'@'%'
    /// IDENTIFIED [WITH plugin] BY 'x'`, `SET PASSWORD [FOR u] = 'x'` or `= PASSWORD('x')`,
    /// `ALTER LOGIN sa WITH PASSWORD = 'x' OLD_PASSWORD = 'y'`, `… REPLACE 'current'`, `CONNECT
    /// user/x@db` (sqlplus), `CONNECT TO user IDENTIFIED BY x` (a database link) and `CONNECT TO db
    /// USER u USING x` (Db2). A literal's contents go and its quotes stay. An unquoted value counts
    /// only inside a statement that creates or changes a user or connects (Oracle's `IDENTIFIED BY
    /// tiger`): "password" in a sentence, a `SELECT` or a `CREATE TABLE` is left alone.
    ///
    /// The SQL may sit inside shell quoting: a double quote is only taken as a string delimiter where
    /// a value is expected, so `psql -c "ALTER USER …"` is read through; a single-quoted shell word
    /// is one literal here and read again when its own command line is redacted.
    static func redactSQLCredentials(_ s: String) -> String {
        let lower = s.lowercased()
        guard lower.contains("password") || lower.contains("identified") || lower.contains("conn") else { return s }
        var scanner = SQLScanner(Array(s.unicodeScalars))
        scanner.run()
        guard !scanner.secrets.isEmpty else { return s }
        var out = scanner.text
        for range in scanner.secrets.sorted(by: { $0.lowerBound > $1.lowerBound }) {
            out.replaceSubrange(range, with: placeholder.unicodeScalars)
        }
        return String(String.UnicodeScalarView(out))
    }

    struct SQLScanner {
        enum Token: Equatable {
            case word(String, Range<Int>)
            /// A string literal: its contents (without the quotes).
            case literal(Range<Int>)
            case punct(Unicode.Scalar)
            case end
        }
        enum Statement { case none, user, setPassword, grant, connectTo }

        let text: [Unicode.Scalar]
        var i = 0
        /// Ranges of `text` to replace.
        var secrets: [Range<Int>] = []

        init(_ text: [Unicode.Scalar]) { self.text = text }

        static func isWordScalar(_ c: Unicode.Scalar) -> Bool {
            (c.isASCII && (c.properties.isAlphabetic || ("0"..."9").contains(c))) || c == "_" || c == "$" || c == "#"
        }

        func at(_ k: Int) -> Unicode.Scalar? { k < text.count ? text[k] : nil }

        /// The next token. `value`: a value is expected here, so a double quote (or a shell-escaped
        /// quote, `\"x\"`) opens a literal, and so does `$$` (PostgreSQL dollar quoting).
        mutating func next(value: Bool = false) -> Token {
            while let c = at(i), c.properties.isWhitespace { i += 1 }
            guard let c = at(i) else { return .end }
            if c == "'" { return quoted(from: i, delimiter: ["'"]) ?? punct() }
            if value {
                if c == "\\", let q = at(i + 1), q == "\"" || q == "'" { return quoted(from: i, delimiter: ["\\", q]) ?? punct() }
                if c == "\"" { return quoted(from: i, delimiter: ["\""]) ?? punct() }
                if c == "$", let lit = dollarQuoted() { return lit }
            }
            guard SQLScanner.isWordScalar(c) else { return punct() }
            let start = i
            while let d = at(i), SQLScanner.isWordScalar(d) { i += 1 }
            let word = String(String.UnicodeScalarView(text[start..<i]))
            // E'…', N'…', B'…', X'…': a prefixed literal (not `-e'…'`, a shell option with its value).
            let before = start > 0 ? text[start - 1] : " "
            if word.count == 1, "EeNnBbXx".unicodeScalars.contains(word.unicodeScalars.first!), at(i) == "'",
               before.properties.isWhitespace || "(,=".unicodeScalars.contains(before),
               let lit = quoted(from: i, delimiter: ["'"]) { return lit }
            return .word(word, start..<i)
        }

        mutating func punct() -> Token {
            defer { i += 1 }
            return .punct(text[i])
        }

        /// A literal from `start` closed by the same delimiter. Inside, a backslash escapes the next
        /// character and a doubled quote stands for one. Unterminated: not a literal.
        mutating func quoted(from start: Int, delimiter: [Unicode.Scalar]) -> Token? {
            let quote = delimiter.last!
            var k = start + delimiter.count
            let contents = k
            while k < text.count {
                if delimiter.count == 2 {
                    // `\"x\"`: the closing quote is escaped like the opening one.
                    if text[k] == "\\" && at(k + 1) == quote { i = k + 2; return .literal(contents..<k) }
                    if text[k] == "\\" { k += 2; continue }
                } else {
                    if text[k] == "\\" { k += 2; continue }
                    if text[k] == quote {
                        if at(k + 1) == quote { k += 2; continue }
                        i = k + 1
                        return .literal(contents..<k)
                    }
                }
                k += 1
            }
            return nil
        }

        /// `$$x$$`, `$tag$x$tag$`.
        mutating func dollarQuoted() -> Token? {
            var k = i + 1
            while let c = at(k), c != "$" {
                guard SQLScanner.isWordScalar(c) else { return nil }
                k += 1
            }
            guard at(k) == "$" else { return nil }
            let tag = Array(text[i...k])
            let contents = k + 1
            var j = contents
            while j + tag.count <= text.count {
                if Array(text[j..<(j + tag.count)]) == tag {
                    i = j + tag.count
                    return .literal(contents..<j)
                }
                j += 1
            }
            return nil
        }

        /// Looks at the next token without consuming it.
        mutating func peek(value: Bool = false) -> Token {
            let saved = i
            defer { i = saved }
            return next(value: value)
        }

        func upper(_ t: Token) -> String? {
            if case .word(let w, _) = t { return w.uppercased() }
            return nil
        }

        mutating func secret(_ range: Range<Int>) {
            if !range.isEmpty { secrets.append(range) }
        }

        /// The value after PASSWORD, BY, AS, `=` or REPLACE: a literal, `PASSWORD('x')` when
        /// `function`, a `0x…` hash, or (`bare`) an unquoted word. Inside a statement that sets a
        /// password (`bare`, or always for the forms that only take one), an unterminated literal
        /// goes to the end of its line: the statement was cut short, or its closing quote is outside
        /// this word.
        mutating func value(equals: Bool = false, function: Bool = false, bare: Bool = false, open: Bool = true) {
            var t = next(value: true)
            if equals, t == .punct("=") { t = next(value: true) }
            if function, let w = upper(t), w == "PASSWORD" || w == "OLD_PASSWORD", peek() == .punct("(") {
                _ = next()
                t = next(value: true)
            }
            switch t {
            case .literal(let r):
                secret(r)
            case .word(let w, let r):
                let k = w.uppercased()
                if k.hasPrefix("0X") && k.count > 2 { secret(r); return }
                // Keywords that may follow (PASSWORD EXPIRE, PASSWORD NULL, BY RANDOM PASSWORD).
                let keywords: Set<String> = ["NULL", "RANDOM", "PASSWORD", "VALUES", "DEFAULT", "EXPIRE", "HISTORY", "REUSE",
                                             "REQUIRE", "LOCK", "UNLOCK", "DISABLE", "VALID", "RETAIN", "CURRENT", "AND",
                                             "WITH", "EXTERNALLY", "GLOBALLY"]
                if bare && !keywords.contains(k) { secret(r) } else { i = r.lowerBound }
            case .punct(let c):
                let escaped = c == "\\" && (at(i) == "'" || at(i) == "\"")
                if open && (c == "'" || c == "\"" || escaped) {
                    let start = escaped ? i + 1 : i
                    var end = start
                    while end < text.count && text[end] != "\n" && text[end] != "\r" { end += 1 }
                    secret(start..<end)
                    i = end
                    return
                }
                // Not a value: let the main loop see it (`;` ends the statement).
                i -= 1
            case .end:
                break
            }
        }

        /// `IDENTIFIED BY x`, `IDENTIFIED BY PASSWORD 'hash'`, `IDENTIFIED WITH plugin [BY|AS] x`,
        /// `IDENTIFIED VIA plugin USING PASSWORD('x')`.
        mutating func identified(bare: Bool) {
            var t = next()
            if let w = upper(t), w == "WITH" || w == "VIA" {
                _ = next()  // the plugin (a word or a literal)
                guard let k = upper(peek()), ["BY", "AS", "USING"].contains(k) else { return }
                t = next()
            }
            guard case .word(let w, let r) = t else { if case .punct = t { i -= 1 }; return }
            switch w.uppercased() {
            case "BY":
                if let next = upper(peek()), next == "PASSWORD" || next == "VALUES" {
                    _ = self.next()
                    value(open: bare)
                } else if upper(peek()) != "RANDOM" {
                    value(bare: bare, open: bare)
                }
            case "AS":
                value(open: bare)
            case "USING":
                value(function: true, open: bare)
            default:
                i = r.lowerBound
            }
        }

        /// `CONNECT user/x@db`: the logon is one word of the command line.
        mutating func connect() {
            while let c = at(i), c == " " || c == "\t" { i += 1 }
            let start = i
            var quote: Unicode.Scalar?
            while let c = at(i) {
                if let q = quote { if c == q { quote = nil } } else if c == "\"" { quote = c } else if c.properties.isWhitespace || c == ";" { break }
                i += 1
            }
            let word = String(String.UnicodeScalarView(text[start..<i]))
            if let range = ArgvRedactor.logonPasswordRange(word) {
                let lower = word.unicodeScalars.distance(from: word.unicodeScalars.startIndex, to: range.lowerBound)
                let upper = word.unicodeScalars.distance(from: word.unicodeScalars.startIndex, to: range.upperBound)
                secret((start + lower)..<(start + upper))
            }
        }

        mutating func run() {
            var statement = Statement.none
            // Words left in which USER/ROLE/LOGIN/GROUP makes an ALTER or CREATE a user statement
            // (`CREATE OR REPLACE USER`).
            var ddl = 0
            var previous = ""
            var setPasswordValueSeen = false
            while true {
                let t = next()
                switch t {
                case .end:
                    return
                case .punct(";"):
                    statement = .none; ddl = 0; previous = ""
                    continue
                case .punct("="):
                    if statement == .setPassword && !setPasswordValueSeen {
                        setPasswordValueSeen = true
                        value(function: true)
                    }
                    continue
                case .punct, .literal:
                    ddl = 0
                    continue
                case .word(let w, _):
                    let k = w.uppercased()
                    defer { previous = k }
                    if ddl > 0 {
                        if ["USER", "ROLE", "LOGIN", "GROUP"].contains(k) { statement = .user; ddl = 0; continue }
                        ddl = ["OR", "REPLACE"].contains(k) ? ddl - 1 : 0
                        if ddl > 0 { continue }
                    }
                    switch k {
                    case "ALTER", "CREATE":
                        ddl = 3
                    case "GRANT":
                        statement = .grant
                    case "PASSWORD", "OLD_PASSWORD":
                        if statement == .user || statement == .grant {
                            value(equals: true)
                        } else if previous == "SET" && k == "PASSWORD" {
                            statement = .setPassword
                            setPasswordValueSeen = false
                        }
                    case "IDENTIFIED":
                        identified(bare: statement == .user || statement == .grant || statement == .connectTo)
                    case "REPLACE":
                        if statement == .user || statement == .setPassword { value(bare: statement == .user) }
                    case "CONNECT", "CONN":
                        if upper(peek()) == "TO" {
                            // `CREATE DATABASE LINK l CONNECT TO user IDENTIFIED BY x` (Oracle), `CONNECT
                            // TO db USER u USING x [NEW y CONFIRM y]` (Db2, embedded SQL).
                            _ = next()
                            statement = .connectTo
                        } else {
                            connect()
                        }
                    case "USER" where statement == .connectTo:
                        _ = next()  // the user name (a word or a literal)
                        if upper(peek()) == "USING" {
                            _ = next()
                            value(bare: true)
                        }
                    case "NEW", "CONFIRM":
                        if statement == .connectTo { value(bare: true) }
                    default:
                        break
                    }
                }
            }
        }
    }

    /// The password in an Oracle logon, `user/password@db` (`scott/tiger`, `sys/"p w"@//h:1521/s`):
    /// nil for `/`, `/@db`, `user@db` and paths.
    static func logonPasswordRange(_ s: String) -> Range<String.Index>? {
        guard !looksLikePath(s), !s.hasPrefix("@"), let slash = s.firstIndex(of: "/"), slash != s.startIndex else { return nil }
        let user = s[..<slash]
        guard !user.contains("@"), !user.contains("="), !user.contains(":") else { return nil }
        let start = s.index(after: slash)
        guard start < s.endIndex, s[start] != "/" else { return nil }
        var end = s[start...].firstIndex(of: "@") ?? s.endIndex
        if s[start] == "\"", let close = s[s.index(after: start)...].firstIndex(of: "\"") { end = s.index(after: close) }
        return start < end ? start..<end : nil
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
        // `password:PW`, `api_key:PW`: a secret's name, a colon and the value in one word (`tmux -t
        // session:1`, `read:packages` and `HEAD:password.txt` are not: only strong names count). Also
        // a Windows-style option (`sqlpackage /TargetPassword:PW`).
        if let colon = t.firstIndex(of: ":"), colon != t.startIndex {
            let key = String(t[..<colon]), value = String(t[t.index(after: colon)...])
            let name = key.hasPrefix("/") ? String(key.dropFirst()) : key
            if !value.isEmpty, !value.hasPrefix("//"), !value.contains(placeholder), !name.isEmpty,
               name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "_.-".contains($0)) }),
               namesSecret(String(name.drop { $0 == "-" })), !refersToSecret(name),
               !looksLikePath(value), !switchValues.contains(value.lowercased()) {
                return key + ":" + placeholder
            }
        }
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
        var s = redactUserinfo(t)
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

    /// `"password": "x"` → `"password": "‹redacted›"`, `pwd: 'x'` → `pwd: '‹redacted›'`, unless the key
    /// only refers to a secret (`"token_file": "/path"`, `secretName: 'prod'`) or the value is a path.
    static func redactQuotedPairs(_ s: String) -> String {
        let range = NSRange(location: 0, length: (s as NSString).length)
        var matches: [(key: NSRange, open: NSRange)] = quotedPair.matches(in: s, range: range).map { ($0.range(at: 2), $0.range(at: 4)) }
        matches += barePair.matches(in: s, range: range).map { ($0.range(at: 1), $0.range(at: 3)) }
        guard !matches.isEmpty else { return s }
        let units = Array(s.utf16)
        let ns = s as NSString
        var values: [NSRange] = []
        for m in matches.sorted(by: { $0.open.location < $1.open.location }) {
            // A key inside a value already found is part of that value.
            if let last = values.last, m.key.location < last.location + last.length { continue }
            let start = m.open.location + m.open.length
            let end = valueEnd(units, from: start, delimiter: Array(ns.substring(with: m.open).utf16))
            guard end > start else { continue }
            let value = NSRange(location: start, length: end - start)
            let text = ns.substring(with: value)
            if refersToSecret(ns.substring(with: m.key)) || looksLikePath(text) || switchValues.contains(text.lowercased()) { continue }
            values.append(value)
        }
        guard !values.isEmpty else { return s }
        let out = NSMutableString(string: s)
        for v in values.reversed() { out.replaceCharacters(in: v, with: placeholder) }
        return out as String
    }

    /// Where a quoted value starting at `start` ends (the index of its closing quote; a line break
    /// or the end of the text when it is not closed). `"` or `'`: a backslash escapes the next
    /// character (JSON, Python, JavaScript). `\"` (JSON in a double-quoted shell word): the shell
    /// doubles each backslash, so a quote preceded by 1, 5, 9… backslashes closes the value, and one
    /// preceded by 3, 7… is a quote inside it.
    static func valueEnd(_ units: [UInt16], from start: Int, delimiter: [UInt16]) -> Int {
        let backslash: UInt16 = 0x5C, newline: UInt16 = 0x0A, ret: UInt16 = 0x0D
        guard let quote = delimiter.last else { return start }
        var k = start
        while k < units.count {
            let c = units[k]
            if c == newline || c == ret { return k }
            if delimiter.count == 1 {
                if c == backslash { k += 2; continue }
                if c == quote { return k }
            } else if c == backslash {
                var run = 0
                while k + run < units.count && units[k + run] == backslash { run += 1 }
                if k + run < units.count && units[k + run] == quote {
                    if run % 4 == 1 { return k + run - 1 }
                    k += run + 1
                    continue
                }
                k += run
                continue
            }
            k += 1
        }
        return min(k, units.count)
    }

    /// A key that names where a secret is, not the secret: `token_file`, `secret-name`, `password_id`,
    /// and in camelCase `tokenFile`, `secretName`, `passwordLength`.
    static func refersToSecret(_ key: String) -> Bool {
        let lower = key.lowercased()
        if referenceSuffixes.contains(where: { lower.hasSuffix($0) }) { return true }
        guard let cap = key.lastIndex(where: \.isUppercase), cap != key.startIndex,
              key[key.index(before: cap)].isLowercase else { return false }
        let word = key[cap...].lowercased()
        return referenceSuffixes.contains { $0.dropFirst() == word }
    }

    /// `scheme://user:password@host`, and `//user:password@host` with no scheme (`mount -t smbfs
    /// //bob:pw@nas/share`): the password goes. Userinfo ends at the last "@" of the authority, so an
    /// "@" in the password or an e-mail address as the user name is covered. A "/" in the password
    /// ends the authority early (`bob:pa/ss@host`): when the authority is `user:x` with no "@" and x
    /// is not a port, the password runs to the last "@" before the host's path.
    static func redactUserinfo(_ s: String) -> String {
        guard s.contains("//"), s.contains("@") else { return s }
        let u = Array(s.unicodeScalars)
        var secrets: [Range<Int>] = []
        var k = 0
        while k + 1 < u.count {
            guard u[k] == "/", u[k + 1] == "/" else { k += 1; continue }
            defer { k += 2 }
            let bare = k == 0 || " \t\n='\"(".unicodeScalars.contains(u[k - 1])
            guard bare || hasScheme(u, colon: k - 1) else { continue }
            var end = k + 2
            while end < u.count && !u[end].properties.isWhitespace && u[end] != "'" && u[end] != "\"" { end += 1 }
            if let r = userinfoPassword(u, from: k + 2, to: end), secrets.last.map({ $0.upperBound <= r.lowerBound }) ?? true {
                secrets.append(r)
            }
        }
        guard !secrets.isEmpty else { return s }
        var out = u
        for r in secrets.reversed() { out.replaceSubrange(r, with: placeholder.unicodeScalars) }
        return String(String.UnicodeScalarView(out))
    }

    /// `https:` ends at `colon`: a letter, then letters, digits, `+`, `-` or `.`.
    static func hasScheme(_ u: [Unicode.Scalar], colon: Int) -> Bool {
        guard colon > 0, u[colon] == ":" else { return false }
        var j = colon
        while j > 0, u[j - 1].isASCII, u[j - 1].properties.isAlphabetic || ("0"..."9").contains(u[j - 1]) || "+-.".unicodeScalars.contains(u[j - 1]) {
            j -= 1
        }
        return j < colon && u[j].properties.isAlphabetic
    }

    /// The password of the URL whose authority starts at `start` (after `//`) and that ends at `end`.
    static func userinfoPassword(_ u: [Unicode.Scalar], from start: Int, to end: Int) -> Range<Int>? {
        func pathStart(_ from: Int) -> Int {
            var j = from
            while j < end && !"/?#".unicodeScalars.contains(u[j]) { j += 1 }
            return j
        }
        let authority = pathStart(start)
        if let at = (start..<authority).last(where: { u[$0] == "@" }) {
            guard let colon = (start..<at).first(where: { u[$0] == ":" }), colon + 1 < at else { return nil }
            // `user:pa@ss/word@host`: an "@" inside the first path segment (not at its start, as in
            // `/@scope`) is where a password with "@" and "/" in it ends. A URL with a password and
            // such a segment (`/me@x.com`) loses its host too.
            if authority < end && u[authority] == "/" {
                let segment = (authority + 1)..<pathStart(authority + 1)
                if let later = segment.last(where: { u[$0] == "@" }), later > segment.lowerBound { return (colon + 1)..<later }
            }
            return (colon + 1)..<at
        }
        // No "@" before the first "/": `user:pa/ss@host`, unless that is `host:port/…@…` or IPv6.
        guard start < authority, u[start] != "[", let colon = (start..<authority).first(where: { u[$0] == ":" }) else { return nil }
        let port = u[(colon + 1)..<authority]
        guard !port.isEmpty, !port.allSatisfy({ ("0"..."9").contains($0) }) else { return nil }
        guard let firstAt = (authority..<end).first(where: { u[$0] == "@" }),
              let at = (firstAt..<pathStart(firstAt)).last(where: { u[$0] == "@" }) else { return nil }
        return (colon + 1)..<at
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
        case .logon:
            var key = "", logon = value
            if let eq = value.firstIndex(of: "="), value[..<eq].lowercased() == "userid" {
                key = String(value[...eq])
                logon = String(value[value.index(after: eq)...])
            }
            guard let range = logonPasswordRange(logon) else { return value }
            return key + logon.replacingCharacters(in: range, with: placeholder)
        case .redisACL:
            guard let first = value.first, value.count > 1 else { return value }
            return String(first) + placeholder
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
        // Not a hidden file (`.htpasswd`) or a jq path (`.db.password`).
        guard !t.contains("="), !t.isEmpty, !t.hasPrefix("."), !t.contains("://"),
              (!t.contains("/") && !looksLikePath(t)) || t.contains(":") else { return false }
        guard t.contains(where: { "_.:".contains($0) }) else { return false }
        let part = t.split(whereSeparator: { "/:.".contains($0) }).last.map(String.init) ?? ""
        if refersToSecret(part) { return false }
        let last = part.lowercased()
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
        // `$'…'` (ANSI-C quoting): a backslash escapes the next character, `\'` included.
        var ansi = false
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
            if c == "\\" && (quote != "'" || ansi) { current.append(c); escaped = true; continue }
            if let q = quote {
                current.append(c)
                if c == q { quote = nil; ansi = false }
                continue
            }
            if c == "\"" || c == "'" {
                ansi = c == "'" && current.last == "$"
                quote = c
            }
            current.append(c)
        }
        if !current.isEmpty { pieces.append(Piece(text: current, isSpace: false)) }
        if !space.isEmpty { pieces.append(Piece(text: space, isSpace: true)) }
        return pieces
    }

    static func isSeparator(_ t: String) -> Bool {
        ["&&", "||", ";", "|", "&", "(", ")", "{", "}", "then", "do", "else", "$(", ";;", ";&", ";;&", "|&"].contains(t)
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

    /// The value the shell gives a quoted word where `unquote` would leave quotes inside: a single
    /// quote written into a single-quoted word (`'it'\''s'`, `'it'"'"'s'` → `it's`), and ANSI-C
    /// quoting (`$'it\'s'`). Nil for any other word, which the rules read as written (`--password='x'`,
    /// `{"k":"v"}`, SQL's `'bob'@'%'`), and for one with shell syntax outside quotes (`'a'\''b'>FILE`)
    /// or an unclosed quote.
    static func shellWordValue(_ word: String) -> String? {
        guard word.contains("'") else { return nil }
        let chars = Array(word)
        var value = ""
        var parts = 0
        var ansi = false
        var k = 0
        while k < chars.count {
            let c = chars[k]
            if c == "'" {
                guard let close = chars[(k + 1)...].firstIndex(of: "'") else { return nil }
                value += String(chars[(k + 1)..<close])
                k = close + 1
            } else if c == "\"" || (c == "$" && k + 1 < chars.count && chars[k + 1] == "'") {
                // Double quotes: \ escapes " \ $ ` (a line break after it is removed). ANSI-C: \' \" \\
                // \n \t \r; other escapes are kept as written.
                ansi = ansi || c == "$"
                let close: Character = c == "$" ? "'" : "\""
                var j = k + (c == "$" ? 2 : 1)
                var closed = false
                while j < chars.count {
                    let d = chars[j]
                    if d == "\\" && j + 1 < chars.count {
                        let e = chars[j + 1]
                        switch (c == "$", e) {
                        case (false, "\""), (false, "\\"), (false, "$"), (false, "`"), (true, "'"), (true, "\""), (true, "\\"):
                            value.append(e)
                        case (false, "\n"):
                            break
                        case (true, "n"): value.append("\n")
                        case (true, "t"): value.append("\t")
                        case (true, "r"): value.append("\r")
                        default: value.append(d); value.append(e)
                        }
                        j += 2
                        continue
                    }
                    if d == close { closed = true; break }
                    value.append(d)
                    j += 1
                }
                guard closed else { return nil }
                k = j + 1
            } else if c == "\\" {
                if k + 1 < chars.count && chars[k + 1] != "\n" { value.append(chars[k + 1]) }
                k += 2
                continue
            } else {
                if "<>|;&()`".contains(c) { return nil }
                value.append(c)
                k += 1
                continue
            }
            parts += 1
        }
        return (isQuoted(word) && parts > 1 && value.contains("'")) || ansi ? value : nil
    }

    static func basename(_ s: String) -> String {
        let (_, t) = unquote(s)
        return t.split(separator: "/").last.map(String.init) ?? t
    }

    static func truncate(_ s: String, _ n: Int) -> String {
        s.count > n ? String(s.prefix(n)) + "…" : s
    }
}
