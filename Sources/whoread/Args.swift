import Foundation

/// Tiny argument parser: positionals, `--flag value`, `--flag=value`, and boolean switches. Which
/// names take a value is fixed here (`valueFlags`); which options and how many positionals each
/// command takes is checked against its `CommandSpec` before anything is sent or changed.
struct Args {
    var positional: [String] = []
    var values: [String: [String]] = [:]
    var switches: Set<String> = []
    /// Option names in the order given (one entry per occurrence).
    var given: [String] = []
    /// Switches written with a value (`--json=false`): the value would be dropped.
    var switchValues: [String: String] = [:]
    /// Value flags with nothing after them.
    var missingValues: Set<String> = []
    /// Words that look like options but are none as written: `-since`, `-ofile.csv` (one dash and
    /// more than one letter), `--`, `--=x`.
    var badWords: [String] = []

    static let valueFlags: Set<String> = [
        "since", "until", "category", "app", "search", "agent", "limit", "format", "output", "o", "lang", "service", "socket",
        "json-file", "home", "defaults", "learning-days", "input", "vault", "sample", "path", "data-dir", "capture-pid",
    ]
    /// Taken by every command.
    static let globalSwitches: Set<String> = ["json", "h", "help"]
    static let globalValues: Set<String> = ["lang", "service", "socket"]

    init(_ argv: [String]) {
        var i = 0
        while i < argv.count {
            let a = argv[i]
            if a == "--" {
                positional += argv[(i + 1)...]
                break
            }
            if a.hasPrefix("-") && a != "-" {
                // One dash takes one letter (`-o`, `-h`); `-since` is not `--since`, and not a word either.
                guard a.hasPrefix("--") || a.count == 2 else {
                    badWords.append(a)
                    i += 1
                    continue
                }
                var name = String(a.drop { $0 == "-" })
                var value: String?
                if let eq = name.firstIndex(of: "=") {
                    value = String(name[name.index(after: eq)...])
                    name = String(name[..<eq])
                }
                guard !name.isEmpty, a.hasPrefix("---") == false else {
                    badWords.append(a)
                    i += 1
                    continue
                }
                given.append(name)
                if Args.valueFlags.contains(name) {
                    if value == nil, i + 1 < argv.count {
                        value = argv[i + 1]
                        i += 1
                    }
                    if let value { values[name, default: []].append(value) } else { missingValues.insert(name) }
                } else {
                    switches.insert(name)
                    if let value { switchValues[name] = value }
                }
            } else {
                positional.append(a)
            }
            i += 1
        }
    }

    func value(_ name: String) -> String? { values[name]?.last }
    func all(_ name: String) -> [String] { values[name] ?? [] }
    func has(_ name: String) -> Bool { switches.contains(name) }
    var json: Bool { has("json") }

    /// `-o` or `--output`, as typed.
    static func spelled(_ name: String) -> String { name.count == 1 ? "-" + name : "--" + name }

    /// Throws a usage error for anything `spec` does not take: an option the command does not
    /// read, a misspelled one, a switch given a value, a value flag without its value or (unless
    /// it adds up) given twice, and too few or too many positionals (the command word counts).
    func check(_ spec: CommandSpec) throws {
        let command = "whoread " + spec.name
        if let w = badWords.first {
            let hint = w.hasPrefix("--") || w.count < 2 ? "" : " (a long option takes two dashes, as in -\(w))"
            throw CLIError.usage("unknown option \(w) for \(command)\(hint)\nusage: whoread \(spec.usage)")
        }
        var seen = Set<String>()
        for name in given {
            let flag = Args.spelled(name)
            let takesValue = Args.valueFlags.contains(name)
            let known = takesValue ? spec.values.contains(name) || Args.globalValues.contains(name)
                : spec.switches.contains(name) || Args.globalSwitches.contains(name)
            guard known else { throw CLIError.usage("\(flag) is not an option of \(command)\nusage: whoread \(spec.usage)") }
            if let v = switchValues[name] { throw CLIError.usage("\(flag) takes no value (\(flag)=\(v))") }
            if missingValues.contains(name) { throw CLIError.usage("\(flag) needs a value") }
            if takesValue, !seen.insert(name).inserted, !spec.repeatable.contains(name) {
                throw CLIError.usage("\(flag) given more than once: \(command) uses one")
            }
        }
        guard spec.positionals.contains(positional.count) else {
            // A stray word is often the rest of an unquoted value with a space in it.
            let quote = spec.positionals.upperBound >= 3 ? " (quote a value that has spaces)" : ""
            let extra = positional.count > spec.positionals.upperBound
                ? "unexpected \(positional.dropFirst(spec.positionals.upperBound).map { "\"\($0)\"" }.joined(separator: " "))\(quote)\n"
                : ""
            throw CLIError.usage(extra + "usage: whoread \(spec.usage)")
        }
    }
}

/// What one command (or subcommand) takes besides the global options, and how many positionals,
/// counting the command word and the subcommand.
struct CommandSpec {
    var name: String
    var usage: String
    var positionals: ClosedRange<Int> = 1...1
    var switches: Set<String> = []
    var values: Set<String> = []
    /// Value flags that may be given more than once (each adds one).
    var repeatable: Set<String> = []
}

struct CLIError: Error, CustomStringConvertible {
    var message: String
    var exitCode: Int32 = 1
    init(_ m: String, exitCode: Int32 = 1) {
        message = m
        self.exitCode = exitCode
    }
    var description: String { message }

    /// EX_USAGE: what was typed cannot be run as it is (checked before anything is sent).
    static func usage(_ m: String) -> CLIError { CLIError(m, exitCode: 64) }
}
