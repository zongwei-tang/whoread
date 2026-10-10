import Foundation

/// Tiny argument parser: positionals, `--flag value`, `--flag=value`, and boolean switches.
struct Args {
    var positional: [String] = []
    var values: [String: [String]] = [:]
    var switches: Set<String> = []

    static let valueFlags: Set<String> = [
        "since", "until", "category", "app", "agent", "limit", "format", "output", "o", "lang", "service", "socket",
        "json-file", "home", "defaults", "learning-days", "input", "vault", "sample", "path", "data-dir", "capture-pid",
    ]

    init(_ argv: [String]) {
        var i = 0
        while i < argv.count {
            let a = argv[i]
            if a == "--" {
                positional += argv[(i + 1)...]
                break
            }
            if a.hasPrefix("--") || (a.hasPrefix("-") && a.count == 2 && a != "-") {
                var name = String(a.drop { $0 == "-" })
                var value: String?
                if let eq = name.firstIndex(of: "=") {
                    value = String(name[name.index(after: eq)...])
                    name = String(name[..<eq])
                }
                if Args.valueFlags.contains(name) {
                    if value == nil, i + 1 < argv.count {
                        value = argv[i + 1]
                        i += 1
                    }
                    values[name, default: []].append(value ?? "")
                } else {
                    switches.insert(name)
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
}

struct CLIError: Error, CustomStringConvertible {
    var message: String
    var exitCode: Int32 = 1
    init(_ m: String, exitCode: Int32 = 1) {
        message = m
        self.exitCode = exitCode
    }
    var description: String { message }
}
