import Foundation
import WhoReadCore

/// Fills owner signing IDs / team IDs in the catalog from the apps actually installed on this
/// Mac, as the brief asks (`codesign -dv`), instead of hard-coding guessed values.
///
/// - Literal bundle paths that exist → `teamIDs` (every binary in a bundle shares the team; helper
///   signing IDs differ, so signing IDs are not pinned for bundles).
/// - Literal executable paths that exist → `signingIDs` (+ `teamIDs` when present).
/// - A spec with any glob path is left alone (reported): pinning it from its literal paths would
///   exclude the members only a glob matches.
public struct CodesignInfo: Equatable, Sendable {
    public var identifier: String?
    public var teamID: String?
    public init(identifier: String?, teamID: String?) {
        self.identifier = identifier
        self.teamID = teamID
    }
}

public protocol CodesignReader {
    func read(path: String) -> CodesignInfo?
}

/// Runs `/usr/bin/codesign -dv --verbose=2 <path>` and parses `Identifier=` / `TeamIdentifier=`
/// from its stderr. (`TeamIdentifier=not set` → nil.)
public struct CodesignCommandReader: CodesignReader {
    public var codesign = "/usr/bin/codesign"
    public init() {}

    public func read(path: String) -> CodesignInfo? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: codesign)
        p.arguments = ["-dv", "--verbose=2", path]
        let err = Pipe()
        p.standardError = err
        p.standardOutput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return CodesignCommandReader.parse(String(decoding: data, as: UTF8.self))
    }

    public static func parse(_ text: String) -> CodesignInfo {
        var info = CodesignInfo(identifier: nil, teamID: nil)
        for line in text.split(separator: "\n") {
            if line.hasPrefix("Identifier=") { info.identifier = String(line.dropFirst("Identifier=".count)) }
            if line.hasPrefix("TeamIdentifier=") {
                let v = String(line.dropFirst("TeamIdentifier=".count))
                info.teamID = (v == "not set" || v.isEmpty) ? nil : v
            }
        }
        return info
    }
}

public enum OwnerResolver {
    public struct Report: Sendable {
        public var resolved: [String] = []
        public var missing: [String] = []
        public var skippedGlobs: Int = 0
    }

    public static func resolve(catalog: Catalog, reader: CodesignReader, exists: (String) -> Bool) -> (Catalog, Report) {
        var out = catalog
        var report = Report()
        for ci in out.categories.indices {
            for oi in out.categories[ci].owners.indices {
                var spec = out.categories[ci].owners[oi]
                // Pinned IDs would describe only the literal members and shut out every process a glob
                // of the same spec matches (`/usr/sbin/securityd` resolves, `/usr/libexec/**/secd` cannot:
                // secd would stop being a keychain owner). Such specs are left as they are.
                let globs = (spec.bundles ?? []).filter(\.hasWildcards).count + (spec.executables ?? []).filter(\.hasWildcards).count
                if globs > 0 {
                    report.skippedGlobs += globs
                    continue
                }
                var teams = Set(spec.teamIDs ?? [])
                var signing = Set(spec.signingIDs ?? [])
                var changed = false
                var someWithoutTeam = false
                for bundle in spec.bundles ?? [] {
                    guard !bundle.hasWildcards else { report.skippedGlobs += 1; continue }
                    guard exists(bundle.pattern) else { report.missing.append(bundle.pattern); continue }
                    if let info = reader.read(path: bundle.pattern) {
                        if let team = info.teamID {
                            teams.insert(team)
                            changed = true
                            report.resolved.append("\(out.categories[ci].id): \(bundle.pattern) team \(team)")
                        } else {
                            someWithoutTeam = true
                        }
                    }
                }
                for exe in spec.executables ?? [] {
                    guard !exe.hasWildcards else { report.skippedGlobs += 1; continue }
                    guard exists(exe.pattern) else { report.missing.append(exe.pattern); continue }
                    if let info = reader.read(path: exe.pattern), let id = info.identifier {
                        signing.insert(id)
                        if let t = info.teamID { teams.insert(t) } else { someWithoutTeam = true }
                        changed = true
                        report.resolved.append("\(out.categories[ci].id): \(exe.pattern) id \(id)" + (info.teamID.map { " team \($0)" } ?? ""))
                    }
                }
                if changed {
                    // A team pin would reject the members that have none (Apple platform binaries).
                    spec.teamIDs = teams.isEmpty || someWithoutTeam ? spec.teamIDs : teams.sorted()
                    // Pin signing IDs only for specs made of literal executables (not bundles).
                    if (spec.bundles ?? []).isEmpty && !signing.isEmpty { spec.signingIDs = signing.sorted() }
                    out.categories[ci].owners[oi] = spec
                }
            }
        }
        return (out, report)
    }
}
