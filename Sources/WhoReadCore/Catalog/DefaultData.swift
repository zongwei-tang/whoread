import Foundation

/// The three data files that drive classification and attribution.
public struct DefaultData: Sendable {
    public var catalog: Catalog
    public var agents: AgentCatalog
    public var benign: BenignCatalog

    public static let catalogFile = "catalog.json"
    public static let agentsFile = "agents.json"
    public static let benignFile = "benign.json"

    public init(catalog: Catalog, agents: AgentCatalog, benign: BenignCatalog) {
        self.catalog = catalog
        self.agents = agents
        self.benign = benign
    }

    /// Far above the shipped files (the catalog is about 100 KB).
    static let maxFileSize = 16 << 20

    /// Loads all three files from a directory. With `trustedOwner` (a daemon running as root), each
    /// file is read only when no one but that user and root could have changed it, its directory or a
    /// directory on the way (`TrustedFile`); otherwise this throws `TrustedFile.Untrusted`.
    public static func load(directory: URL, trustedOwner: uid_t? = nil) throws -> DefaultData {
        func read(_ name: String) throws -> Data {
            let url = directory.appendingPathComponent(name)
            guard let owner = trustedOwner else { return try Data(contentsOf: url) }
            return try TrustedFile.read(url.path, owner: owner, limit: maxFileSize)
        }
        return DefaultData(
            catalog: try Catalog.load(from: read(catalogFile)),
            agents: try AgentCatalog.load(from: read(agentsFile)),
            benign: try BenignCatalog.load(from: read(benignFile)))
    }

    /// Candidate directories holding the default data, in priority order.
    public static func searchDirectories(explicit: String?, executablePath: String?) -> [URL] {
        var out: [URL] = []
        if let explicit { out.append(URL(fileURLWithPath: explicit)) }
        if let env = ProcessInfo.processInfo.environment["WHOREAD_DATA_DIR"] { out.append(URL(fileURLWithPath: env)) }
        if let exe = executablePath {
            let dir = URL(fileURLWithPath: exe).deletingLastPathComponent()
            // App / system extension bundle: Contents/MacOS/x -> Contents/Resources
            out.append(dir.deletingLastPathComponent().appendingPathComponent("Resources"))
            out.append(dir.deletingLastPathComponent().appendingPathComponent("Resources/Data"))
            out.append(dir.appendingPathComponent("WhoReadData"))
        }
        out.append(URL(fileURLWithPath: WhoReadPaths.dataDirectory).appendingPathComponent("defaults"))
        return out
    }

    /// The default data and the directory it came from: the first candidate holding catalog.json.
    ///
    /// With `trustedOwner` (a daemon running as root, daemonfs-4), a candidate is used only when no one
    /// but that user and root could have changed its files, the directory or a directory on the way
    /// (`TrustedFile`): whoever could write them could drop sensitive categories, or make any program a
    /// benign service or hide an AI agent. An explicit directory that fails the check stops the start,
    /// since the other candidates are not what was asked for; any other candidate that fails it is
    /// skipped, never read, and named in the error when nothing else is found.
    public static func locate(explicit: String?, executablePath: String?, trustedOwner: uid_t? = nil) throws -> (DefaultData, URL) {
        var errors: [String] = []
        for (index, dir) in searchDirectories(explicit: explicit, executablePath: executablePath).enumerated() {
            let probe = dir.appendingPathComponent(catalogFile)
            guard FileManager.default.fileExists(atPath: probe.path) else { continue }
            do {
                return (try load(directory: dir, trustedOwner: trustedOwner), dir)
            } catch let problem as TrustedFile.Untrusted where explicit != nil && index == 0 {
                throw DefaultDataError.untrusted(directory: dir.path, problem: problem)
            } catch {
                errors.append("\(dir.path): \(error)")
            }
        }
        throw DefaultDataError.notFound(errors)
    }
}

public enum DefaultDataError: Error, CustomStringConvertible {
    case notFound([String])
    case untrusted(directory: String, problem: TrustedFile.Untrusted)
    public var description: String {
        switch self {
        case .notFound(let errors):
            return "default data (catalog.json, agents.json, benign.json) not found" + (errors.isEmpty ? "" : ": " + errors.joined(separator: "; "))
        case .untrusted(let directory, let problem):
            return "refusing the default data in \(directory): \(problem). Only root may be able to change these files, "
                + "their directory and every directory above it: install them again into such a directory"
        }
    }
}
