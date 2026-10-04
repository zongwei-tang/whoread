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

    /// Loads all three files from a directory.
    public static func load(directory: URL) throws -> DefaultData {
        func read(_ name: String) throws -> Data {
            try Data(contentsOf: directory.appendingPathComponent(name))
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
            out.append(dir.appendingPathComponent("WhoReadData"))
        }
        out.append(URL(fileURLWithPath: WhoReadPaths.dataDirectory).appendingPathComponent("defaults"))
        return out
    }

    public static func locate(explicit: String?, executablePath: String?) throws -> (DefaultData, URL) {
        var errors: [String] = []
        for dir in searchDirectories(explicit: explicit, executablePath: executablePath) {
            let probe = dir.appendingPathComponent(catalogFile)
            guard FileManager.default.fileExists(atPath: probe.path) else { continue }
            do {
                return (try load(directory: dir), dir)
            } catch {
                errors.append("\(dir.path): \(error)")
            }
        }
        throw DefaultDataError.notFound(errors)
    }
}

public enum DefaultDataError: Error, CustomStringConvertible {
    case notFound([String])
    public var description: String {
        switch self {
        case .notFound(let errors):
            return "default data (catalog.json, agents.json, benign.json) not found" + (errors.isEmpty ? "" : ": " + errors.joined(separator: "; "))
        }
    }
}
