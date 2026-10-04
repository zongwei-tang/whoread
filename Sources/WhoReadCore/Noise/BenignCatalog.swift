import Foundation

/// System services whose reads are expected noise (`Data/benign.json`): Spotlight, Time Machine,
/// iCloud/File Provider, QuickLook, XProtect…
///
/// Matching is by exact process identity (platform binary + location), never "any platform
/// binary": `cat`, `cp`, `curl` and `osascript` are platform binaries too.
public struct BenignCatalog: Codable, Hashable, Sendable {
    public var version: Int
    public var services: [BenignService]

    public init(version: Int = 1, services: [BenignService]) {
        self.version = version
        self.services = services
    }

    public static func load(from data: Data) throws -> BenignCatalog {
        try JSONDecoder().decode(BenignCatalog.self, from: data)
    }
}

public struct BenignService: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var name: LocalizedText
    /// UI grouping, e.g. "spotlight".
    public var group: String
    public var identity: IdentitySpec

    public init(id: String, name: LocalizedText, group: String, identity: IdentitySpec) {
        self.id = id
        self.name = name
        self.group = group
        self.identity = identity
    }
}

public struct BenignClassifier: Sendable {
    public let catalog: BenignCatalog

    public init(catalog: BenignCatalog) {
        self.catalog = catalog
    }

    func service(for p: ProcessRecord) -> BenignService? {
        catalog.services.first { $0.identity.matches(p) }
    }

    /// Returns the benign service ID if the leaf is a benign service *and* it was started by
    /// launchd or by other benign services. A benign binary launched by a shell, an app or an
    /// agent is not benign — it is attributed and alerted like anything else.
    public func classify(chain: [ProcessNode]) -> String? {
        guard let leaf = chain.first, let service = service(for: leaf.image) else { return nil }
        let ancestors = chain.dropFirst()
        if ancestors.isEmpty {
            // Parent unknown: only trust it if the process itself reports launchd as parent.
            return leaf.image.ppid == 1 ? service.id : nil
        }
        for node in ancestors {
            if node.image.isSystemRoot { continue }
            if self.service(for: node.image) == nil { return nil }
        }
        return service.id
    }
}
