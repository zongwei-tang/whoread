import Foundation

/// How bad it is when a file in a category is touched by something unexpected.
public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case medium
    case high
    case critical

    public var rank: Int {
        switch self {
        case .medium: return 0
        case .high: return 1
        case .critical: return 2
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

/// A single kind of access, used for baseline triples and rule matching.
public enum AccessKind: String, Codable, CaseIterable, Sendable {
    case read
    case write
}

/// The set of accesses an operation implies for one path (an open with FREAD|FWRITE is both).
public struct AccessSet: OptionSet, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let read = AccessSet(rawValue: 1 << 0)
    public static let write = AccessSet(rawValue: 1 << 1)
    public static let readWrite: AccessSet = [.read, .write]

    public var kinds: [AccessKind] {
        var out: [AccessKind] = []
        if contains(.read) { out.append(.read) }
        if contains(.write) { out.append(.write) }
        return out
    }

    public init(_ kind: AccessKind) {
        self = kind == .read ? .read : .write
    }

    /// "read", "write", "read+write" or "none".
    public var label: String {
        switch (contains(.read), contains(.write)) {
        case (true, true): return "read+write"
        case (true, false): return "read"
        case (false, true): return "write"
        default: return "none"
        }
    }

    public init?(label: String) {
        switch label {
        case "read": self = .read
        case "write": self = .write
        case "read+write", "readwrite", "rw": self = .readWrite
        case "none": self = []
        default: return nil
        }
    }
}

extension AccessSet: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self), let v = AccessSet(label: s) {
            self = v
        } else {
            self = AccessSet(rawValue: try c.decode(UInt8.self))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(label)
    }
}

/// UI languages. Everything user-visible exists in both.
public enum Language: String, Codable, CaseIterable, Sendable {
    case en
    case zhHans = "zh-Hans"

    /// Picks the first supported language from a preference list such as `Locale.preferredLanguages`.
    public static func preferred(from identifiers: [String]) -> Language {
        for id in identifiers {
            let lower = id.lowercased()
            if lower.hasPrefix("zh") {
                // Traditional Chinese users still get Simplified rather than English.
                return .zhHans
            }
            if lower.hasPrefix("en") { return .en }
        }
        return .en
    }
}

/// A display string in every supported language. Decodes from {"en": "...", "zh-Hans": "..."}.
public struct LocalizedText: Codable, Hashable, Sendable {
    public var en: String
    public var zhHans: String

    public init(en: String, zhHans: String) {
        self.en = en
        self.zhHans = zhHans
    }

    public init(_ both: String) {
        self.en = both
        self.zhHans = both
    }

    public func resolve(_ language: Language) -> String {
        switch language {
        case .en: return en
        case .zhHans: return zhHans.isEmpty ? en : zhHans
        }
    }

    enum CodingKeys: String, CodingKey {
        case en
        case zhHans = "zh-Hans"
    }

    public init(from decoder: Decoder) throws {
        if let single = try? decoder.singleValueContainer().decode(String.self) {
            self.init(single)
            return
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let en = try c.decode(String.self, forKey: .en)
        self.init(en: en, zhHans: try c.decodeIfPresent(String.self, forKey: .zhHans) ?? en)
    }
}
