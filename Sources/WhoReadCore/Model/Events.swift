import Foundation

/// File operations we observe. Mirrors the ES event types we subscribe to.
public enum FileOperation: String, Codable, CaseIterable, Sendable {
    case open
    /// Only recorded when the file was modified.
    case close
    case rename
    case clone
    case copyfile
    case link
    case unlink
    case truncate
    case exchangedata
    case readdir
    /// A brand-new file was created at a path (AUTH/NOTIFY_CREATE). Not subscribed by default.
    case create
}

/// The part a path plays in an operation.
public enum TargetRole: String, Codable, Sendable {
    case target
    case source
    case destination
}

/// One path involved in a file operation, with the access the operation implies for it.
public struct FileTarget: Codable, Hashable, Sendable {
    public var path: String
    public var role: TargetRole
    public var access: AccessSet
    public var truncated: Bool

    public init(path: String, role: TargetRole, access: AccessSet, truncated: Bool = false) {
        self.path = path
        self.role = role
        self.access = access
        self.truncated = truncated
    }
}

/// A file operation as reported by a source, before classification.
public struct FileActivity: Sendable {
    public var time: Date
    public var sequence: UInt64?
    public var operation: FileOperation
    public var process: ProcessRecord
    public var targets: [FileTarget]

    public init(time: Date, sequence: UInt64? = nil, operation: FileOperation, process: ProcessRecord, targets: [FileTarget]) {
        self.time = time
        self.sequence = sequence
        self.operation = operation
        self.process = process
        self.targets = targets
    }
}

/// Access semantics per operation. Shared by the eslogger parser and the native ES source so
/// both backends classify identically.
///
/// Data-carrying operations (rename, clone, copyfile, link, exchangedata) count as a *read* of
/// their source: they can move sensitive content outside the monitored prefixes without an open.
public enum OperationSemantics {
    public static let fread: UInt32 = 0x1
    public static let fwrite: UInt32 = 0x2

    public static func openAccess(fflag: UInt32) -> AccessSet {
        var a: AccessSet = []
        if fflag & fread != 0 { a.insert(.read) }
        if fflag & fwrite != 0 { a.insert(.write) }
        // O_RDONLY is 0 in userland but the kernel's fflag always carries FREAD for reads;
        // an fflag with neither bit (e.g. O_EVTONLY / O_SEARCH-style opens) is metadata-only.
        return a
    }

    public static func open(path: String, fflag: UInt32, truncated: Bool = false) -> [FileTarget] {
        [FileTarget(path: path, role: .target, access: openAccess(fflag: fflag), truncated: truncated)]
    }

    public static func close(path: String, modified: Bool, truncated: Bool = false) -> [FileTarget] {
        guard modified else { return [] }
        return [FileTarget(path: path, role: .target, access: .write, truncated: truncated)]
    }

    public static func rename(source: String, destination: String) -> [FileTarget] {
        [
            FileTarget(path: source, role: .source, access: .readWrite),
            FileTarget(path: destination, role: .destination, access: .write),
        ]
    }

    public static func clone(source: String, destination: String) -> [FileTarget] {
        [
            FileTarget(path: source, role: .source, access: .read),
            FileTarget(path: destination, role: .destination, access: .write),
        ]
    }

    public static func copyfile(source: String, destination: String) -> [FileTarget] {
        clone(source: source, destination: destination)
    }

    public static func link(source: String, destination: String) -> [FileTarget] {
        clone(source: source, destination: destination)
    }

    public static func unlink(path: String) -> [FileTarget] {
        [FileTarget(path: path, role: .target, access: .write)]
    }

    public static func truncate(path: String) -> [FileTarget] {
        [FileTarget(path: path, role: .target, access: .write)]
    }

    public static func exchangedata(_ a: String, _ b: String) -> [FileTarget] {
        [
            FileTarget(path: a, role: .source, access: .readWrite),
            FileTarget(path: b, role: .destination, access: .readWrite),
        ]
    }

    public static func readdir(path: String) -> [FileTarget] {
        [FileTarget(path: path, role: .target, access: .read)]
    }

    public static func create(path: String) -> [FileTarget] {
        [FileTarget(path: path, role: .destination, access: .write)]
    }

    /// Joins a destination directory and a file name the way ES reports "new path" destinations.
    public static func join(dir: String, name: String) -> String {
        if dir.hasSuffix("/") { return dir + name }
        return dir + "/" + name
    }
}

/// What an event source emits.
public enum SourceEvent: Sendable {
    case fork(parent: ProcessRecord, child: ProcessRecord, time: Date)
    /// `process` is the image before exec, `target` the new image (with argv when available).
    case exec(process: ProcessRecord, target: ProcessRecord, time: Date)
    case exit(process: ProcessRecord, time: Date)
    case file(FileActivity)

    public var time: Date {
        switch self {
        case .fork(_, _, let t), .exec(_, _, let t), .exit(_, let t): return t
        case .file(let f): return f.time
        }
    }
}
