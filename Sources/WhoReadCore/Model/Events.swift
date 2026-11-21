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
    /// Directory listings, and opens of directories (which only list them). Off by default.
    case readdir
    /// A brand-new file, directory or link was created at a path (AUTH_CREATE). Enforcement only.
    case create
    /// Permission bits changed (chmod, or setattrlist with ATTR_CMN_ACCESSMASK).
    case setmode
    /// Owner or group changed (chown, or setattrlist with an owner or group attribute).
    case setowner
    /// ACL set or cleared (chmod +a, or setattrlist with ATTR_CMN_EXTENDED_SECURITY).
    case setacl
    /// A file system was mounted on the path, hiding what was there.
    case mount
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
    /// The source truncated an overlong path (ES: `path_truncated`).
    public var truncated: Bool
    /// From the file's stat when the source reports it; nil = unknown.
    public var isDirectory: Bool?

    public init(path: String, role: TargetRole, access: AccessSet, truncated: Bool = false, isDirectory: Bool? = nil) {
        self.path = path
        self.role = role
        self.access = access
        self.truncated = truncated
        self.isDirectory = isDirectory
    }

    /// Whether `operation` can move this path's content (for a directory, everything below it) to
    /// another path: the source of a data-carrying operation, and an existing directory a rename
    /// lands on. A rename onto a non-empty directory only succeeds as a swap (renamex_np RENAME_SWAP),
    /// which moves the directory to the source path; ES reports no flags, and may report only that
    /// direction. An existing *file* destination is not carried: atomic saves rename a temp file over it.
    public func carriesContent(in operation: FileOperation) -> Bool {
        guard OperationSemantics.carryingOperations.contains(operation) else { return false }
        switch role {
        case .source: return true
        case .destination: return operation == .rename && isDirectory == true
        case .target: return false
        }
    }
}

/// A file operation as reported by a source, before classification.
public struct FileActivity: Sendable {
    public var time: Date
    public var sequence: UInt64?
    public var operation: FileOperation
    public var process: ProcessRecord
    public var targets: [FileTarget]
    /// Carried into the recorded events (`AnalyzedEvent.note`): what the operation and targets alone do
    /// not tell, such as a close that is only possibly a write (`EventNote.mappedWritable`).
    public var note: String?

    public init(time: Date, sequence: UInt64? = nil, operation: FileOperation, process: ProcessRecord, targets: [FileTarget],
                note: String? = nil) {
        self.time = time
        self.sequence = sequence
        self.operation = operation
        self.process = process
        self.targets = targets
        self.note = note
    }
}

/// A path as a source reports it: the string plus what its es_file_t / JSON object says.
public struct ReportedPath: Sendable, Hashable {
    public var path: String
    public var truncated: Bool
    public var isDirectory: Bool?

    public init(_ path: String, truncated: Bool = false, isDirectory: Bool? = nil) {
        self.path = path
        self.truncated = truncated
        self.isDirectory = isDirectory
    }
}

/// Access semantics per operation. Shared by the eslogger parser and the native ES source so
/// both backends classify identically.
///
/// Data-carrying operations (rename, clone, copyfile, link, exchangedata) count as a *read* of
/// their source: they can move sensitive content outside the monitored prefixes without an open.
public enum OperationSemantics {
    /// Operations that carry a source's content (and, for directories, everything below it).
    public static let carryingOperations: Set<FileOperation> = [.rename, .clone, .link, .exchangedata, .copyfile]

    public static let fread: UInt32 = 0x1
    public static let fwrite: UInt32 = 0x2
    /// O_TRUNC (sys/fcntl.h). The kernel fflag keeps the open(2) bits above FREAD/FWRITE, and XNU
    /// authorizes WRITE_DATA for O_TRUNC whatever the access mode (vn_authorize_open_existing), so
    /// open(O_RDONLY|O_TRUNC) can empty a file without FWRITE: a write.
    public static let ftrunc: UInt32 = 0x400
    /// O_DIRECTORY as carried in the kernel fflag (the documented eslogger sample fflag 0x1100001
    /// is FREAD | O_DIRECTORY | O_CLOEXEC).
    public static let fdirectory: UInt32 = 0x0010_0000

    /// st_mode file-type bits.
    public static func isDirectory(mode: UInt32) -> Bool { mode & 0o170000 == 0o040000 }

    public static func openAccess(fflag: UInt32) -> AccessSet {
        var a: AccessSet = []
        if fflag & fread != 0 { a.insert(.read) }
        if fflag & (fwrite | ftrunc) != 0 { a.insert(.write) }
        // An fflag with neither bit (O_EVTONLY-style opens) is metadata-only.
        return a
    }

    /// An open. Opening a directory only lists it, so it is reported as `readdir` (off by default)
    /// rather than as a read of the category.
    public static func open(_ file: ReportedPath, fflag: UInt32) -> (FileOperation, [FileTarget]) {
        let dir = file.isDirectory ?? (fflag & fdirectory != 0)
        let access = openAccess(fflag: fflag)
        if dir && !access.contains(.write) {
            return (.readdir, readdir(file))
        }
        return (.open, [FileTarget(path: file.path, role: .target, access: access, truncated: file.truncated,
                                   isDirectory: file.isDirectory)])
    }

    public static func open(path: String, fflag: UInt32, truncated: Bool = false) -> [FileTarget] {
        [FileTarget(path: path, role: .target, access: openAccess(fflag: fflag), truncated: truncated)]
    }

    public static func close(_ file: ReportedPath, modified: Bool) -> [FileTarget] {
        guard modified else { return [] }
        return [FileTarget(path: file.path, role: .target, access: .write, truncated: file.truncated, isDirectory: file.isDirectory)]
    }

    public static func close(path: String, modified: Bool, truncated: Bool = false) -> [FileTarget] {
        close(ReportedPath(path, truncated: truncated), modified: modified)
    }

    /// A rename. An existing directory at the destination is read as well as written: a rename can only
    /// land on a non-empty one as a swap, which moves it (and everything below it) to the source path
    /// (see `FileTarget.carriesContent`). An existing file there is only overwritten (atomic saves).
    public static func rename(_ source: ReportedPath, _ destination: ReportedPath) -> [FileTarget] {
        [
            FileTarget(path: source.path, role: .source, access: .readWrite, truncated: source.truncated, isDirectory: source.isDirectory),
            FileTarget(path: destination.path, role: .destination, access: destination.isDirectory == true ? .readWrite : .write,
                       truncated: destination.truncated, isDirectory: destination.isDirectory),
        ]
    }

    public static func rename(source: String, destination: String) -> [FileTarget] {
        rename(ReportedPath(source), ReportedPath(destination))
    }

    public static func clone(_ source: ReportedPath, _ destination: ReportedPath) -> [FileTarget] {
        [
            FileTarget(path: source.path, role: .source, access: .read, truncated: source.truncated, isDirectory: source.isDirectory),
            FileTarget(path: destination.path, role: .destination, access: .write, truncated: destination.truncated),
        ]
    }

    public static func clone(source: String, destination: String) -> [FileTarget] {
        clone(ReportedPath(source), ReportedPath(destination))
    }

    public static func copyfile(_ source: ReportedPath, _ destination: ReportedPath) -> [FileTarget] { clone(source, destination) }
    public static func copyfile(source: String, destination: String) -> [FileTarget] { clone(source: source, destination: destination) }
    public static func link(_ source: ReportedPath, _ destination: ReportedPath) -> [FileTarget] { clone(source, destination) }
    public static func link(source: String, destination: String) -> [FileTarget] { clone(source: source, destination: destination) }

    public static func unlink(_ file: ReportedPath) -> [FileTarget] {
        [FileTarget(path: file.path, role: .target, access: .write, truncated: file.truncated, isDirectory: file.isDirectory)]
    }

    public static func unlink(path: String) -> [FileTarget] { unlink(ReportedPath(path)) }

    public static func truncate(_ file: ReportedPath) -> [FileTarget] {
        [FileTarget(path: file.path, role: .target, access: .write, truncated: file.truncated, isDirectory: file.isDirectory)]
    }

    public static func truncate(path: String) -> [FileTarget] { truncate(ReportedPath(path)) }

    public static func exchangedata(_ a: ReportedPath, _ b: ReportedPath) -> [FileTarget] {
        [
            FileTarget(path: a.path, role: .source, access: .readWrite, truncated: a.truncated, isDirectory: a.isDirectory),
            FileTarget(path: b.path, role: .destination, access: .readWrite, truncated: b.truncated, isDirectory: b.isDirectory),
        ]
    }

    public static func exchangedata(_ a: String, _ b: String) -> [FileTarget] { exchangedata(ReportedPath(a), ReportedPath(b)) }

    public static func readdir(_ dir: ReportedPath) -> [FileTarget] {
        [FileTarget(path: dir.path, role: .target, access: .read, truncated: dir.truncated, isDirectory: true)]
    }

    public static func readdir(path: String) -> [FileTarget] { readdir(ReportedPath(path)) }

    /// `isDirectory` (from the created object's stat, when the source has one) tells a new symlink or
    /// node from a new directory: only the first can redirect a monitored prefix below it.
    public static func create(_ file: ReportedPath) -> [FileTarget] {
        [FileTarget(path: file.path, role: .destination, access: .write, truncated: file.truncated, isDirectory: file.isDirectory)]
    }

    public static func create(path: String) -> [FileTarget] { create(ReportedPath(path)) }

    /// A change of permission bits, owner or ACL (setmode, setowner, setacl): a write to the file's
    /// metadata. `chmod 644 ~/.ssh/id_ed25519` or an ACL granting everyone read exposes a key to the
    /// other users of the Mac without any open.
    public static func attributes(_ file: ReportedPath) -> [FileTarget] {
        [FileTarget(path: file.path, role: .target, access: .write, truncated: file.truncated, isDirectory: file.isDirectory)]
    }

    /// setattrlist(2) can change the same metadata as chmod, chown and chmod +a, but ES reports it as
    /// its own event. Which operation a set of common attributes (`attrlist.commonattr`) amounts to, or
    /// nil when it changes none of them (times, Finder info, flags…).
    public static func setattrlistOperation(commonattr: UInt32) -> FileOperation? {
        if commonattr & attrAccessMask != 0 { return .setmode }
        if commonattr & attrExtendedSecurity != 0 { return .setacl }
        if commonattr & (attrOwnerID | attrGroupID | attrUUID | attrGroupUUID) != 0 { return .setowner }
        return nil
    }

    // sys/attr.h common attributes.
    public static let attrOwnerID: UInt32 = 0x0000_8000
    public static let attrGroupID: UInt32 = 0x0001_0000
    public static let attrAccessMask: UInt32 = 0x0002_0000
    public static let attrExtendedSecurity: UInt32 = 0x0040_0000
    public static let attrUUID: UInt32 = 0x0080_0000
    public static let attrGroupUUID: UInt32 = 0x0100_0000

    /// A file system mounted on `mountPoint` (statfs f_mntonname) replaces what is visible there: a
    /// write to it, and to everything below it (Analyzer: a mount on ~/.config is a write to gh,
    /// gcloud…), except on a home or above one, where network and FileVault homes are mounted at
    /// login. Nor is the usual place for volumes, /Volumes/<name>, judged: every disk, disk image,
    /// share or decrypted vault is mounted there (the "volumes" category covers what is on them, not
    /// their arrival), and a mount over a monitored path inside a volume is still seen.
    public static func mount(mountPoint: String) -> [FileTarget] {
        guard !mountPoint.isEmpty else { return [] }
        let parts = PathNormalizer.components(PathNormalizer().normalize(mountPoint))
        if parts.count == 2 && PathNormalizer.fold(parts[0]) == "volumes" { return [] }
        return [FileTarget(path: mountPoint, role: .target, access: .write, isDirectory: true)]
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
