import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Reads files that only the daemon's user (root) should have been able to write: the Mach service
/// name the daemon leaves in its data directory for the CLI and the app, and the catalog, agent and
/// benign lists a root daemon starts from. Whoever could change such a file could point the app at
/// another service, or rewrite what counts as sensitive and who counts as an AI agent.
///
/// A file is trusted when:
/// - it is a regular file (not a link, not a FIFO) with one name, owned by `owner`, and neither its
///   mode nor an ACL lets anyone else change it;
/// - its directory is a real directory (not a link) owned by `owner` that others cannot change;
/// - every directory on the way is owned by `owner` or root, and others cannot rename or replace
///   its entries (a sticky one like /private/tmp passes). Links on the way are followed, and the
///   directories their targets go through are checked the same way.
public enum TrustedFile {
    public struct Untrusted: Error, CustomStringConvertible, Equatable {
        public let path: String
        public let reason: String
        public var description: String { "\(path) \(reason)" }
    }

    /// The name of the file the daemon writes its Mach service name to, in its data directory.
    public static let machServiceFile = "mach-service"

    /// The Mach service name the running daemon announced in `dataDirectory`, or nil when it has
    /// announced none there (no directory, no file). Throws `Untrusted` when the file could have been
    /// written by someone other than `owner` (root), or does not hold a service name: the caller then
    /// uses its built-in name.
    public static func machServiceName(inDataDirectory dataDirectory: String, owner: uid_t = 0) throws -> String? {
        let path = (PathClassifier.stripTrailingSlash(dataDirectory) as NSString).appendingPathComponent(machServiceFile)
        var st = stat()
        guard lstat(path, &st) == 0 else {
            if errno == ENOENT || errno == ENOTDIR { return nil }
            throw Untrusted(path: path, reason: "cannot be inspected: \(String(cString: strerror(errno)))")
        }
        let data = try read(path, owner: owner, limit: 1024)
        let name = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_".unicodeScalars)
        guard !name.isEmpty, name.utf8.count <= 255, !name.hasPrefix("."), name.unicodeScalars.allSatisfy(allowed.contains) else {
            throw Untrusted(path: path, reason: "does not hold a Mach service name")
        }
        return name
    }

    /// The contents of `path` (at most `limit` bytes) when it and the directories on the way to it
    /// pass the checks above; otherwise throws `Untrusted`. The file is opened without following a
    /// link and without waiting on a FIFO, and read through the descriptor that was checked.
    public static func read(_ path: String, owner: uid_t, limit: Int) throws -> Data {
        try checkDirectory(parent(of: path), owner: owner)
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            if e == ELOOP { throw Untrusted(path: path, reason: "is a symbolic link") }
            throw Untrusted(path: path, reason: "cannot be opened: \(String(cString: strerror(e)))")
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw Untrusted(path: path, reason: "cannot be inspected: \(String(cString: strerror(errno)))")
        }
        if let reason = fileProblem(st, owner: owner) ?? (SafeFile.aclAllows(fd: fd, changing: true)
            ? "has an access control list that lets others change it" : nil) {
            throw Untrusted(path: path, reason: reason)
        }
        guard st.st_size <= off_t(limit) else { throw Untrusted(path: path, reason: "is larger than \(limit) bytes") }
        var data = Data()
        let chunk = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunk)
        while data.count <= limit {
            let n = buffer.withUnsafeMutableBytes { posixRead(fd, $0.baseAddress!, chunk) }
            if n < 0 {
                if errno == EINTR { continue }
                throw Untrusted(path: path, reason: "cannot be read: \(String(cString: strerror(errno)))")
            }
            if n == 0 { break }
            data.append(contentsOf: buffer[0..<n])
        }
        guard data.count <= limit else { throw Untrusted(path: path, reason: "is larger than \(limit) bytes") }
        return data
    }

    /// Throws `Untrusted` unless `dir` is a real directory owned by `owner` that others cannot change,
    /// reached only through directories others cannot change (see above).
    public static func checkDirectory(_ dir: String, owner: uid_t) throws {
        let dir = PathClassifier.stripTrailingSlash(dir)
        if let problem = untrustedAncestor(of: dir, owner: owner) { throw problem }
        var st = stat()
        guard lstat(dir, &st) == 0 else {
            throw Untrusted(path: dir, reason: "cannot be inspected: \(String(cString: strerror(errno)))")
        }
        let reason: String?
        if (st.st_mode & S_IFMT) != S_IFDIR {
            reason = "is a symbolic link or not a directory"
        } else if st.st_uid != owner {
            reason = "is owned by uid \(st.st_uid), not \(ownerName(owner))"
        } else if st.st_mode & 0o022 != 0 {
            reason = "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
        } else if SafeFile.aclAllows(path: dir, changing: true) {
            reason = aclReason
        } else {
            reason = nil
        }
        if let reason { throw Untrusted(path: dir, reason: reason) }
    }

    /// The first directory on the way to `path` (`path` itself excluded) that someone other than
    /// `owner` or root could rename or replace entries in. Links on the way are followed (at most 32).
    static func untrustedAncestor(of path: String, owner: uid_t) -> Untrusted? {
        let absolute = path.hasPrefix("/") ? path : FileManager.default.currentDirectoryPath + "/" + path
        // Components still to walk, last one first (a link's target is pushed in front of the rest).
        var pending = Array(parent(of: absolute).split(separator: "/").map(String.init).reversed())
        var current = "/"
        var links = 0
        var st = stat()
        guard lstat("/", &st) == 0 else { return Untrusted(path: "/", reason: "cannot be inspected") }
        if let reason = ancestorProblem("/", st, owner: owner) { return Untrusted(path: "/", reason: reason) }
        while let name = pending.popLast() {
            if name.isEmpty || name == "." { continue }
            if name == ".." {
                current = parent(of: current)
                continue
            }
            let next = current == "/" ? "/" + name : current + "/" + name
            guard lstat(next, &st) == 0 else {
                return Untrusted(path: next, reason: "cannot be inspected: \(String(cString: strerror(errno)))")
            }
            switch st.st_mode & S_IFMT {
            case S_IFLNK:
                links += 1
                guard links <= 32, let target = readLink(next) else {
                    return Untrusted(path: next, reason: "is a link that cannot be followed")
                }
                if target.hasPrefix("/") { current = "/" }
                pending.append(contentsOf: target.split(separator: "/").map(String.init).reversed())
            case S_IFDIR:
                if let reason = ancestorProblem(next, st, owner: owner) { return Untrusted(path: next, reason: reason) }
                current = next
            default:
                return Untrusted(path: next, reason: "is not a directory")
            }
        }
        return nil
    }

    private static func ancestorProblem(_ path: String, _ st: stat, owner: uid_t) -> String? {
        if st.st_uid != 0 && st.st_uid != owner { return "is owned by uid \(st.st_uid), not \(ownerName(owner)) or root" }
        if st.st_mode & 0o022 != 0 && st.st_mode & S_ISVTX == 0 {
            return "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
        }
        // Also when sticky: an ACL's delete_child is not limited by the sticky bit.
        return SafeFile.aclAllows(path: path, changing: true) ? aclReason : nil
    }

    private static func fileProblem(_ st: stat, owner: uid_t) -> String? {
        if (st.st_mode & S_IFMT) != S_IFREG { return "is not a regular file" }
        if st.st_uid != owner { return "is owned by uid \(st.st_uid), not \(ownerName(owner))" }
        if st.st_nlink != 1 { return "has \(st.st_nlink) hard links" }
        if st.st_mode & 0o022 != 0 { return "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))" }
        return nil
    }

    private static let aclReason = "has an access control list that lets others add, remove or rename its entries"

    private static func ownerName(_ owner: uid_t) -> String { owner == 0 ? "root" : "uid \(owner)" }

    private static func parent(of path: String) -> String {
        let p = (path as NSString).deletingLastPathComponent
        return p.isEmpty ? "." : p
    }

    private static func readLink(_ path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = readlink(path, &buf, buf.count - 1)
        guard n > 0 else { return nil }
        buf[n] = 0
        return String(cString: buf)
    }
}

/// read(2), which `TrustedFile.read` hides inside the type.
private func posixRead(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
    read(fd, buffer, count)
}
