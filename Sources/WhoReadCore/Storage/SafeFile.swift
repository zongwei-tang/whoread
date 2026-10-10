import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Careful writes for WhoRead's own state (catalog copies, markers, exports, the kill switch).
///
/// Foundation's `.atomic` writes and `FileManager.createFile` write first and apply permissions
/// afterwards, follow a symlink at the target's temporary location, and inside a sandboxed process
/// stage the temporary copy outside the target directory. These helpers create every file with
/// `O_CREAT|O_EXCL|O_NOFOLLOW` and its final mode from the start, in the target's own directory.
public enum SafeFile {
    public struct Failure: Error, CustomStringConvertible, Equatable {
        public let description: String
        public let errno: Int32
        init(_ what: String, _ path: String, errno e: Int32 = Glibc_errno()) {
            description = "\(what) \(path): \(String(cString: strerror(e)))"
            errno = e
        }
        init(message: String) {
            description = message
            errno = 0
        }
    }

    /// Replaces `path` with `data` atomically. The temporary file is created next to `path`
    /// (`O_CREAT|O_EXCL|O_NOFOLLOW`, `mode` exactly, whatever the umask), written in full, fsynced
    /// and renamed over `path`. rename(2) replaces a symlink at `path` rather than writing through
    /// it. On failure the old file is untouched and the temporary file is removed.
    ///
    /// - Parameter trustedDirectoryOwner: when set, the parent directory must be a real directory
    ///   (not a symlink) owned by this uid and not writable by group or others; otherwise nothing
    ///   is written.
    public static func replace(_ path: String, with data: Data, mode: mode_t = 0o600,
                               trustedDirectoryOwner: uid_t? = nil) throws {
        let dir = parent(of: path)
        if let owner = trustedDirectoryOwner { try checkTrustedDirectory(dir, owner: owner) }
        let base = (path as NSString).lastPathComponent
        var fd: Int32 = -1
        var tmp = ""
        for _ in 0..<16 {
            tmp = (dir as NSString).appendingPathComponent(".\(base).tmp-\(String(UInt32.random(in: .min ... .max), radix: 16))")
            fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
            if fd >= 0 || Glibc_errno() != EEXIST { break }
        }
        guard fd >= 0 else { throw Failure("cannot create a temporary file for", path) }
        var ok = false
        defer {
            if fd >= 0 { close(fd) }
            if !ok { unlink(tmp) }
        }
        guard fchmod(fd, mode) == 0 else { throw Failure("cannot set the mode of", tmp) }
        try writeAll(fd, data, path: tmp)
        guard fsync(fd) == 0 else { throw Failure("cannot sync", tmp) }
        guard close(fd) == 0 else { fd = -1; throw Failure("cannot close", tmp) }
        fd = -1
        guard rename(tmp, path) == 0 else { throw Failure("cannot rename a temporary file to", path) }
        ok = true
        let dfd = open(dir, O_RDONLY | O_CLOEXEC)
        if dfd >= 0 { _ = fsync(dfd); close(dfd) }
    }

    /// Creates `path`, which must not exist yet, with `mode` exactly (`O_EXCL|O_NOFOLLOW`), and
    /// returns a handle that owns the descriptor.
    public static func createNew(_ path: String, mode: mode_t = 0o600) throws -> FileHandle {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw Failure("cannot create", path) }
        guard fchmod(fd, mode) == 0 else {
            let e = Glibc_errno()
            close(fd)
            unlink(path)
            throw Failure("cannot set the mode of", path, errno: e)
        }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    /// Creates `path` with `data` if it does not exist (`O_EXCL|O_NOFOLLOW`, `mode` exactly).
    /// Returns false, without touching anything, when something already exists at `path`.
    @discardableResult
    public static func createIfAbsent(_ path: String, with data: Data = Data(), mode: mode_t = 0o600) throws -> Bool {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        if fd < 0 {
            if Glibc_errno() == EEXIST { return false }
            throw Failure("cannot create", path)
        }
        var ok = false
        defer {
            close(fd)
            if !ok { unlink(path) }
        }
        guard fchmod(fd, mode) == 0 else { throw Failure("cannot set the mode of", path) }
        try writeAll(fd, data, path: path)
        ok = true
        return true
    }

    /// Throws unless `dir` is a real directory (lstat: not a symlink) owned by `owner` and not
    /// writable by group or others.
    public static func checkTrustedDirectory(_ dir: String, owner: uid_t) throws {
        var st = stat()
        guard lstat(dir, &st) == 0 else { throw Failure("cannot inspect", dir) }
        guard (st.st_mode & S_IFMT) == S_IFDIR else {
            throw Failure(message: "\(dir) is not a directory (a symlink or another file type); refusing to use it")
        }
        guard st.st_uid == owner else {
            throw Failure(message: "\(dir) is owned by uid \(st.st_uid), expected \(owner); refusing to use it")
        }
        guard st.st_mode & 0o022 == 0 else {
            throw Failure(message: "\(dir) is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8))); refusing to use it")
        }
    }

    /// Creates `dir` (and missing parents) if needed with `mode`, then checks it like
    /// `checkTrustedDirectory`. An existing directory keeps its mode but must pass the check.
    public static func ensureTrustedDirectory(_ dir: String, owner: uid_t, mode: mode_t = 0o755) throws {
        var st = stat()
        if lstat(dir, &st) != 0 {
            guard Glibc_errno() == ENOENT else { throw Failure("cannot inspect", dir) }
            let up = parent(of: dir)
            if up != dir { try ensureDirectoryExists(up, mode: 0o755) }
            if mkdir(dir, mode) != 0 && Glibc_errno() != EEXIST { throw Failure("cannot create", dir) }
            if lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() {
                _ = chmod(dir, mode)
            }
        }
        try checkTrustedDirectory(dir, owner: owner)
    }

    private static func ensureDirectoryExists(_ dir: String, mode: mode_t) throws {
        var st = stat()
        if stat(dir, &st) == 0 { return }
        let up = parent(of: dir)
        if up != dir { try ensureDirectoryExists(up, mode: mode) }
        if mkdir(dir, mode) != 0 && Glibc_errno() != EEXIST { throw Failure("cannot create", dir) }
    }

    static func parent(of path: String) -> String {
        let p = (path as NSString).deletingLastPathComponent
        return p.isEmpty ? "." : p
    }

    private static func writeAll(_ fd: Int32, _ data: Data, path: String) throws {
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress! + off, buf.count - off)
                if n < 0 {
                    if Glibc_errno() == EINTR { continue }
                    throw Failure("cannot write", path)
                }
                off += n
            }
        }
    }
}

@inline(__always) func Glibc_errno() -> Int32 { errno }
