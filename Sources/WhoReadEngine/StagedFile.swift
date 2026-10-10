import Foundation
import WhoReadCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// An output file written as `<name>.partial` next to its final path and renamed over it by `commit()`,
/// so a failed export never leaves a truncated file (`whoread export --output`, privacy-4).
///
/// The export holds every user's history, and `sudo whoread export` may write into a folder that an
/// agent running as that user can change. So: the directory is opened once and every later step goes
/// through that descriptor (swapping the folder for a link changes nothing); the `.partial` file is
/// created with `O_EXCL|O_NOFOLLOW` and its final mode (0600) whatever the umask, without inherited
/// ACL entries; the output path is refused when it is a link or not a regular file (never written
/// through, never replaced); and only the very file this process wrote is renamed into place. Under sudo, a file written into a folder
/// of the user who ran sudo is given to that user (otherwise only root could read their export).
public final class StagedFile {
    public struct Failure: Error, CustomStringConvertible {
        public let description: String
    }

    public struct Owner: Equatable {
        public let uid: uid_t
        /// `gid_t.max` (-1): left as is.
        public let gid: gid_t
        public init(uid: uid_t, gid: gid_t) {
            self.uid = uid
            self.gid = gid
        }
    }

    public let path: String
    /// Owns the `.partial` file's descriptor. Write through it; `commit` or `abandon` closes it.
    public let handle: FileHandle
    private let dirFD: Int32
    private let name: String
    private let partialName: String
    private let device: dev_t
    private let inode: ino_t
    private var finished = false

    public init(path: String, mode: mode_t = 0o600) throws {
        guard !path.isEmpty, !path.hasSuffix("/") else { throw Failure(description: "\(path) names a directory") }
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty, name != ".", name != ".." else { throw Failure(description: "\(path) names a directory") }
        let dir = TrustedDirectory.parent(of: path)
        let dirFD = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard dirFD >= 0 else { throw Failure(description: "cannot open \(dir): \(String(cString: strerror(errno)))") }
        var ok = false
        defer { if !ok { close(dirFD) } }
        try StagedFile.checkReplaceable(dirFD, name, path: path)

        let partial = name + ".partial"
        let fd = openat(dirFD, partial, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else {
            let e = errno
            throw Failure(description: "cannot create \(path).partial: \(String(cString: strerror(e)))"
                          + (e == EEXIST ? " (remove a leftover file first)" : ""))
        }
        var st = stat(), dirStat = stat()
        // The mode alone is not enough: the file inherits the folder's inheritable ACL entries (e.g.
        // `group:staff allow read,file_inherit`), which would let others read every user's history.
        var setUp = fchmod(fd, mode) == 0 && SafeFile.removeACL(fd: fd) && fstat(fd, &st) == 0 && fstat(dirFD, &dirStat) == 0
        if setUp, let owner = StagedFile.owner(euid: geteuid(), environment: ProcessInfo.processInfo.environment,
                                               directoryOwner: dirStat.st_uid) {
            setUp = fchown(fd, owner.uid, owner.gid) == 0
        }
        guard setUp else {
            let e = errno
            close(fd)
            unlinkat(dirFD, partial, 0)
            throw Failure(description: "cannot set up \(path).partial: \(String(cString: strerror(e)))")
        }
        self.path = path
        self.name = name
        self.partialName = partial
        self.dirFD = dirFD
        self.device = st.st_dev
        self.inode = st.st_ino
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        ok = true
    }

    deinit {
        if !finished { abandon() }
    }

    /// Closes the file and renames it over the output path.
    public func commit() throws {
        guard !finished else { return }
        finished = true
        defer { close(dirFD) }
        // Only the file written here: someone who can write the folder may have put another one there.
        guard isOurs() else {
            try? handle.close()
            throw Failure(description: "\(path).partial was replaced while the export was written; nothing was renamed")
        }
        do {
            try handle.close()
            try StagedFile.checkReplaceable(dirFD, name, path: path)
            guard renameat(dirFD, partialName, dirFD, name) == 0 else {
                throw Failure(description: "cannot rename \(path).partial: \(String(cString: strerror(errno)))")
            }
        } catch {
            if isOurs() { unlinkat(dirFD, partialName, 0) }
            throw error
        }
    }

    /// Closes the file and removes it, if it is still the one written here.
    public func abandon() {
        guard !finished else { return }
        finished = true
        try? handle.close()
        if isOurs() { unlinkat(dirFD, partialName, 0) }
        close(dirFD)
    }

    /// Who should own an export written by root: the user who ran `sudo`, when it goes into a folder that
    /// user owns (they will read it there); nil otherwise (root keeps it, 0600).
    public static func owner(euid: uid_t, environment: [String: String], directoryOwner: uid_t) -> Owner? {
        guard euid == 0, let s = environment["SUDO_UID"], let uid = uid_t(s), uid != 0, uid == directoryOwner else { return nil }
        return Owner(uid: uid, gid: environment["SUDO_GID"].flatMap { gid_t($0) } ?? gid_t.max)
    }

    private func isOurs() -> Bool {
        var st = stat()
        return fstatat(dirFD, partialName, &st, AT_SYMLINK_NOFOLLOW) == 0 && st.st_dev == device && st.st_ino == inode
    }

    /// Absent or a regular file: anything else (a link, even a dangling one, a directory) is refused.
    private static func checkReplaceable(_ dirFD: Int32, _ name: String, path: String) throws {
        var st = stat()
        guard fstatat(dirFD, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else { return }
        let type = st.st_mode & S_IFMT
        guard type != S_IFREG else { return }
        let what = type == S_IFLNK ? "a symbolic link" : type == S_IFDIR ? "a directory" : "not a regular file"
        throw Failure(description: "\(path) is \(what); refusing to replace it (remove it, or choose another name)")
    }
}
