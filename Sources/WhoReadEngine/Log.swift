import Foundation
import WhoReadCore
import WhoReadIPC

/// Minimal logger: timestamped lines on stderr. The dev LaunchDaemon plist redirects stderr to
/// /Library/Logs/WhoRead/whoreadd.log; the system extension redirects its own stderr to
/// /Library/Logs/WhoRead/extension.log (both root-only). Never logs file contents; paths and process
/// names only, sanitized to one line each.
public enum Log {
    public enum Level: Int, Comparable, Sendable {
        case debug, info, warning, error
        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
    }

    nonisolated(unsafe) public static var minimum: Level = .info
    private static let lock = NSLock()

    public static func debug(_ m: @autoclosure () -> String) { write(.debug, m()) }
    public static func info(_ m: @autoclosure () -> String) { write(.info, m()) }
    public static func warning(_ m: @autoclosure () -> String) { write(.warning, m()) }
    public static func error(_ m: @autoclosure () -> String) { write(.error, m()) }

    private static func write(_ level: Level, _ message: String) {
        guard level >= minimum else { return }
        let tag = ["DEBUG", "INFO", "WARN", "ERROR"][level.rawValue]
        let line = "\(RFC3339.format(Date(), fractionDigits: 3)) \(tag) \(sanitize(message))\n"
        lock.lock()
        FileHandle.standardError.write(Data(line.utf8))
        lock.unlock()
    }
}

extension Log {
    /// File names, rule ids and process names are attacker-controlled: escape control characters and
    /// line separators so one message is always one line (no forged log entries), and cap the length.
    static func sanitize(_ message: String, maxLength: Int = 4096) -> String {
        var out = String.UnicodeScalarView()
        var count = 0
        for s in message.unicodeScalars {
            if count >= maxLength { out.append(contentsOf: "…".unicodeScalars); break }
            if s.value < 0x20 || s.value == 0x7F || (0x80...0x9F).contains(s.value) || s.value == 0x2028 || s.value == 0x2029 {
                out.append(contentsOf: "\\u{\(String(s.value, radix: 16))}".unicodeScalars)
            } else {
                out.append(s)
            }
            count += 1
        }
        return String(out)
    }
}

// MARK: - Log file (macos-3)

extension Log {
    public struct PrivateLogFile {
        /// Open for appending; the caller makes it stderr (dup2) and closes this one.
        public let descriptor: Int32
        /// What was found in the way and renamed (to log once the descriptor is stderr).
        public let movedAside: [String]
    }

    /// Opens `directory/name` for appending, for a daemon whose stderr nobody keeps (the system
    /// extension). The log names files and processes of every user, so the directory is 0700 and the
    /// file 0600, both owned by `owner` (root in production). Everything goes through a descriptor of
    /// the directory, so a link planted at either path is never followed. A directory that is a link,
    /// another user's or writable by others, and a log file that is a link, not a regular file,
    /// another user's or hard-linked elsewhere, is renamed aside (`…untrusted-<time>`, never read or
    /// deleted) and a fresh one created; so is either one with an ACL granting anyone anything (mode
    /// bits do not show it, and fchmod keeps it). Throws when that still does not give a trusted file.
    public static func openPrivateLogFile(directory: String, name: String, owner: uid_t = geteuid(),
                                          now: Date = Date()) throws -> PrivateLogFile {
        var moved: [String] = []
        func fail(_ what: String, _ e: Int32 = errno) -> Error {
            IPCError(.unavailable, "log \(directory)/\(name): \(what)\(e != 0 ? ": \(String(cString: strerror(e)))" : "")")
        }
        func moveAside(_ dirFD: Int32, _ entry: String, _ path: String, _ reason: String) throws {
            for _ in 0..<8 {
                let aside = "\(entry).untrusted-\(Int(now.timeIntervalSince1970))-\(String(UInt16.random(in: .min ... .max), radix: 16))"
                var st = stat()
                guard fstatat(dirFD, aside, &st, AT_SYMLINK_NOFOLLOW) != 0 else { continue }
                guard renameat(dirFD, entry, dirFD, aside) == 0 else { throw fail("cannot move \(path) aside") }
                let dir = TrustedDirectory.parent(of: path)
                moved.append("\(path) \(reason): moved aside to \(dir == "/" ? "" : dir)/\(aside)")
                return
            }
            throw fail("cannot move \(path) aside", 0)
        }

        // The directory, opened without following a link at its own name.
        let parentPath = TrustedDirectory.parent(of: directory)
        let entry = (directory as NSString).lastPathComponent
        let parentFD = open(parentPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parentFD >= 0 else { throw fail("cannot open \(parentPath)") }
        defer { close(parentFD) }
        var dirFD: Int32 = -1
        var created = false, movedDirectory = false
        while dirFD < 0 {
            let fd = openat(parentFD, entry, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if fd < 0 {
                let e = errno
                if e == ENOENT && !created {
                    guard mkdirat(parentFD, entry, 0o700) == 0 || errno == EEXIST else { throw fail("cannot create it") }
                    created = true
                    continue
                }
                guard (e == ELOOP || e == ENOTDIR) && !movedDirectory && !created else { throw fail("cannot open it", e) }
                try moveAside(parentFD, entry, directory, "is a symbolic link or not a directory")
                movedDirectory = true
                continue
            }
            var st = stat()
            guard fstat(fd, &st) == 0 else { close(fd); throw fail("cannot inspect it") }
            let problem: String
            if st.st_uid != owner {
                problem = "is owned by uid \(st.st_uid), not \(TrustedDirectory.ownerName(owner))"
            } else if st.st_mode & 0o022 != 0 {
                problem = "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
            } else if SafeFile.aclAllows(fd: fd, changing: false) {
                // fchmod(0700) keeps an ACL: `everyone allow list,search,add_file` would still open it to all.
                problem = "has an access control list that lets others in"
            } else {
                dirFD = fd
                break
            }
            close(fd)
            // One we made just now that still fails is not ours to give away: fail closed, no loop.
            guard !created && !movedDirectory else { throw fail(problem, 0) }
            try moveAside(parentFD, entry, directory, problem)
            movedDirectory = true
        }
        defer { close(dirFD) }
        // Others may not even list it (the names of rotated or moved-aside logs).
        _ = fchmod(dirFD, 0o700)

        let path = directory + "/" + name
        var movedFile = false
        while true {
            let fd = openat(dirFD, name, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            let e = errno
            var st = stat()
            let problem: String?
            if fd < 0 {
                guard e == ELOOP && !movedFile else { throw fail("cannot open \(path)", e) }
                problem = "is a symbolic link"
            } else if fstat(fd, &st) != 0 {
                close(fd)
                throw fail("cannot inspect \(path)")
            } else if (st.st_mode & S_IFMT) != S_IFREG {
                problem = "is not a regular file"
            } else if st.st_uid != owner {
                problem = "is owned by uid \(st.st_uid), not \(TrustedDirectory.ownerName(owner))"
            } else if st.st_nlink != 1 {
                // Appending would write into the other name's file too (e.g. a root-owned config file).
                problem = "has \(st.st_nlink) hard links"
            } else if SafeFile.aclAllows(fd: fd, changing: false) {
                problem = "has an access control list that lets others in"
            } else {
                problem = nil
            }
            guard let problem else {
                _ = fchmod(fd, 0o600)
                return PrivateLogFile(descriptor: fd, movedAside: moved)
            }
            if fd >= 0 { close(fd) }
            guard !movedFile else { throw fail("\(path) \(problem)", 0) }
            try moveAside(dirFD, name, path, problem)
            movedFile = true
        }
    }

    /// Why the log behind `descriptor` (a daemon's stderr, opened by launchd from the plist) may be
    /// read or changed by someone other than `owner`, or nil. Not a regular file (a terminal, a pipe,
    /// /dev/null): nil.
    public static func privateLogProblem(descriptor: Int32, owner: uid_t) -> String? {
        var st = stat()
        guard fstat(descriptor, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        if st.st_uid != owner { return "the log file is owned by uid \(st.st_uid), not \(TrustedDirectory.ownerName(owner))" }
        if st.st_nlink != 1 { return "the log file has \(st.st_nlink) hard links" }
        if st.st_mode & 0o077 != 0 {
            return "the log file can be read or written by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
        }
        return nil
    }
}

public enum WhoReadVersion {
    public static let string = "0.1.0"
}
