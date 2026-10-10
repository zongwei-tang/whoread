import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Which homes `~/` expands to. The daemon runs as root, so `~` means every real user.
public enum HomeDirectories {
    /// nobody / nogroup style accounts (65534, and -2 / -1 as uid_t).
    static let nobodyUIDs: Set<uid_t> = [65534, 4_294_967_294, 4_294_967_295]

    /// Not homes even when a passwd entry says so.
    static let excluded: Set<String> = ["/", "/var/empty", "/var/root", "/private/var/root", "/dev/null", "/nonexistent",
                                         "/var/empty/", "/root"]

    /// Local users with a home directory that exists: uid ≥ 501 on macOS, ≥ 1000 elsewhere. Homes
    /// outside /Users (another volume, a network home) count too, plus their realpath spelling.
    public static func discover() -> [String] {
        #if os(macOS)
        let minUID: uid_t = 501
        #else
        let minUID: uid_t = 1000
        #endif
        var entries: [(uid: uid_t, dir: String)] = []
        setpwent()
        while let pw = getpwent() {
            if let dir = pw.pointee.pw_dir { entries.append((pw.pointee.pw_uid, String(cString: dir))) }
        }
        endpwent()
        // Directory-service accounts (network or mobile AD homes) are often not enumerated by getpwent;
        // the console user is looked up directly.
        if let uid = ConsoleUser.uid(), let pw = getpwuid(uid), let dir = pw.pointee.pw_dir {
            entries.append((uid, String(cString: dir)))
        }
        var homes = select(entries, minUID: minUID, isDirectory: { home in
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: home, isDirectory: &isDir) && isDir.boolValue
        }, resolve: { home in
            guard let r = realpath(home, nil) else { return nil }
            defer { free(r) }
            return String(cString: r)
        })
        if homes.isEmpty, let h = ProcessInfo.processInfo.environment["HOME"], h != "/var/root", h != "/root" {
            homes.append(h)
        }
        return homes
    }

    /// The policy behind `discover`, over passwd entries (uid, pw_dir). Separate so it can be tested
    /// without the host's user database.
    static func select(_ entries: [(uid: uid_t, dir: String)], minUID: uid_t, isDirectory: (String) -> Bool,
                       resolve: (String) -> String?) -> [String] {
        var homes = Set<String>()
        for (uid, home) in entries {
            // Directory-service users have large uids (AD maps them from GUIDs); only nobody is excluded.
            guard uid >= minUID, !nobodyUIDs.contains(uid) else { continue }
            guard home.hasPrefix("/"), !excluded.contains(home), isDirectory(home) else { continue }
            homes.insert(home)
            if let resolved = resolve(home), resolved != home && !excluded.contains(resolved) { homes.insert(resolved) }
        }
        return homes.sorted()
    }
}

/// The user at the console (owner of /dev/console). Non-root clients are only served if they are
/// this user, so one user cannot read another user's access history.
public enum ConsoleUser {
    public static func uid() -> uid_t? {
        var st = stat()
        guard stat("/dev/console", &st) == 0 else { return nil }
        return st.st_uid
    }
}
