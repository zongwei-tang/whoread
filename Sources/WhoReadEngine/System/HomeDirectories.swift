import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Which homes `~/` expands to. The daemon runs as root, so `~` means every real user.
public enum HomeDirectories {
    /// Local users with a home directory that exists: uid ≥ 501 under /Users on macOS,
    /// uid ≥ 1000 under /home elsewhere.
    public static func discover() -> [String] {
        #if os(macOS)
        let minUID: uid_t = 501
        let root = "/Users/"
        #else
        let minUID: uid_t = 1000
        let root = "/home/"
        #endif
        var homes = Set<String>()
        setpwent()
        while let pw = getpwent() {
            guard pw.pointee.pw_uid >= minUID, pw.pointee.pw_uid < 65534, let dir = pw.pointee.pw_dir else { continue }
            let home = String(cString: dir)
            var isDir: ObjCBool = false
            if home.hasPrefix(root), FileManager.default.fileExists(atPath: home, isDirectory: &isDir), isDir.boolValue {
                homes.insert(home)
            }
        }
        endpwent()
        if homes.isEmpty, let h = ProcessInfo.processInfo.environment["HOME"], h != "/var/root", h != "/root" {
            homes.insert(h)
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
