import Foundation
import WhoReadCore
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Enumerates running processes at startup to seed the process tree, and resolves single pids
/// later when an event's parent is unknown.
///
/// macOS: libproc `proc_listallpids` (returns a count), `proc_pidinfo(PROC_PIDTBSDINFO)` (root
/// needed for other users' processes), `proc_pidpath`, and `sysctl(KERN_PROCARGS2)` for argv.
/// Code signing identity is not available here (events carry it); `isPlatformBinary` is guessed
/// from the path until an event reports the real flag.
/// Linux (development only): /proc.
public enum ProcessSnapshot {
    public static func all() -> [ProcessRecord] {
        #if os(macOS)
        return MacProcessSnapshot.all()
        #elseif os(Linux)
        return LinuxProcessSnapshot.all()
        #else
        return []
        #endif
    }

    public static func record(pid: Int32) -> ProcessRecord? {
        #if os(macOS)
        return MacProcessSnapshot.record(pid: pid)
        #elseif os(Linux)
        return LinuxProcessSnapshot.record(pid: pid)
        #else
        return nil
        #endif
    }

    /// Path heuristic for Apple-signed system binaries (corrected by the first real event).
    public static func looksLikePlatformBinary(_ path: String) -> Bool {
        for p in ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/usr/lib/"] where path.hasPrefix(p) {
            return true
        }
        return false
    }
}

#if os(macOS)
import Darwin

enum MacProcessSnapshot {
    // NOT YET COMPILED (written on Linux). Declarations per docs/research/eslogger-libproc-packaging.md §B5.
    static func all() -> [ProcessRecord] {
        let capacity = Int(proc_listallpids(nil, 0)) + 64
        guard capacity > 64 else { return [] }
        var pids = [pid_t](repeating: 0, count: capacity)
        let count = pids.withUnsafeMutableBufferPointer { buf in
            Int(proc_listallpids(buf.baseAddress, Int32(buf.count * MemoryLayout<pid_t>.size)))
        }
        guard count > 0 else { return [] }
        return pids.prefix(count).compactMap { $0 > 0 ? record(pid: $0) : nil }
    }

    static func record(pid: pid_t) -> ProcessRecord? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        var pathBuf = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
        let n = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        let path = n > 0 ? String(cString: pathBuf) : withUnsafeBytes(of: info.pbi_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        let start = Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec) + TimeInterval(info.pbi_start_tvusec) / 1_000_000)
        return ProcessRecord(
            pid: pid, ppid: Int32(info.pbi_ppid), executablePath: path,
            isPlatformBinary: ProcessSnapshot.looksLikePlatformBinary(path), argv: argv(pid: pid), startTime: start,
            euid: info.pbi_uid)
    }

    /// KERN_PROCARGS2: [argc: Int32][exec path\0][\0 padding][argv[0]\0]…[argv[argc-1]\0][env…]
    static func argv(pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return nil }
        let argc = buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var i = 4
        while i < size && buf[i] != 0 { i += 1 } // exec path
        while i < size && buf[i] == 0 { i += 1 } // padding
        var out: [String] = []
        while out.count < Int(argc) && i < size {
            let start = i
            while i < size && buf[i] != 0 { i += 1 }
            out.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        return out
    }
}
#endif

#if os(Linux)
enum LinuxProcessSnapshot {
    static func all() -> [ProcessRecord] {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: "/proc") else { return [] }
        return entries.compactMap { Int32($0) }.compactMap(record)
    }

    static func record(pid: Int32) -> ProcessRecord? {
        guard let stat = try? String(contentsOfFile: "/proc/\(pid)/stat", encoding: .utf8),
              let close = stat.lastIndex(of: ")") else { return nil }
        let fields = stat[stat.index(after: close)...].split(separator: " ")
        guard fields.count > 20, let ppid = Int32(fields[1]) else { return nil }
        let exe = (try? FileManager.default.destinationOfSymbolicLink(atPath: "/proc/\(pid)/exe")) ?? "?"
        var argv: [String]?
        if let data = FileManager.default.contents(atPath: "/proc/\(pid)/cmdline"), !data.isEmpty {
            argv = data.split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
        }
        // starttime is in clock ticks since boot; enough as a stable instance identifier here.
        let ticks = Double(fields[19]) ?? 0
        return ProcessRecord(pid: pid, ppid: ppid, executablePath: exe, isPlatformBinary: ProcessSnapshot.looksLikePlatformBinary(exe),
                             argv: argv, startTime: Date(timeIntervalSince1970: ticks / 100))
    }
}
#endif
