import Foundation

/// Everything we know about one process image, as reported by an event source
/// (eslogger JSON, a native es_process_t, or a libproc snapshot).
///
/// Optional fields are genuinely optional: eslogger output is not a stable API and
/// libproc snapshots cannot see code signing data.
public struct ProcessRecord: Codable, Hashable, Sendable {
    public var pid: Int32
    /// audit_token pidversion. Distinguishes images of the same pid.
    public var pidVersion: UInt32?
    public var ppid: Int32
    /// ppid at fork time; survives reparenting to launchd.
    public var originalPPID: Int32?
    public var responsiblePID: Int32?
    public var executablePath: String
    public var pathTruncated: Bool
    public var signingID: String?
    public var teamID: String?
    /// Lower-case hex.
    public var cdhash: String?
    public var isPlatformBinary: Bool
    public var argv: [String]?
    /// Fork time. Stays the same across exec, so (pid, startTime) identifies a process instance.
    public var startTime: Date?
    public var euid: UInt32?

    public init(
        pid: Int32,
        pidVersion: UInt32? = nil,
        ppid: Int32,
        originalPPID: Int32? = nil,
        responsiblePID: Int32? = nil,
        executablePath: String,
        pathTruncated: Bool = false,
        signingID: String? = nil,
        teamID: String? = nil,
        cdhash: String? = nil,
        isPlatformBinary: Bool = false,
        argv: [String]? = nil,
        startTime: Date? = nil,
        euid: UInt32? = nil
    ) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.ppid = ppid
        self.originalPPID = originalPPID
        self.responsiblePID = responsiblePID
        self.executablePath = executablePath
        self.pathTruncated = pathTruncated
        self.signingID = signingID
        self.teamID = teamID
        self.cdhash = cdhash
        self.isPlatformBinary = isPlatformBinary
        self.argv = argv
        self.startTime = startTime
        self.euid = euid
    }

    /// Last path component of the executable.
    public var name: String {
        if let slash = executablePath.lastIndex(of: "/") {
            let next = executablePath.index(after: slash)
            if next < executablePath.endIndex { return String(executablePath[next...]) }
        }
        return executablePath
    }

    /// Path of the outermost `.app` bundle containing the executable, if any.
    public var outermostAppBundle: String? { BundlePath.outermostApp(in: executablePath) }

    /// True for launchd and the kernel, which terminate every chain.
    public var isSystemRoot: Bool { pid <= 1 }

    /// Merge fields we did not know before from a newer report of the same image.
    /// Values in `self` win; `other` only fills gaps.
    public func filling(from other: ProcessRecord) -> ProcessRecord {
        var r = self
        if r.pidVersion == nil { r.pidVersion = other.pidVersion }
        if r.originalPPID == nil { r.originalPPID = other.originalPPID }
        if r.responsiblePID == nil { r.responsiblePID = other.responsiblePID }
        if r.signingID == nil { r.signingID = other.signingID }
        if r.teamID == nil { r.teamID = other.teamID }
        if r.cdhash == nil { r.cdhash = other.cdhash }
        if r.argv == nil { r.argv = other.argv }
        if r.startTime == nil { r.startTime = other.startTime }
        if r.euid == nil { r.euid = other.euid }
        if !r.isPlatformBinary && other.isPlatformBinary && r.executablePath == other.executablePath {
            r.isPlatformBinary = true
        }
        return r
    }
}

public enum BundlePath {
    /// "/Applications/Xcode.app/Contents/Applications/Simulator.app/Contents/MacOS/Simulator"
    /// -> "/Applications/Xcode.app"
    public static func outermostApp(in path: String) -> String? {
        appBundles(in: path).first
    }

    /// Every `.app` bundle on the path, outermost first.
    public static func appBundles(in path: String) -> [String] {
        var out: [String] = []
        var current = ""
        for component in path.split(separator: "/") {
            current += current.isEmpty && !path.hasPrefix("/") ? String(component) : "/" + component
            if component.count > 4 && component.lowercased().hasSuffix(".app") {
                out.append(current)
            }
        }
        return out
    }

    /// "Google Chrome" for "/Applications/Google Chrome.app".
    public static func displayName(ofBundle bundlePath: String) -> String {
        var name = bundlePath
        if let slash = name.lastIndex(of: "/") { name = String(name[name.index(after: slash)...]) }
        if name.lowercased().hasSuffix(".app") { name = String(name.dropLast(4)) }
        return name
    }
}
