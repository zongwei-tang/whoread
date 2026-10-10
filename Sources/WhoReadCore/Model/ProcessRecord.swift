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
    /// The responsible process (macOS's "responsible app"); nil when there is none, including when the
    /// source names the process itself (no responsible process, or it has exited).
    public var responsiblePID: Int32?
    /// es_process_t.parent_audit_token (message version >= 4): pid and pidversion of a parent's exact
    /// execution. It replaces `ppid`, so it may name the process that adopted this one; it is only
    /// used when its pid is the fork-time parent's (`ProcessTree.parentExecution`).
    public var parentToken: ProcessToken?
    public var executablePath: String
    public var pathTruncated: Bool
    public var signingID: String?
    public var teamID: String?
    /// Lower-case hex.
    public var cdhash: String?
    public var isPlatformBinary: Bool
    /// es_process_t.cs_validation_category (message version >= 10): the code signing policy the kernel
    /// validated this executable under. nil when the source does not say (older macOS, libproc).
    public var signingCategory: SigningCategory?
    /// es_process_t.codesigning_flags (cs_blobs.h), as the kernel had them when the event was made.
    public var codeSigningFlags: UInt32?
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
        parentToken: ProcessToken? = nil,
        executablePath: String,
        pathTruncated: Bool = false,
        signingID: String? = nil,
        teamID: String? = nil,
        cdhash: String? = nil,
        isPlatformBinary: Bool = false,
        signingCategory: SigningCategory? = nil,
        codeSigningFlags: UInt32? = nil,
        argv: [String]? = nil,
        startTime: Date? = nil,
        euid: UInt32? = nil
    ) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.ppid = ppid
        self.originalPPID = originalPPID
        self.responsiblePID = responsiblePID
        self.parentToken = parentToken
        self.executablePath = executablePath
        self.pathTruncated = pathTruncated
        self.signingID = signingID
        self.teamID = teamID
        self.cdhash = cdhash
        self.isPlatformBinary = isPlatformBinary
        self.signingCategory = signingCategory
        self.codeSigningFlags = codeSigningFlags
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

    /// Path of the outermost user-facing `.app` bundle containing the executable, if any.
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
        if r.parentToken == nil { r.parentToken = other.parentToken }
        if r.signingCategory == nil { r.signingCategory = other.signingCategory }
        if r.codeSigningFlags == nil { r.codeSigningFlags = other.codeSigningFlags }
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

/// One execution of a process: the pid and pidversion of an audit token. exec gives the process a new
/// pidversion, so (pid, pidversion) tells apart the images of one pid as well as reused pids.
public struct ProcessToken: Codable, Hashable, Sendable {
    public var pid: Int32
    public var pidVersion: UInt32

    public init(pid: Int32, pidVersion: UInt32) {
        self.pid = pid
        self.pidVersion = pidVersion
    }
}

/// es_cs_validation_category_t (ESTypes.h): the code signing policy under which the kernel validated an
/// executable. Kept as the raw value, so a category this build does not know is never mistaken for a
/// trusted one.
public struct SigningCategory: RawRepresentable, Codable, Hashable, Sendable {
    public var rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let invalid = SigningCategory(rawValue: 0)
    public static let platform = SigningCategory(rawValue: 1)
    public static let testFlight = SigningCategory(rawValue: 2)
    public static let development = SigningCategory(rawValue: 3)
    public static let appStore = SigningCategory(rawValue: 4)
    public static let enterprise = SigningCategory(rawValue: 5)
    public static let developerID = SigningCategory(rawValue: 6)
    public static let localSigning = SigningCategory(rawValue: 7)
    public static let rosetta = SigningCategory(rawValue: 8)
    public static let oopJIT = SigningCategory(rawValue: 9)
    /// ES_CS_VALIDATION_CATEGORY_NONE (named apart from Optional's `.none`).
    public static let noPolicy = SigningCategory(rawValue: 10)
}

/// Code signing flags from `es_process_t.codesigning_flags`. Values from <kern/cs_blobs.h> (in the
/// SDK's Kernel.framework headers, which user space cannot include).
public enum CodeSigningFlag {
    /// CS_GET_TASK_ALLOW: the code has the get-task-allow entitlement (Xcode debug builds), so the
    /// user's other processes may get its task port: debug it, read and write its memory.
    public static let getTaskAllow: UInt32 = 0x0000_0004
    /// CS_DEBUGGED: the process is, or has been, debugged and allowed to run with invalid pages.
    public static let debugged: UInt32 = 0x1000_0000
}

extension ProcessRecord {
    /// Other processes of the user may control this one (get-task-allow, or it has been debugged), so
    /// its code identity says nothing about what it does. False when the source gives no flags.
    public var isControllable: Bool {
        codeSigningFlags.map { $0 & (CodeSigningFlag.getTaskAllow | CodeSigningFlag.debugged) != 0 } ?? false
    }

    /// The platform flag, where the kernel's signing category confirms it: Apple trust (Apple programs,
    /// platform owners, benign services, never-block) needs category PLATFORM, and code nobody else
    /// controls. Without a category (older macOS, libproc) the flag alone counts, as before.
    public var isVerifiedPlatformBinary: Bool {
        isPlatformBinary && (signingCategory.map { $0 == .platform } ?? true) && !isControllable
    }

    /// A third-party code identity (team ID, signing ID) can stand for its vendor: signed for
    /// distribution (Developer ID, App Store) where the kernel's category is known, and not controllable.
    /// Development, local or ad-hoc signing and every other category are not: a debug build of an app
    /// carries the vendor's team ID too.
    public var hasDistributionSignature: Bool {
        (signingCategory.map { $0 == .developerID || $0 == .appStore } ?? true) && !isControllable
    }
}

public enum BundlePath {
    /// "/Applications/Xcode.app/Contents/Applications/Simulator.app/Contents/MacOS/Simulator"
    /// -> "/Applications/Xcode.app"
    public static func outermostApp(in path: String) -> String? {
        attributableAppBundles(in: path).first
    }

    /// `.app` bundles that stand for an application. Helper apps embedded in a framework with no
    /// enclosing app (e.g. `Python3.framework/…/Resources/Python.app`, the interpreter behind
    /// `/usr/bin/python3`) are runtime plumbing, not the app responsible for an access.
    public static func attributableAppBundles(in path: String) -> [String] {
        var out: [String] = []
        var current = ""
        var sawFramework = false
        let components = path.split(separator: "/")
        for (i, component) in components.enumerated() {
            current += current.isEmpty && !path.hasPrefix("/") ? String(component) : "/" + component
            let lower = component.lowercased()
            if lower.hasSuffix(".framework") && out.isEmpty { sawFramework = true }
            if component.count > 4 && lower.hasSuffix(".app") {
                if out.isEmpty && sawFramework { continue }
                // Xcode's toolchain (`Xcode.app/Contents/Developer/usr/bin/git`, python3…) plays the
                // role of /Library/Developer/CommandLineTools: the shims in /usr/bin exec into it.
                if out.isEmpty, i + 2 < components.count, components[i + 1].lowercased() == "contents",
                   components[i + 2].lowercased() == "developer" {
                    // Apps inside the developer dir (Simulator.app) are still found further down.
                    continue
                }
                out.append(current)
            }
        }
        return out
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
