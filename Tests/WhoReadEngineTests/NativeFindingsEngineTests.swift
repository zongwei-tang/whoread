import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Regression tests for the native source findings, Engine side: the native mute plan for
// homes outside the firmlinks (files-4), the fail-closed deadline miss mode (macOS 27), the new event
// kinds (files-10), and the ES message conversion (files-5, files-8, files-10) on hand-built messages.

private func nfCatalog() throws -> Catalog {
    try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog
}

// MARK: - files-4: mute plan for data-volume homes

final class NativeMutePlanHomeFindingTests: XCTestCase {
    /// The daemon's classifier for `homes` (raw, as HomeDirectories reports them) and the plan built from it,
    /// with `links` standing in for the file system's symlinks.
    private func plan(homes: [String], links: [String: String]) throws
        -> (classifier: PathClassifier, prefixes: Set<String>, literals: Set<String>) {
        let classifier = PathClassifier(catalog: try nfCatalog(), normalizer: PathNormalizer(homeDirectories: homes),
                                        symlinks: MapSymlinkResolver(links))
        let resolver = MapSymlinkResolver(links)
        let p = NativeMutePlan.plan(prefixes: classifier.mutePaths, ancestors: classifier.ancestors,
                                    homes: classifier.normalizer.homeDirectories, normalize: classifier.normalizer.normalize,
                                    resolve: resolver.resolve)
        return (classifier, Set(p.prefixes.map(\.path)), Set(p.literals.map(\.path)))
    }

    func testAutoHomeIsSelectedByItsVFSSpelling() throws {
        // pw_dir /home/bob; /home is a symlink to /System/Volumes/Data/home, where autofs mounts auto_home. ES
        // reports /System/Volumes/Data/home/bob/…; before, only /home/bob/… was selected.
        let r = try plan(homes: ["/home/bob", "/System/Volumes/Data/home/bob"], links: ["/home": "/System/Volumes/Data/home"])
        XCTAssertEqual(r.classifier.normalizer.homeDirectories, ["/home/bob"])
        XCTAssertTrue(r.prefixes.contains("/home/bob/.ssh"))
        XCTAssertTrue(r.prefixes.contains("/System/Volumes/Data/home/bob/.ssh"), "the realpath spelling ES reports")
        XCTAssertTrue(r.prefixes.contains("/System/Volumes/Data/home/bob/.aws"))
        XCTAssertTrue(r.literals.contains("/System/Volumes/Data/home/bob"), "moving the whole home is selected too")
        // What ES reports classifies like the catalog spelling.
        let c = r.classifier.classify("/System/Volumes/Data/home/bob/.ssh/id_ed25519")
        XCTAssertEqual(c?.categoryID, "ssh")
        XCTAssertEqual(c?.severity, .critical)
        // Never the home itself, its folder or the data volume.
        for tooMuch in ["/home/bob", "/System/Volumes/Data/home/bob", "/System/Volumes/Data/home", "/System/Volumes/Data", "/"] {
            XCTAssertFalse(r.prefixes.contains(tooMuch), tooMuch)
        }
    }

    func testDataVolumeHomeWithoutARootSpellingIsSelected() throws {
        // A home created under /System/Volumes/Data (no /Homes at the root): the normalizer folds it to
        // /Homes/bob, whose realpath fails. ES reports the data-volume spelling.
        let r = try plan(homes: ["/System/Volumes/Data/Homes/bob"], links: [:])
        XCTAssertEqual(r.classifier.normalizer.homeDirectories, ["/Homes/bob"])
        XCTAssertTrue(r.prefixes.contains("/System/Volumes/Data/Homes/bob/.ssh"))
        XCTAssertEqual(r.classifier.classify("/System/Volumes/Data/Homes/bob/.ssh/id_ed25519")?.categoryID, "ssh")
    }

    func testResolvedSpellingIsJudgedNormalizedButRegisteredAsResolved() {
        // The accept filter compares with normalized homes: the raw realpath is never "inside a home".
        let homes = PathNormalizer(homeDirectories: ["/home/bob", "/System/Volumes/Data/home/bob"]).homeDirectories
        let p = NativeMutePlan.plan(prefixes: ["/home/bob/.ssh"], ancestors: [], homes: homes,
                                    normalize: PathNormalizer().normalize, resolve: { "/System/Volumes/Data" + $0 })
        XCTAssertEqual(Set(p.prefixes.map(\.path)), ["/home/bob/.ssh", "/System/Volumes/Data/home/bob/.ssh"])
        // A home that is a link to another data-volume folder: its realpath is not the firmlink spelling, and
        // only its normalized form (/OtherHomes/bob/…) is inside a home.
        let linked = PathNormalizer(homeDirectories: ["/Users/bob", "/System/Volumes/Data/OtherHomes/bob"]).homeDirectories
        XCTAssertEqual(linked, ["/Users/bob", "/OtherHomes/bob"])
        let q = NativeMutePlan.plan(prefixes: ["/Users/bob/.ssh"], ancestors: [], homes: linked, normalize: PathNormalizer().normalize,
                                    resolve: { $0 == "/Users/bob/.ssh" ? "/System/Volumes/Data/OtherHomes/bob/.ssh" : nil })
        XCTAssertTrue(q.prefixes.contains(NativeMutePlan.Path("/System/Volumes/Data/OtherHomes/bob/.ssh")))
        // A link out of the home into system files stays refused after normalization.
        let out = NativeMutePlan.plan(prefixes: ["/home/bob/.aws/credentials"], ancestors: [], homes: homes,
                                      normalize: PathNormalizer().normalize, resolve: { _ in "/System/Volumes/Data/usr/lib/x" })
        XCTAssertFalse(out.prefixes.contains(NativeMutePlan.Path("/System/Volumes/Data/usr/lib/x")))
    }

    func testFirmlinkSpellings() {
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("/Users/alice/.ssh"), ["/System/Volumes/Data/Users/alice/.ssh"])
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("/System/Volumes/Data/home/bob"), [])
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("/system/volumes/DATA/x"), [], "already there, any case")
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("/System/Volumes/Data"), [])
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("/"), [])
        XCTAssertEqual(NativeMutePlan.firmlinkSpellings("relative"), [])
        // NFC and NFD each get theirs (byte-distinct to ES).
        let v = NativeMutePlan.variants("/Users/alice/Caf\u{E9}", resolve: { _ in nil })
        XCTAssertEqual(Set(v.map { Array($0.utf8) }).count, 4)
        XCTAssertTrue(NativeMutePlan.variants("/Users/alice/\u{0}x", resolve: { _ in nil }).isEmpty)
    }
}

// MARK: - Deadline miss mode (macOS 27)

final class NativeDeadlineMissModeTests: XCTestCase {
    func testRawValuesFollowTheHeadersOrder() {
        // ESTypes.h: KILL, FAIL_CLOSED, FAIL_OPEN (no explicit values).
        XCTAssertEqual(NativeDeadlineMissMode.kill.rawValue, 0)
        XCTAssertEqual(NativeDeadlineMissMode.failClosed.rawValue, 1)
        XCTAssertEqual(NativeDeadlineMissMode.failOpen.rawValue, 2)
        XCTAssertEqual(NativeDeadlineMissMode.wanted, .failClosed)
    }

    func testOlderSystemsKeepKillWithoutAnError() {
        let o = NativeDeadlineMissMode.configure(set: nil, get: nil)
        XCTAssertEqual(o, .init(mode: .kill, problem: nil))
        XCTAssertEqual(o.name, "kill")
    }

    func testFailClosedIsSetAndVerified() {
        var asked: [UInt32] = []
        var current: UInt32 = 0
        let o = NativeDeadlineMissMode.configure(set: { asked.append($0); current = $0; return true }, get: { current })
        XCTAssertEqual(asked, [1], "the raw FAIL_CLOSED value")
        XCTAssertEqual(o, .init(mode: .failClosed, problem: nil))
        XCTAssertEqual(o.name, "fail-closed")
    }

    func testFailuresAreReportedWithTheModeReadBack() {
        let refused = NativeDeadlineMissMode.configure(set: { _ in false }, get: { 0 })
        XCTAssertEqual(refused.mode, .kill)
        XCTAssertNotNil(refused.problem)
        let ignored = NativeDeadlineMissMode.configure(set: { _ in true }, get: { 2 })
        XCTAssertEqual(ignored.mode, .failOpen)
        XCTAssertNotNil(ignored.problem, "set succeeded but another mode is in force")
        let unreadable = NativeDeadlineMissMode.configure(set: { _ in true }, get: { nil })
        XCTAssertNil(unreadable.mode)
        XCTAssertEqual(unreadable.name, "unknown")
        XCTAssertNotNil(unreadable.problem)
        let strange = NativeDeadlineMissMode.configure(set: { _ in true }, get: { 7 })
        XCTAssertNil(strange.mode)
        XCTAssertNotNil(strange.problem)
        let noGetter = NativeDeadlineMissMode.configure(set: { _ in true }, get: nil)
        XCTAssertNil(noGetter.mode, "set but not verifiable")
        XCTAssertNotNil(noGetter.problem)
        let refusedUnverified = NativeDeadlineMissMode.configure(set: { _ in false }, get: nil)
        XCTAssertEqual(refusedUnverified.mode, .kill, "a failed set leaves the default")
        XCTAssertNotNil(refusedUnverified.problem)
    }

    func testFunctionsAreFoundOnlyWhereTheSystemHasThem() {
        // Looked up at run time; libEndpointSecurity is linked into this bundle.
        let has27 = ProcessInfo.processInfo.isOperatingSystemAtLeast(OperatingSystemVersion(majorVersion: 27, minorVersion: 0, patchVersion: 0))
        XCTAssertEqual(NativeDeadlineMissMode.symbol(NativeDeadlineMissMode.setterName) != nil, has27)
        XCTAssertEqual(NativeDeadlineMissMode.symbol(NativeDeadlineMissMode.getterName) != nil, has27)
        XCTAssertNil(NativeDeadlineMissMode.symbol("es_no_such_function"))
    }

    func testStatusText() {
        XCTAssertTrue(NativeDeadlineMissMode.statusDescription("fail-closed").hasPrefix("fail-closed (an access not answered in time is denied"))
        XCTAssertTrue(NativeDeadlineMissMode.statusDescription("kill").contains("allows that access"))
        XCTAssertTrue(NativeDeadlineMissMode.statusDescription("fail-open").contains("WARNING"))
        XCTAssertEqual(NativeDeadlineMissMode.statusDescription("unknown"), "unknown (could not be read back)")
        XCTAssertTrue(NativeDeadlineMissMode.missesDenied("fail-closed"))
        for m in ["kill", "fail-open", "unknown", nil] as [String?] { XCTAssertFalse(NativeDeadlineMissMode.missesDenied(m)) }
        for m in NativeDeadlineMissMode.allCases { XCTAssertEqual(NativeDeadlineMissMode(name: m.name), m) }
    }

    func testStatusCarriesTheModeAndStaysBackwardCompatible() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNil(core.status().sourceDeadlineMissMode)
        core.pipeline.sourceStateChanged(SourceState(running: true, deadlineMissMode: "fail-closed"))
        let status = core.status()
        XCTAssertEqual(status.sourceDeadlineMissMode, "fail-closed")
        // Round trip, and an older daemon's status (no field) still decodes.
        let data = try JSONEncoder().encode(status)
        XCTAssertEqual(try JSONDecoder().decode(DaemonStatus.self, from: data).sourceDeadlineMissMode, "fail-closed")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object.removeValue(forKey: "sourceDeadlineMissMode")
        let old = try JSONDecoder().decode(DaemonStatus.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(old.sourceDeadlineMissMode)
        XCTAssertEqual(try JSONDecoder().decode(SourceState.self, from: Data(#"{"running":true,"finished":false}"#.utf8)),
                       SourceState(running: true))
    }
}

// MARK: - es_delete_client exclusivity

final class NativeClientGateTests: XCTestCase {
    func testUseRunsUntilClosed() {
        let gate = NativeClientGate()
        var ran = 0
        XCTAssertTrue(gate.use { ran += 1 })
        XCTAssertTrue(gate.close(waitAtMost: 0.1))
        XCTAssertFalse(gate.use { ran += 1 }, "nothing new once the client is being deleted")
        XCTAssertEqual(ran, 1)
    }

    func testCloseWaitsForACallStillInside() {
        // A respond still running on the handler's thread: deleting the client now would race it.
        let gate = NativeClientGate()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            gate.use {
                entered.signal()
                release.wait()
            }
            finished.signal()
        }
        entered.wait()
        XCTAssertFalse(gate.close(waitAtMost: 0.05), "still inside: not exclusive")
        XCTAssertFalse(gate.use { XCTFail("ran after close") })
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { release.signal() }
        XCTAssertTrue(gate.close(waitAtMost: 5), "exclusive once the call returned")
        XCTAssertEqual(finished.wait(timeout: .now() + 5), .success)
    }
}

// MARK: - files-10: eslogger subscription

final class NewEventKindsSubscriptionTests: XCTestCase {
    func testEsloggerSubscribesPermissionOwnerAndMountEvents() {
        let names = EsloggerSource.eventNames(readdir: false)
        for n in ["setmode", "setowner", "setacl", "setattrlist", "mount"] { XCTAssertTrue(names.contains(n), n) }
        XCTAssertFalse(names.contains("readdir"))
    }
}

#if canImport(EndpointSecurity)
import EndpointSecurity

/// An es_message_t built by hand in zeroed memory, laid out by the real SDK headers, so the source's
/// conversion (`NativeESSource.activity`) is tested without an ES client. Pointers it hands out live as
/// long as it does.
private final class FakeESMessage {
    private var blocks: [UnsafeMutableRawPointer] = []
    private(set) var message: UnsafeMutablePointer<es_message_t>!
    private let eventOffset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event)!

    init(_ type: es_event_type_t, auth: Bool = false, version: UInt32 = 7) {
        message = zeroed(es_message_t.self, extra: 256)
        let process = zeroed(es_process_t.self)
        put(file("/bin/chmod", mode: 0o100755), into: UnsafeMutableRawPointer(process),
            at: MemoryLayout<es_process_t>.offset(of: \es_process_t.executable)!)
        let m = UnsafeMutableRawPointer(message!)
        put(version, into: m, at: MemoryLayout<es_message_t>.offset(of: \es_message_t.version)!)
        put(process, into: m, at: MemoryLayout<es_message_t>.offset(of: \es_message_t.process)!)
        put(auth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY, into: m, at: MemoryLayout<es_message_t>.offset(of: \es_message_t.action_type)!)
        put(type, into: m, at: MemoryLayout<es_message_t>.offset(of: \es_message_t.event_type)!)
    }

    deinit { blocks.forEach { $0.deallocate() } }

    private func zeroed<T>(_: T.Type, extra: Int = 0) -> UnsafeMutablePointer<T> {
        let size = MemoryLayout<T>.stride + extra
        let raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: max(MemoryLayout<T>.alignment, 16))
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        blocks.append(raw)
        return raw.bindMemory(to: T.self, capacity: 1)
    }

    private func put<T>(_ value: T, into base: UnsafeMutableRawPointer, at offset: Int) {
        (base + offset).storeBytes(of: value, as: T.self)
    }

    /// Writes `value` at `offset` inside the event union.
    func event<T>(_ value: T, at offset: Int) {
        put(value, into: UnsafeMutableRawPointer(message!), at: eventOffset + offset)
    }

    func file(_ path: String, mode: UInt32) -> UnsafeMutablePointer<es_file_t> {
        let bytes = Array(path.utf8)
        let chars = zeroed(CChar.self, extra: bytes.count + 1)
        bytes.withUnsafeBytes { UnsafeMutableRawPointer(chars).copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        var st = stat()
        st.st_mode = mode_t(mode)
        let f = zeroed(es_file_t.self)
        f.initialize(to: es_file_t(path: es_string_token_t(length: bytes.count, data: UnsafePointer(chars)), path_truncated: false, stat: st))
        return f
    }

    func mountStat(_ path: String) -> UnsafeMutablePointer<Darwin.statfs> {
        let s = zeroed(Darwin.statfs.self)
        let bytes = Array(path.utf8)
        let offset = MemoryLayout<Darwin.statfs>.offset(of: \Darwin.statfs.f_mntonname)!
        bytes.withUnsafeBytes { UnsafeMutableRawPointer(s).advanced(by: offset).copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        return s
    }

    var activity: FileActivity? { NativeESSource.activity(UnsafePointer(message)) }
}

final class NativeConversionFindingTests: XCTestCase {
    private let key = "/Users/alice/.ssh/id_ed25519"
    private let regular: UInt32 = 0o100600
    private let directory: UInt32 = 0o040755

    func testTruncatingReadOnlyOpenIsAWrite() throws {
        for type in [ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_OPEN] {
            let m = FakeESMessage(type, auth: type == ES_EVENT_TYPE_AUTH_OPEN)
            m.event(Int32(0x401), at: MemoryLayout<es_event_open_t>.offset(of: \es_event_open_t.fflag)!)
            m.event(m.file(key, mode: regular), at: MemoryLayout<es_event_open_t>.offset(of: \es_event_open_t.file)!)
            let a = try XCTUnwrap(m.activity)
            XCTAssertEqual(a.operation, .open)
            XCTAssertEqual(a.targets.map(\.access), [[.read, .write]])
            XCTAssertEqual(a.process.executablePath, "/bin/chmod")
        }
    }

    func testRenameOntoAnExistingDirectoryKeepsItsType() throws {
        let m = FakeESMessage(ES_EVENT_TYPE_AUTH_RENAME, auth: true)
        m.event(m.file("/private/tmp/empty", mode: directory), at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.source)!)
        m.event(ES_DESTINATION_TYPE_EXISTING_FILE, at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.destination_type)!)
        m.event(m.file("/Users/alice/.config", mode: directory), at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.destination)!)
        let a = try XCTUnwrap(m.activity)
        XCTAssertEqual(a.targets.map(\.path), ["/private/tmp/empty", "/Users/alice/.config"])
        XCTAssertEqual(a.targets[1].isDirectory, true)
        XCTAssertEqual(a.targets[1].access, .readWrite)
        XCTAssertTrue(a.targets[1].carriesContent(in: a.operation))
    }

    func testPermissionOwnerAndACLChangesAreConverted() throws {
        let cases: [(es_event_type_t, FileOperation, Int)] = [
            (ES_EVENT_TYPE_NOTIFY_SETMODE, .setmode, MemoryLayout<es_event_setmode_t>.offset(of: \es_event_setmode_t.target)!),
            (ES_EVENT_TYPE_AUTH_SETMODE, .setmode, MemoryLayout<es_event_setmode_t>.offset(of: \es_event_setmode_t.target)!),
            (ES_EVENT_TYPE_NOTIFY_SETOWNER, .setowner, MemoryLayout<es_event_setowner_t>.offset(of: \es_event_setowner_t.target)!),
            (ES_EVENT_TYPE_AUTH_SETOWNER, .setowner, MemoryLayout<es_event_setowner_t>.offset(of: \es_event_setowner_t.target)!),
            (ES_EVENT_TYPE_NOTIFY_SETACL, .setacl, MemoryLayout<es_event_setacl_t>.offset(of: \es_event_setacl_t.target)!),
            (ES_EVENT_TYPE_AUTH_SETACL, .setacl, MemoryLayout<es_event_setacl_t>.offset(of: \es_event_setacl_t.target)!),
        ]
        for (type, op, offset) in cases {
            let m = FakeESMessage(type, auth: [ES_EVENT_TYPE_AUTH_SETMODE, ES_EVENT_TYPE_AUTH_SETOWNER, ES_EVENT_TYPE_AUTH_SETACL].contains(type))
            m.event(m.file(key, mode: regular), at: offset)
            let a = try XCTUnwrap(m.activity, "\(type)")
            XCTAssertEqual(a.operation, op)
            XCTAssertEqual(a.targets.map(\.path), [key])
            XCTAssertEqual(a.targets.map(\.access), [.write])
            XCTAssertEqual(a.targets.first?.isDirectory, false)
        }
    }

    func testSetattrlistCountsOnlyPermissionAttributes() throws {
        func convert(_ common: UInt32) -> FileActivity? {
            let m = FakeESMessage(ES_EVENT_TYPE_AUTH_SETATTRLIST, auth: true)
            let list = attrlist(bitmapcount: 5, reserved: 0, commonattr: common, volattr: 0, dirattr: 0, fileattr: 0, forkattr: 0)
            m.event(list, at: MemoryLayout<es_event_setattrlist_t>.offset(of: \es_event_setattrlist_t.attrlist)!)
            m.event(m.file(key, mode: regular), at: MemoryLayout<es_event_setattrlist_t>.offset(of: \es_event_setattrlist_t.target)!)
            return m.activity
        }
        XCTAssertEqual(convert(0x20000)?.operation, .setmode)
        XCTAssertEqual(convert(0x8000)?.operation, .setowner)
        XCTAssertEqual(convert(0x400000)?.operation, .setacl)
        XCTAssertEqual(convert(0x20000)?.targets.map(\.access), [.write])
        XCTAssertNil(convert(0x400), "times only: allowed and not recorded")
    }

    func testMountIsConvertedToItsMountPoint() throws {
        for type in [ES_EVENT_TYPE_AUTH_MOUNT, ES_EVENT_TYPE_NOTIFY_MOUNT] {
            let m = FakeESMessage(type, auth: type == ES_EVENT_TYPE_AUTH_MOUNT)
            m.event(m.mountStat("/Users/alice/.ssh"), at: MemoryLayout<es_event_mount_t>.offset(of: \es_event_mount_t.statfs)!)
            let a = try XCTUnwrap(m.activity)
            XCTAssertEqual(a.operation, .mount)
            XCTAssertEqual(a.targets.map(\.path), ["/Users/alice/.ssh"])
            XCTAssertEqual(a.targets.map(\.access), [.write])
        }
        // A full-length f_mntonname without a NUL is cut at the buffer's end, not read past it.
        let m = FakeESMessage(ES_EVENT_TYPE_NOTIFY_MOUNT)
        let long = String(repeating: "a", count: Int(MAXPATHLEN) - 1)
        m.event(m.mountStat("/" + long), at: MemoryLayout<es_event_mount_t>.offset(of: \es_event_mount_t.statfs)!)
        XCTAssertEqual(try XCTUnwrap(m.activity).targets.first?.path.utf8.count, Int(MAXPATHLEN))
    }

    func testFileClientSubscribesTheNewEvents() {
        let notify = Set(NativeESSource.notifyFileEvents.map(\.rawValue))
        let auth = Set(NativeESSource.authFileEvents.map(\.rawValue))
        for t in [ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETACL,
                  ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_NOTIFY_MOUNT] {
            XCTAssertTrue(notify.contains(t.rawValue), "\(t)")
        }
        for t in [ES_EVENT_TYPE_AUTH_SETMODE, ES_EVENT_TYPE_AUTH_SETOWNER, ES_EVENT_TYPE_AUTH_SETACL,
                  ES_EVENT_TYPE_AUTH_SETATTRLIST, ES_EVENT_TYPE_AUTH_MOUNT] {
            XCTAssertTrue(auth.contains(t.rawValue), "\(t)")
        }
        XCTAssertFalse(auth.contains(ES_EVENT_TYPE_AUTH_READDIR.rawValue), "listings are never blocked")
    }
}
#endif
