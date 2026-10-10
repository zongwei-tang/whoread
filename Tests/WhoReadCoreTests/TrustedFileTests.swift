import Foundation
import XCTest
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
@testable import WhoReadCore

/// Files the CLI, the app and a root daemon read from places only root should be able to change:
/// the daemon's Mach service name (daemonfs-3) and the default catalog, agent and benign lists
/// (daemonfs-4). The tests run as a user, who stands in for root as the trusted owner.
final class TrustedFileTests: XCTestCase {
    private var dir = ""
    private let me = geteuid()
    /// A uid that is not the test process's.
    private var someoneElse: uid_t { me == 0 ? 1 : 0 }

    override func setUpWithError() throws {
        let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        dir = (base as NSString).appendingPathComponent("whoread-trusted-\(UUID().uuidString.prefix(8))")
        XCTAssertEqual(mkdir(dir, 0o755), 0)
        XCTAssertEqual(chmod(dir, 0o755), 0)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    private func path(_ name: String) -> String { (dir as NSString).appendingPathComponent(name) }

    /// A data directory holding `mach-service` with `name`, as the daemon writes it.
    private func dataDirectory(_ name: String = "com.example.daemon.xpc\n") throws -> String {
        let data = path("data")
        XCTAssertEqual(mkdir(data, 0o755), 0)
        XCTAssertEqual(chmod(data, 0o755), 0)
        try SafeFile.replace(data + "/mach-service", with: Data(name.utf8), mode: 0o644)
        return data
    }

    private func assertUntrusted(_ dataDir: String, owner: uid_t? = nil, mentioning text: String,
                                 file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try TrustedFile.machServiceName(inDataDirectory: dataDir, owner: owner ?? me),
                             file: file, line: line) { error in
            XCTAssertTrue(error is TrustedFile.Untrusted, "\(error)", file: file, line: line)
            XCTAssertTrue("\(error)".contains(text), "\(error)", file: file, line: line)
        }
    }

    private func chmodACL(_ arguments: [String]) throws {
        #if canImport(Darwin)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/chmod")
        p.arguments = arguments
        try p.run()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, "chmod \(arguments)")
        #else
        throw XCTSkip("no extended ACLs here")
        #endif
    }

    // MARK: - mach-service (daemonfs-3)

    func testTrustedServiceNameIsRead() throws {
        let data = try dataDirectory()
        XCTAssertEqual(try TrustedFile.machServiceName(inDataDirectory: data, owner: me), "com.example.daemon.xpc")
        XCTAssertEqual(try TrustedFile.machServiceName(inDataDirectory: data + "/", owner: me), "com.example.daemon.xpc")
    }

    func testNoAnnouncementIsNil() throws {
        XCTAssertNil(try TrustedFile.machServiceName(inDataDirectory: path("missing"), owner: me))
        XCTAssertEqual(mkdir(path("empty"), 0o755), 0)
        XCTAssertNil(try TrustedFile.machServiceName(inDataDirectory: path("empty"), owner: me))
    }

    // daemonfs-3: the CLI and the app took the name from any mach-service file, so whoever could
    // write the data directory could point them at another service.
    func testDataDirectoryOthersCanWriteIsNotTrusted() throws {
        let data = try dataDirectory()
        XCTAssertEqual(chmod(data, 0o777), 0)
        assertUntrusted(data, mentioning: "writable by group or others")
        XCTAssertEqual(chmod(data, 0o775), 0)
        assertUntrusted(data, mentioning: "writable by group or others")
    }

    func testDataDirectoryOfAnotherUserIsNotTrusted() throws {
        let data = try dataDirectory()
        assertUntrusted(data, owner: someoneElse, mentioning: "is owned by uid \(me)")
    }

    func testDataDirectoryThatIsALinkIsNotTrusted() throws {
        let real = try dataDirectory()
        XCTAssertEqual(symlink(real, path("link")), 0)
        assertUntrusted(path("link"), mentioning: "symbolic link or not a directory")
        assertUntrusted(path("link") + "/", mentioning: "symbolic link or not a directory")
    }

    func testDirectoryOnTheWayOthersCanWriteIsNotTrusted() throws {
        let shared = path("shared")
        XCTAssertEqual(mkdir(shared, 0o755), 0)
        XCTAssertEqual(mkdir(shared + "/data", 0o755), 0)
        try SafeFile.replace(shared + "/data/mach-service", with: Data("com.example.x\n".utf8), mode: 0o644)
        XCTAssertEqual(chmod(shared, 0o777), 0)
        assertUntrusted(shared + "/data", mentioning: shared)
        // Sticky (like /private/tmp): others may add entries there but not move ours.
        XCTAssertEqual(chmod(shared, 0o1777), 0)
        XCTAssertEqual(try TrustedFile.machServiceName(inDataDirectory: shared + "/data", owner: me), "com.example.x")
    }

    func testLinkOnTheWayIsFollowedForTheCheck() throws {
        let shared = path("shared")
        XCTAssertEqual(mkdir(shared, 0o755), 0)
        XCTAssertEqual(mkdir(shared + "/data", 0o755), 0)
        try SafeFile.replace(shared + "/data/mach-service", with: Data("com.example.x\n".utf8), mode: 0o644)
        XCTAssertEqual(chmod(shared, 0o777), 0)
        XCTAssertEqual(symlink(shared, path("via")), 0)
        assertUntrusted(path("via") + "/data", mentioning: shared)
    }

    func testServiceFileThatIsALinkIsNotFollowed() throws {
        let data = path("data")
        XCTAssertEqual(mkdir(data, 0o755), 0)
        try SafeFile.replace(path("elsewhere"), with: Data("com.attacker.xpc\n".utf8), mode: 0o644)
        XCTAssertEqual(symlink(path("elsewhere"), data + "/mach-service"), 0)
        assertUntrusted(data, mentioning: "symbolic link")
    }

    func testServiceFileOthersCanWriteIsNotTrusted() throws {
        let data = try dataDirectory()
        XCTAssertEqual(chmod(data + "/mach-service", 0o666), 0)
        assertUntrusted(data, mentioning: "writable by group or others")
    }

    func testServiceFileWithAnotherNameIsNotTrusted() throws {
        let data = try dataDirectory()
        XCTAssertEqual(link(data + "/mach-service", path("second-name")), 0)
        assertUntrusted(data, mentioning: "hard links")
    }

    func testFIFOIsRefusedWithoutWaitingForAWriter() throws {
        let data = path("data")
        XCTAssertEqual(mkdir(data, 0o755), 0)
        XCTAssertEqual(mkfifo(data + "/mach-service", 0o644), 0)
        let start = Date()
        assertUntrusted(data, mentioning: "not a regular file")
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }

    func testContentThatIsNoServiceNameIsRefused() throws {
        for content in ["", "\n", "com.example xpc\n", ".hidden\n", "com.example/../x\n", String(repeating: "a", count: 300)] {
            try? FileManager.default.removeItem(atPath: path("data"))
            let data = try dataDirectory(content)
            assertUntrusted(data, mentioning: "does not hold a Mach service name")
        }
    }

    func testDataDirectoryWithAnACLThatLetsOthersChangeItIsNotTrusted() throws {
        let data = try dataDirectory()
        try chmodACL(["+a", "everyone allow add_file,delete_child", data])
        assertUntrusted(data, mentioning: "access control list")
        try chmodACL(["-N", data])
        XCTAssertEqual(try TrustedFile.machServiceName(inDataDirectory: data, owner: me), "com.example.daemon.xpc")
        // A DENY entry only takes rights away.
        try chmodACL(["+a", "everyone deny delete", data])
        XCTAssertEqual(try TrustedFile.machServiceName(inDataDirectory: data, owner: me), "com.example.daemon.xpc")
    }

    func testServiceFileWithAnACLThatLetsOthersWriteItIsNotTrusted() throws {
        let data = try dataDirectory()
        try chmodACL(["+a", "everyone allow write", data + "/mach-service"])
        assertUntrusted(data, mentioning: "access control list")
    }
}

/// daemonfs-4: a root daemon took its catalog, agent and benign lists from any directory, even one
/// others could change: whoever could write it could drop sensitive categories or make every program
/// a benign service.
final class TrustedDefaultDataTests: XCTestCase {
    private var dir = ""
    private let me = geteuid()
    private var someoneElse: uid_t { me == 0 ? 1 : 0 }

    override func setUpWithError() throws {
        let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        dir = (base as NSString).appendingPathComponent("whoread-defaults-\(UUID().uuidString.prefix(8))")
        XCTAssertEqual(mkdir(dir, 0o755), 0)
        XCTAssertEqual(chmod(dir, 0o755), 0)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    private func path(_ name: String) -> String { (dir as NSString).appendingPathComponent(name) }

    /// A copy of Data/ at `name`, made the way the install script does (0755 directory, 0644 files).
    @discardableResult
    private func copyOfDefaults(_ name: String = "defaults") throws -> String {
        let d = path(name)
        let up = (d as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: up) { XCTAssertEqual(mkdir(up, 0o755), 0) }
        XCTAssertEqual(mkdir(d, 0o755), 0)
        XCTAssertEqual(chmod(d, 0o755), 0)
        for file in [DefaultData.catalogFile, DefaultData.agentsFile, DefaultData.benignFile] {
            let data = try Data(contentsOf: repoRoot.appendingPathComponent("Data").appendingPathComponent(file))
            try SafeFile.replace(d + "/" + file, with: data, mode: 0o644)
        }
        return d
    }

    private func assertRefused(_ explicit: String, owner: uid_t? = nil, mentioning text: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try DefaultData.locate(explicit: explicit, executablePath: nil, trustedOwner: owner ?? me),
                             file: file, line: line) { error in
            XCTAssertTrue("\(error)".contains(text), "\(error)", file: file, line: line)
        }
    }

    func testTrustedDefaultsLoad() throws {
        let d = try copyOfDefaults()
        let (data, from) = try DefaultData.locate(explicit: d, executablePath: nil, trustedOwner: me)
        XCTAssertEqual(from.path, d)
        XCTAssertEqual(data.catalog, try defaultData().catalog)
    }

    func testWithoutAnOwnerNothingIsChecked() throws {
        let d = try copyOfDefaults()
        XCTAssertEqual(chmod(d, 0o777), 0)
        XCTAssertNoThrow(try DefaultData.locate(explicit: d, executablePath: nil, trustedOwner: nil))
    }

    func testDefaultsDirectoryOthersCanWriteIsRefused() throws {
        let d = try copyOfDefaults()
        XCTAssertEqual(chmod(d, 0o777), 0)
        assertRefused(d, mentioning: "writable by group or others")
    }

    func testDefaultsDirectoryOfAnotherUserIsRefused() throws {
        let d = try copyOfDefaults()
        assertRefused(d, owner: someoneElse, mentioning: "is owned by uid \(me)")
    }

    func testDefaultsDirectoryThatIsALinkIsRefused() throws {
        let d = try copyOfDefaults()
        XCTAssertEqual(symlink(d, path("link")), 0)
        assertRefused(path("link"), mentioning: "symbolic link or not a directory")
    }

    func testDirectoryOnTheWayOthersCanWriteIsRefused() throws {
        XCTAssertEqual(mkdir(path("shared"), 0o755), 0)
        let d = try copyOfDefaults("shared/defaults")
        XCTAssertEqual(chmod(path("shared"), 0o777), 0)
        assertRefused(d, mentioning: path("shared"))
    }

    func testDefaultsFileOthersCanWriteIsRefused() throws {
        for file in [DefaultData.catalogFile, DefaultData.agentsFile, DefaultData.benignFile] {
            try? FileManager.default.removeItem(atPath: path("defaults"))
            let d = try copyOfDefaults()
            XCTAssertEqual(chmod(d + "/" + file, 0o666), 0)
            assertRefused(d, mentioning: file)
        }
    }

    func testDefaultsFileThatIsALinkIsRefused() throws {
        let d = try copyOfDefaults()
        let elsewhere = try copyOfDefaults("elsewhere")
        XCTAssertEqual(unlink(d + "/" + DefaultData.agentsFile), 0)
        XCTAssertEqual(symlink(elsewhere + "/" + DefaultData.agentsFile, d + "/" + DefaultData.agentsFile), 0)
        assertRefused(d, mentioning: "symbolic link")
    }

    // An explicit directory that fails the check stops the start: the other candidates are not what
    // was asked for.
    func testUntrustedExplicitDirectoryDoesNotFallBackToAnotherCandidate() throws {
        let d = try copyOfDefaults()
        XCTAssertEqual(chmod(d, 0o777), 0)
        let next = try copyOfDefaults("bin/WhoReadData")
        XCTAssertEqual(try DefaultData.locate(explicit: nil, executablePath: path("bin/whoreadd"), trustedOwner: me).1.path, next)
        XCTAssertThrowsError(try DefaultData.locate(explicit: d, executablePath: path("bin/whoreadd"), trustedOwner: me)) { error in
            XCTAssertTrue("\(error)".contains("writable by group or others"), "\(error)")
            XCTAssertTrue("\(error)".contains(d), "\(error)")
        }
    }

    // daemonfs-4-variant: the other candidates (in a bundle's Resources, next to the executable,
    // WHOREAD_DATA_DIR) are checked too; one that fails is skipped, never read.
    func testUntrustedSearchCandidateIsSkipped() throws {
        let first = try copyOfDefaults("Resources")
        XCTAssertEqual(chmod(first + "/" + DefaultData.catalogFile, 0o666), 0)
        let second = try copyOfDefaults("bin/WhoReadData")
        XCTAssertEqual(try DefaultData.locate(explicit: nil, executablePath: path("bin/whoreadd"), trustedOwner: me).1.path, second)
        // A daemon running as a user reads the first one as before.
        XCTAssertEqual(try DefaultData.locate(explicit: nil, executablePath: path("bin/whoreadd"), trustedOwner: nil).1.path, first)
        // Nothing trusted at all: the error names why each candidate was refused.
        XCTAssertEqual(chmod(second, 0o777), 0)
        XCTAssertThrowsError(try DefaultData.locate(explicit: nil, executablePath: path("bin/whoreadd"), trustedOwner: me)) { error in
            XCTAssertTrue("\(error)".contains(first), "\(error)")
            XCTAssertTrue("\(error)".contains(second), "\(error)")
        }
    }
}
