import Foundation
import XCTest
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import WhoReadCore
@testable import WhoReadEngine

// Regression tests for the default catalog, agent and benign lists a root daemon starts from (a
// macos-4 variant).

final class DefaultsTrustDaemonTests: XCTestCase {
    private func copyOfDefaults(_ dir: TempDir, _ name: String = "defaults") throws -> String {
        let d = dir.path(name)
        XCTAssertEqual(mkdir(d, 0o755), 0)
        XCTAssertEqual(chmod(d, 0o755), 0)
        for file in [DefaultData.catalogFile, DefaultData.agentsFile, DefaultData.benignFile] {
            let data = try Data(contentsOf: repoRoot.appendingPathComponent("Data").appendingPathComponent(file))
            try SafeFile.replace(d + "/" + file, with: data, mode: 0o644)
        }
        return d
    }

    private func config(_ dir: TempDir, defaults: String) -> DaemonConfiguration {
        var c = baseConfig(dir)
        c.resolveOwners = false
        c.defaultsDirectory = defaults
        c.defaultsOwner = geteuid()
        return c
    }

    func testOnlyARootDaemonChecksItsDefaultsByDefault() {
        XCTAssertEqual(DaemonConfiguration().defaultsOwner, geteuid() == 0 ? 0 : nil)
    }

    // macos-4 variant: `--defaults DIR` was read as it was, so whoever could write DIR decided what a root
    // daemon treats as sensitive, as an AI agent and as a benign service.
    func testDefaultsOthersCanChangeAreRefused() throws {
        let dir = TempDir()
        let defaults = try copyOfDefaults(dir)
        XCTAssertEqual(chmod(defaults, 0o777), 0)
        XCTAssertThrowsError(try DaemonCore(config: config(dir, defaults: defaults), makeSource: { _ in FakeSource(canEnforce: true) })) { error in
            XCTAssertTrue("\(error)".contains("refusing the default data in \(defaults)"), "\(error)")
            XCTAssertTrue("\(error)".contains("writable by group or others"), "\(error)")
        }
        XCTAssertEqual(chmod(defaults, 0o755), 0)
        XCTAssertEqual(chmod(defaults + "/" + DefaultData.benignFile, 0o664), 0)
        XCTAssertThrowsError(try DaemonCore(config: config(dir, defaults: defaults), makeSource: { _ in FakeSource(canEnforce: true) })) { error in
            XCTAssertTrue("\(error)".contains(DefaultData.benignFile), "\(error)")
        }
    }

    func testTrustedDefaultsStart() throws {
        let dir = TempDir()
        let defaults = try copyOfDefaults(dir)
        let core = try DaemonCore(config: config(dir, defaults: defaults), makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertEqual(core.data.catalog, try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog)
    }
}
