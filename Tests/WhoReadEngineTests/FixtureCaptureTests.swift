import Foundation
import XCTest
import WhoReadCore
@testable import WhoReadEngine

/// Fixture capture: what a sanitized eslogger capture may still carry (privacy-5 and variants).
final class FixtureSanitizerPrivacyTests: XCTestCase {
    /// An eslogger-shaped line with a process object; `body` is the event body JSON.
    func line(_ kind: String, _ body: String, pid: Int, ppid: Int = 1, exe: String = "/usr/sbin/fontd", team: String = "null") -> String {
        #"{"schema_version":1,"event":{"\#(kind)":\#(body)},"process":{"audit_token":{"pid":\#(pid)},"ppid":\#(ppid),"original_ppid":\#(ppid),"signing_id":"x","team_id":\#(team),"executable":{"path":"\#(exe)"}}}"#
    }

    func file(_ path: String) -> String { #"{"path":"\#(path)"}"# }
    func open(_ path: String) -> String { #"{"fflag":1,"file":\#(file(path))}"# }

    func sanitize(_ lines: [String]) -> String {
        FixtureSanitizer(home: "/Users/bob", samplePerKind: 50).sanitize(lines: lines).output.joined(separator: "\n")
    }

    /// privacy-5: /private/var/db holds device identifiers (lockdown records named by iPhone UDID,
    /// DHCP leases named by MAC address) and per-app files named by bundle id or app name.
    func testPrivateVarDbIsNotASystemSample() {
        let out = sanitize([
            line("open", open("/private/var/db/lockdown/00008110-001A2B3C4D5E6F70.plist"), pid: 10, exe: "/usr/libexec/usbmuxd"),
            line("open", open("/private/var/db/oah/2b8f0c5e/0a1b2c3d/zoom.us.aot"), pid: 11, exe: "/usr/libexec/oahd"),
            line("open", open("/var/db/BootCaches/6F1D2C3B-0000-4000-8000-0123456789AB/app.com.secretvpn.client.playlist"), pid: 12,
                 exe: "/usr/sbin/BootCacheControl"),
            line("unlink", #"{"target":\#(file("/private/var/db/dhcpclient/leases/en0-1,aa:bb:cc:dd:ee:ff")),"parent_dir":\#(file("/private/var/db/dhcpclient/leases"))}"#,
                 pid: 13, exe: "/usr/libexec/InternetSharing"),
            line("open", open("/System/Library/Fonts/Helvetica.ttc"), pid: 14),
        ])
        for s in ["00008110", "zoom.us", "secretvpn", "aa:bb:cc"] { XCTAssertFalse(out.contains(s), s) }
        XCTAssertTrue(out.contains("Helvetica.ttc"), "a genuine system sample survives")
    }

    /// privacy-5: what is still under /System/Volumes after firmlink normalization is another volume
    /// (Preboot paths start with the volume group UUID). Variant: the data-volume directories
    /// firmlinked into the system tree (/usr/share/firmlinks) hold caches, downloaded assets, device
    /// icons and third-party printer drivers.
    func testOtherVolumesAndFirmlinkedDataDirectoriesAreNotSystemSamples() {
        let out = sanitize([
            line("open", open("/System/Volumes/Preboot/6F1D2C3B-0000-4000-8000-0123456789AB/boot/System/Library/KernelCollections/x.kc"), pid: 20),
            line("open", open("/System/Volumes/Update/mnt1/SecretUpdate"), pid: 21),
            line("open", open("/System/Library/Caches/com.secretvpn.cache"), pid: 22),
            line("open", open("/System/Library/AssetsV2/com_apple_MobileAsset_SecretVoice/x.asset/Info.plist"), pid: 23),
            line("open", open("/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices.bundle/Contents/Resources/secret-model.plist"), pid: 24),
            line("open", open("/usr/libexec/cups/backend/secretprinter"), pid: 25),
            line("open", open("/usr/share/snmp/secret.conf"), pid: 26),
            line("open", open("/System/Library/CoreServices/CoreTypes.bundle/Contents/Info.plist"), pid: 27),
            line("open", open("/usr/share/icu/icudt76l.dat"), pid: 28),
        ])
        XCTAssertFalse(out.lowercased().contains("secret"), out)
        XCTAssertFalse(out.contains("6F1D2C3B"), out)
        XCTAssertTrue(out.contains("CoreTypes.bundle/Contents/Info.plist"), "the sealed part of CoreTypes.bundle is still system")
        XCTAssertTrue(out.contains("icudt76l.dat"))
    }

    /// Variant: /private/etc holds installer and VPN domain names (paths.d, resolver/), and the
    /// serial device nodes /dev/cu.* and /dev/tty.* are named after paired Bluetooth devices.
    func testEtcAndNamedDeviceNodesAreNotSystemSamples() {
        let out = sanitize([
            line("open", open("/private/etc/paths.d/SecretTool"), pid: 30, exe: "/usr/libexec/path_helper"),
            line("open", open("/etc/resolver/corp.secret-employer.example"), pid: 31, exe: "/usr/sbin/mDNSResponder"),
            line("open", open("/dev/cu.Bobs-Secret-AirPods"), pid: 32, exe: "/usr/sbin/bluetoothd"),
            line("open", open("/dev/tty.Bobs-Secret-iPhone"), pid: 33, exe: "/usr/sbin/bluetoothd"),
            line("open", open("/dev/null"), pid: 34),
            line("open", open("/dev/ttys003"), pid: 35),
        ])
        XCTAssertFalse(out.lowercased().contains("secret"), out)
        XCTAssertTrue(out.contains("/dev/null"), out)
        XCTAssertTrue(out.contains("/dev/ttys003"), out)
    }

    /// privacy-5: rename/link/clone/copyfile name the new file in a field other than `path`. Even
    /// with a system directory such events are not samples (the vault covers those shapes).
    func testEventsNamingAFileOutsideAPathAreNotSamples() {
        let dir = file("/System/Library/Fonts")
        let src = file("/System/Library/Fonts/Helvetica.ttc")
        let out = sanitize([
            line("rename", #"{"source":\#(src),"destination_type":1,"destination":{"new_path":{"dir":\#(dir),"filename":"en0-1,aa:bb:cc:dd:ee:ff"}}}"#, pid: 40),
            line("link", #"{"source":\#(src),"target_dir":\#(dir),"target_filename":"SecretLink"}"#, pid: 41),
            line("clone", #"{"source":\#(src),"target_dir":\#(dir),"target_name":"SecretClone"}"#, pid: 42),
            line("copyfile", #"{"source":\#(src),"target_file":null,"target_dir":\#(dir),"target_name":"SecretCopy","mode":420,"flags":0}"#, pid: 43),
            line("rename", #"{"source":\#(src),"destination_type":0,"destination":{"existing_file":\#(file("/System/Library/Fonts/Courier.ttc"))}}"#, pid: 44),
        ])
        XCTAssertFalse(out.contains("aa:bb:cc"), out)
        XCTAssertFalse(out.contains("Secret"), out)
        XCTAssertTrue(out.contains("Courier.ttc"), "a rename onto an existing file names it by path, which is checked")
    }

    /// Variant: an exec's `dyld_exec_path` is the path before symlink resolution, and argv[0] (kept
    /// in samples) is whatever the parent passed: a venv's python resolves to a system binary while
    /// both name the project.
    func testExecSamplesCheckDyldExecPathAndArgv0() {
        func exec(_ dyld: String, _ argv0: String, pid: Int) -> String {
            line("exec", #"{"target":{"audit_token":{"pid":\#(pid)},"executable":\#(file("/usr/bin/python3"))},"args":["\#(argv0)","-c","x"],"env":[],"cwd":\#(file("/usr/share")),"dyld_exec_path":"\#(dyld)"}"#,
                 pid: pid, exe: "/bin/zsh")
        }
        let out = sanitize([
            exec("/Users/bob/Projects/AcmeMerger/venv/bin/python", "python3", pid: 50),
            exec("/usr/bin/python3", "/Users/bob/Projects/AcmeMerger/venv/bin/python", pid: 51),
            exec("/usr/bin/python3", "venv-acmemerger/bin/python", pid: 52),
            exec("/usr/bin/python3", "python3", pid: 53),
            // Review: a spelling the sanitizer normalizes away is still committed as written.
            exec("/usr/bin/python3", "/usr/share/AcmeMerger/../../bin/python3", pid: 54),
            exec("/usr/bin/../share/AcmeMerger/../../bin/python3", "python3", pid: 55),
            // Review: launchd passes ProgramArguments[0] as argv[0] when a plist also sets Program, so a
            // third-party job running a system binary can name itself there without any '/'.
            exec("/usr/bin/python3", "com.acmemerger.updater", pid: 56),
            exec("/usr/bin/python3", "-python3", pid: 57),
        ])
        XCTAssertFalse(out.lowercased().contains("acmemerger"), out)
        XCTAssertTrue(out.contains(#""pid":53"#), "an all-system exec is still a sample")
        XCTAssertTrue(out.contains(#""pid":57"#), "a login-shell style argv[0] is the executable's name")
    }

    /// Variant: samples only come from event kinds whose name-bearing fields are known. A `lookup`
    /// names its target in `relative_target`.
    func testUnknownEventKindsAreNotSamples() {
        let out = sanitize([
            line("lookup", #"{"source_dir":\#(file("/usr/share")),"relative_target":"SecretProject/notes.txt"}"#, pid: 60),
            line("open", open("/usr/share/icu/icudt76l.dat"), pid: 61),
        ])
        XCTAssertFalse(out.contains("SecretProject"), out)
        XCTAssertTrue(out.contains("icudt76l.dat"))
    }

    /// Variant: given the capture script's pid, vault events from processes outside its tree are kept
    /// only for system programs. A third-party scanner opening the vault would otherwise commit its
    /// bundle path and team id, and its exec as lifecycle.
    func testVaultEventsFromForeignProcessesAreDropped() {
        let vault = "/Users/bob/WhoReadTestVault/ssh/id_ed25519"
        let scanner = "/Applications/SecretAV.app/Contents/MacOS/scanner"
        let lines = [
            line("fork", #"{"child":{"audit_token":{"pid":402},"ppid":300,"original_ppid":300,"executable":\#(file("/bin/bash"))}}"#, pid: 300, ppid: 200, exe: "/bin/bash"),
            line("open", open(vault), pid: 402, ppid: 300, exe: "/bin/cat"),
            line("open", open(vault), pid: 300, ppid: 200, exe: "/bin/bash"),
            line("exec", #"{"target":{"audit_token":{"pid":900},"executable":\#(file(scanner))},"args":["scanner"],"env":[],"cwd":\#(file("/"))}"#,
                 pid: 900, exe: "/usr/libexec/xpcproxy"),
            line("open", open(vault), pid: 900, exe: scanner, team: #""TEAMAV1234""#),
            line("open", open(vault), pid: 950, exe: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Support/mdworker_shared"),
        ]
        var s = FixtureSanitizer(home: "/Users/bob")
        s.capturePID = 300
        let (out, report) = s.sanitize(lines: lines)
        let joined = out.joined(separator: "\n")
        XCTAssertFalse(joined.contains("SecretAV"), joined)
        XCTAssertFalse(joined.contains("TEAMAV1234"), joined)
        XCTAssertTrue(joined.contains(#""pid":402"#), "the script's own children")
        XCTAssertTrue(joined.contains("mdworker_shared"), "Apple's own programs stay")
        XCTAssertEqual(report.vaultEvents, 3)
        XCTAssertEqual(report.foreignVaultEvents, 1)
        XCTAssertEqual(out.count, 4, "the fork, three vault events")
    }

    /// The capture script's `( cat … & )`: the subshell exits first, so cat reports ppid 1 and its
    /// subshell as original_ppid. With the script's pid it is still the script's own process.
    func testReparentedChildOfTheCaptureScriptKeepsItsVaultEvents() {
        let vault = "/Users/bob/WhoReadTestVault/aws/credentials"
        func child(_ pid: Int, _ ppid: Int) -> String {
            #"{"audit_token":{"pid":\#(pid)},"ppid":\#(ppid),"original_ppid":\#(ppid),"executable":{"path":"/bin/bash"}}"#
        }
        let forkSubshell = line("fork", #"{"child":\#(child(401, 300))}"#, pid: 300, ppid: 200, exe: "/bin/bash")
        let forkCat = line("fork", #"{"child":\#(child(402, 401))}"#, pid: 401, ppid: 300, exe: "/bin/bash")
        let subshellExit = line("exit", #"{"stat":0}"#, pid: 401, ppid: 300, exe: "/bin/bash")
        let read = #"{"schema_version":1,"event":{"open":{"fflag":1,"file":{"path":"\#(vault)"}}},"process":{"audit_token":{"pid":402},"ppid":1,"original_ppid":401,"executable":{"path":"/bin/cat"}}}"#
        var s = FixtureSanitizer(home: "/Users/bob")
        s.capturePID = 300
        for lines in [[forkSubshell, forkCat, subshellExit, read], [forkSubshell, subshellExit, read]] {
            let (out, report) = s.sanitize(lines: lines)
            XCTAssertEqual(report.foreignVaultEvents, 0)
            XCTAssertEqual(report.vaultEvents, 1)
            XCTAssertEqual(out.count, lines.count, "the read and its ancestry")
        }
    }

    /// Review of the foreign-vault variant: a program outside the capture script's tree that reaches the
    /// vault through system binaries (an agent's node running `/bin/zsh -c 'cat ~/WhoReadTestVault/…'`).
    /// The cat is a system program, but its ancestry must not come with it: node's fork names node and
    /// its team id, and zsh's exec (whose process is the pre-exec node image) keeps the full command line.
    func testSystemProgramsStartedByAForeignProgramDoNotBringItsLifecycle() {
        let vault = "/Users/bob/WhoReadTestVault/ssh/id_ed25519"
        let node = "/opt/homebrew/Cellar/node/22.1.0/bin/node"
        let team = #""TEAMNODE01""#
        func proc(_ pid: Int, _ ppid: Int, _ exe: String) -> String {
            #"{"audit_token":{"pid":\#(pid)},"ppid":\#(ppid),"original_ppid":\#(ppid),"executable":{"path":"\#(exe)"}}"#
        }
        let lines = [
            line("fork", #"{"child":\#(proc(801, 800, node))}"#, pid: 800, ppid: 700, exe: node, team: team),
            line("exec", #"{"target":\#(proc(801, 800, "/bin/zsh")),"args":["/bin/zsh","-c","cd ~/Projects/AcmeMerger && cat ~/WhoReadTestVault/ssh/id_ed25519"],"env":[],"cwd":\#(file("/"))}"#,
                 pid: 801, ppid: 800, exe: node, team: team),
            line("fork", #"{"child":\#(proc(802, 801, "/bin/zsh"))}"#, pid: 801, ppid: 800, exe: "/bin/zsh"),
            // The cat's exec names the vault, but runs in the agent's project directory.
            line("exec", #"{"target":\#(proc(802, 801, "/bin/cat")),"args":["cat","\#(vault)"],"env":[],"cwd":\#(file("/Users/bob/Projects/AcmeMerger"))}"#,
                 pid: 802, ppid: 801, exe: "/bin/zsh"),
            line("open", open(vault), pid: 802, ppid: 801, exe: "/bin/cat"),
            line("exit", #"{"stat":0}"#, pid: 802, ppid: 801, exe: "/bin/cat"),
            line("exit", #"{"stat":0}"#, pid: 801, ppid: 800, exe: "/bin/zsh"),
        ]
        // No samples: every kept line is a vault or lifecycle event.
        var s = FixtureSanitizer(home: "/Users/bob", samplePerKind: 0)
        s.capturePID = 300
        let (out, report) = s.sanitize(lines: lines)
        let joined = out.joined(separator: "\n")
        for leak in ["homebrew", "TEAMNODE01", "AcmeMerger"] { XCTAssertFalse(joined.contains(leak), "\(leak): \(joined)") }
        XCTAssertEqual(out.count, 1, "only the system program's own read: \(joined)")
        XCTAssertTrue(joined.contains(#""pid":802"#), joined)
        XCTAssertEqual(report.foreignVaultEvents, 1, "the cat's exec, whose line names the agent's project")
        XCTAssertEqual(report.lifecycle, 0)
    }

    /// privacy-6: a raw capture with a line that is not UTF-8 is sanitized, that line dropped and
    /// counted, instead of failing the whole run (which left the raw capture behind).
    func testUndecodableLinesAreDroppedAndCounted() {
        let good = line("open", open("/usr/share/icu/icudt76l.dat"), pid: 70)
        var data = Data((good + "\n").utf8)
        data.append(contentsOf: [0x7B, 0xFF, 0xFE, 0x7D, 0x0A])
        data.append(Data((good + "\n\n").utf8))
        let (out, report) = FixtureSanitizer(home: "/Users/bob").sanitize(data: data)
        XCTAssertEqual(report.inputLines, 3)
        XCTAssertEqual(report.undecodableLines, 1)
        XCTAssertEqual(out.count, 2)
    }
}

/// install-3, install-4, privacy-6: scripts/capture-fixture.sh against stubs.
///
/// A copy of the script runs in a temporary repository with its two root-side literals patched:
/// `/usr/bin/eslogger` becomes a fake that writes a few lines and waits for SIGINT like eslogger, and
/// the `/private/tmp` parent of the root-only directory becomes a temporary directory. `sudo` is a
/// stub first on PATH that records each call and runs it unprivileged, so nothing runs as root and no
/// Endpoint Security client is created. A stub cannot show that the directory really is root-owned:
/// that rests on `sudo mktemp -d` in the sticky /private/tmp, checked as text.
final class CaptureFixtureScriptTests: XCTestCase {
    override func setUpWithError() throws {
        #if !os(macOS)
        throw XCTSkip("capture-fixture.sh needs sw_vers and cp -c")
        #endif
    }

    private struct Run {
        let status: Int32
        let stderr: String
        let calls: [String]
    }

    private struct Unsafe: Error { let reason: String }

    /// The `whoread` executable next to the test bundle (`swift build --build-tests` and
    /// scripts/dev/sc-build.sh build it).
    private static let whoread: String? = {
        var dirs: [URL] = []
        #if os(macOS)
        dirs += Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        #endif
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private static let rawDirTemplate = "/private/tmp/whoread-capture."

    private func repoFile(_ relative: String) -> String { repoRoot.appendingPathComponent(relative).path }

    private func executable(_ path: String, _ body: String) throws {
        try body.write(toFile: path, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
    }

    /// The fake eslogger: three lines (the script's own vault read and exec, and a third-party
    /// scanner's vault read), one line that is not UTF-8, then it waits for SIGINT.
    private static let fakeEslogger = #"""
    #!/bin/bash
    trap 'touch "$ES_STOPPED"; exit 0' INT TERM
    touch "$ES_STARTED"
    if [ "${ES_MODE:-}" = early-exit ]; then echo "eslogger: not permitted to create a client" >&2; exit 1; fi
    V="$HOME/WhoReadTestVault/ssh/id_ed25519"
    P='"ppid":'"$PPID"',"original_ppid":'"$PPID"
    echo '{"schema_version":1,"event":{"open":{"fflag":1,"file":{"path":"'"$V"'"}}},"process":{"audit_token":{"pid":4242},'"$P"',"executable":{"path":"/bin/cat"}}}'
    echo '{"schema_version":1,"event":{"exec":{"args":["cat","'"$V"'"],"env":["FAKE_SECRET=s3cr3t-env-token"],"target":{"audit_token":{"pid":4242},"executable":{"path":"/bin/cat"}}}},"process":{"audit_token":{"pid":4242},'"$P"',"executable":{"path":"/bin/bash"}}}'
    echo '{"schema_version":1,"event":{"open":{"fflag":1,"file":{"path":"'"$V"'"}}},"process":{"audit_token":{"pid":4343},"ppid":1,"original_ppid":1,"team_id":"TEAMAV1234","executable":{"path":"/Applications/SecretAV.app/Contents/MacOS/scanner"}}}'
    printf '{\377\376}\n'
    for _ in $(seq 400); do sleep 0.05; done
    """#

    /// `sudo`: records the call (and whether the unprivileged caller redirected its output to a
    /// file), refuses the real eslogger, then runs it as the test user.
    private static let sudoStub = #"""
    #!/bin/bash
    so=-; se=-
    [ -f /dev/stdout ] && so=FILE
    [ -f /dev/stderr ] && se=FILE
    { printf 'sudo stdout=%s stderr=%s' "$so" "$se"; printf ' %s' "$@"; printf '\n'; } >> "$LOG"
    for a in "$@"; do [ "$a" = /usr/bin/eslogger ] && exit 99; done
    [ "$1" = -v ] && exit 0
    exec "$@"
    """#

    /// The `whoread` that `swift build -c release --product whoread` (a stub) leaves in the repository.
    private enum Sanitizer {
        case real(String)
        case succeeds
        case fails
        /// The build fails.
        case unbuildable
    }

    /// Builds the temporary repository, stubs and fake in `dir`.
    private func prepare(_ dir: TempDir, whoread: Sanitizer) throws {
        let fm = FileManager.default
        for d in ["repo/scripts", "bin", "home", "tmp", "root-tmp"] {
            try fm.createDirectory(atPath: dir.path(d), withIntermediateDirectories: true)
        }
        let original = try String(contentsOfFile: repoFile("scripts/capture-fixture.sh"), encoding: .utf8)
        let patched = original
            .replacingOccurrences(of: "/usr/bin/eslogger", with: dir.path("fake-eslogger"))
            .replacingOccurrences(of: Self.rawDirTemplate, with: dir.path("root-tmp") + "/whoread-capture.")
        // Hermetic, also on CI runners with passwordless sudo: sudo can only be the stub, and no
        // root-side path of the real script survives.
        for s in ["/sudo", "/usr/bin/eslogger", Self.rawDirTemplate] where patched.contains(s) {
            throw Unsafe(reason: "the patched script still contains \(s)")
        }
        try executable(dir.path("repo/scripts/capture-fixture.sh"), patched)
        try executable(dir.path("repo/scripts/create-test-vault.sh"),
                       try String(contentsOfFile: repoFile("scripts/create-test-vault.sh"), encoding: .utf8))
        try executable(dir.path("fake-eslogger"), Self.fakeEslogger)
        try executable(dir.path("bin/sudo"), Self.sudoStub)
        // /bin/ps is not allowed in every sandbox; the script only asks whether a pid is alive.
        try executable(dir.path("bin/ps"), "#!/bin/bash\n[ \"$1\" = -p ] || exit 1\nkill -0 \"$2\" 2>/dev/null\n")
        try executable(dir.path("bin/mdls"), "#!/bin/bash\nexit 0\n")
        // An installed whoread first on PATH (the app's CLI, say): never the sanitizer, it may be older
        // than this checkout and silently ignore --capture-pid.
        try executable(dir.path("bin/whoread"), "#!/bin/bash\ntouch '\(dir.path("installed-whoread-ran"))'\nexit 1\n")
        let product: String?
        switch whoread {
        case .real(let path): product = path
        case .succeeds: product = dir.path("sanitizer"); try executable(dir.path("sanitizer"), "#!/bin/bash\ncat > /dev/null\n")
        case .fails: product = dir.path("sanitizer"); try executable(dir.path("sanitizer"), "#!/bin/bash\nexit 3\n")
        case .unbuildable: product = nil
        }
        // `swift build` run in the repository links the product into its .build/release.
        try executable(dir.path("bin/swift"), product.map { """
            #!/bin/bash
            [ "$*" = "build -c release --product whoread" ] || exit 2
            [ "$(pwd -P)" = "$(cd '\(dir.path("repo"))' && pwd -P)" ] || exit 2
            mkdir -p .build/release && ln -sf '\($0)' .build/release/whoread

            """ } ?? "#!/bin/bash\nexit 1\n")
    }

    private func run(_ dir: TempDir, env extra: [String: String] = [:], interrupt: Bool = false) throws -> Run {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = [dir.path("repo/scripts/capture-fixture.sh")]
        proc.environment = [
            "PATH": dir.path("bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": dir.path("home"), "TMPDIR": dir.path("tmp"), "LOG": dir.path("sudo.log"), "DURATION": "5",
            "ES_STARTED": dir.path("es-started"), "ES_STOPPED": dir.path("es-stopped"),
        ].merging(extra) { $1 }
        let err = Pipe()
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = err
        try proc.run()
        if interrupt {
            XCTAssertNotNil(waitFor(15) { FileManager.default.fileExists(atPath: dir.path("es-started")) }, "eslogger never started")
            proc.interrupt()
        }
        let e = err.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        let calls = ((try? String(contentsOfFile: dir.path("sudo.log"), encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
        return Run(status: proc.terminationStatus, stderr: String(decoding: e, as: UTF8.self), calls: calls)
    }

    private func entries(_ path: String) -> [String] { (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [] }

    /// What holds whatever the run's outcome: root only touches its own directory, opens its own
    /// output files and runs absolute paths; nothing of the raw capture is left behind.
    private func assertConfined(_ r: Run, _ dir: TempDir, keptRaw: Bool = false, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(r.calls.contains("sudo stdout=- stderr=- -v"), "the sudo stub ran: \(r.calls)", file: file, line: line)
        for call in r.calls {
            XCTAssertFalse(call.contains("chown"), call, file: file, line: line)
            XCTAssertFalse(call.contains(dir.path("repo")), "root touches the user-writable repository: \(call)", file: file, line: line)
            XCTAssertTrue(call.hasPrefix("sudo stdout=- stderr=- "), "an unprivileged shell opened root's output: \(call)", file: file, line: line)
            let command = call.split(separator: " ").dropFirst(3).first ?? ""
            XCTAssertTrue(command == "-v" || command.hasPrefix("/"), "root runs a PATH lookup: \(call)", file: file, line: line)
        }
        XCTAssertEqual(entries(dir.path("repo/Tests/Fixtures/eslogger/captured/raw")), [], file: file, line: line)
        XCTAssertEqual(entries(dir.path("root-tmp")).count, keptRaw ? 1 : 0, "\(entries(dir.path("root-tmp")))", file: file, line: line)
        XCTAssertEqual(entries(dir.path("tmp")).filter { $0.hasPrefix("whoread-capture") }, [], "scratch left behind", file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("installed-whoread-ran")), "an installed whoread ran",
                       file: file, line: line)
    }

    func testCaptureKeepsTheRawCaptureRootOnlyAndRemovesIt() throws {
        guard let wr = Self.whoread else { throw XCTSkip("the whoread executable is not built") }
        let dir = TempDir()
        try prepare(dir, whoread: .real(wr))
        // Links where the old script wrote fixed names: never written through.
        let precious = dir.path("precious")
        try "precious".write(toFile: precious, atomically: false, encoding: .utf8)
        let fm = FileManager.default
        try fm.createSymbolicLink(atPath: dir.path("tmp/whoread-clone-test"), withDestinationPath: precious)
        try fm.createDirectory(atPath: dir.path("home/WhoReadTestVault/notes"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: dir.path("home/WhoReadTestVault/notes/truncate-me.txt"), withDestinationPath: precious)

        let r = try run(dir, env: ["WHOREAD_TEST_VAULT": dir.path("elsewhere")])
        XCTAssertEqual(r.status, 0, r.stderr)
        assertConfined(r, dir)
        XCTAssertTrue(r.calls.contains { $0.contains("/usr/bin/mktemp -d \(dir.path("root-tmp"))/whoread-capture.") }, "\(r.calls)")
        let original = try String(contentsOfFile: repoFile("scripts/capture-fixture.sh"), encoding: .utf8)
        XCTAssertTrue(original.contains("sudo /usr/bin/mktemp -d \(Self.rawDirTemplate)XXXXXXXX"), "a root-owned directory in the sticky /private/tmp")

        let captured = dir.path("repo/Tests/Fixtures/eslogger/captured")
        let san = try XCTUnwrap(entries(captured).first { $0.hasPrefix("macos-") }, "\(entries(captured))")
        let fixture = try String(contentsOfFile: captured + "/" + san + "/capture.jsonl", encoding: .utf8)
        XCTAssertTrue(fixture.contains("/Users/alice/WhoReadTestVault/ssh/id_ed25519"), fixture)
        XCTAssertFalse(fixture.contains("s3cr3t"), fixture)
        XCTAssertFalse(fixture.contains("SecretAV"), "a process outside the script's tree touching the vault")
        XCTAssertEqual(try String(contentsOfFile: precious, encoding: .utf8), "precious")
        XCTAssertFalse(fm.fileExists(atPath: dir.path("elsewhere")), "the vault exercised is the vault created")
        XCTAssertEqual(entries(dir.path("home/WhoReadTestVault/notes")).sorted(), ["old.txt", "todo.txt"], "the symlink and directory creates are undone")
    }

    func testKeepRawLeavesTheCaptureOnlyInTheRootOnlyDirectory() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .succeeds)
        let r = try run(dir, env: ["KEEP_RAW": "1"])
        XCTAssertEqual(r.status, 0, r.stderr)
        assertConfined(r, dir, keptRaw: true)
        let kept = try XCTUnwrap(entries(dir.path("root-tmp")).first)
        let raw = try Data(contentsOf: URL(fileURLWithPath: dir.path("root-tmp/\(kept)/raw.jsonl")))
        XCTAssertNotNil(raw.range(of: Data("s3cr3t-env-token".utf8)), "the raw capture itself")
        XCTAssertTrue(r.stderr.contains(dir.path("root-tmp/\(kept)")), r.stderr)
    }

    func testFailedSanitizeRemovesTheRawCapture() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .fails)
        let r = try run(dir)
        XCTAssertNotEqual(r.status, 0)
        assertConfined(r, dir)
        XCTAssertTrue(r.stderr.contains("raw capture was removed"), r.stderr)
    }

    /// Variant: whoread is found or built before anything is captured. The old order built it after
    /// the capture and died on an unset `WR` with the raw capture in the repository.
    func testUnbuildableSanitizerStopsBeforeAnyCapture() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .unbuildable)
        let r = try run(dir)
        XCTAssertEqual(r.status, 1, r.stderr)
        XCTAssertTrue(r.stderr.contains("building whoread failed"), r.stderr)
        XCTAssertEqual(r.calls, [], "no sudo at all, not even -v")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("installed-whoread-ran")), "an installed whoread ran")
        XCTAssertEqual(entries(dir.path("root-tmp")), [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("es-started")))
    }

    /// The capture subscribed 11 events and left out exchangedata and create, which EsloggerSource
    /// subscribes: no fixture could show the parser those shapes.
    func testCaptureSubscribesWhatEsloggerSourceSubscribes() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .succeeds)
        let r = try run(dir, env: ["ES_MODE": "early-exit"])
        assertConfined(r, dir)
        let fake = dir.path("fake-eslogger") + " "
        let call = try XCTUnwrap(r.calls.first { $0.contains(fake) }, "\(r.calls)")
        let events = call.components(separatedBy: fake)[1].split(separator: " ").map(String.init)
        XCTAssertEqual(events.sorted(), EsloggerSource.eventNames(readdir: false).sorted())
    }

    func testEarlyEsloggerExitRemovesTheRawCapture() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .succeeds)
        let r = try run(dir, env: ["ES_MODE": "early-exit"])
        XCTAssertEqual(r.status, 1, r.stderr)
        assertConfined(r, dir)
        XCTAssertTrue(r.stderr.contains("not permitted to create a client"), r.stderr)
        XCTAssertTrue(r.stderr.contains("raw capture was removed"), r.stderr)
    }

    func testInterruptRemovesTheRawCaptureAndStopsEslogger() throws {
        let dir = TempDir()
        try prepare(dir, whoread: .succeeds)
        let r = try run(dir, interrupt: true)
        XCTAssertEqual(r.status, 130, r.stderr)
        assertConfined(r, dir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path("es-stopped")), "eslogger left running")
    }

    /// Variant: create-test-vault.sh writes through whatever sits at the vault paths. A link there
    /// (planted or left over) must never turn the fake config or credentials into a write to a real file.
    func testCreateTestVaultRefusesSymbolicLinks() throws {
        let fm = FileManager.default
        func create(_ dir: TempDir) throws -> Int32 {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/bin/bash")
            proc.arguments = [repoFile("scripts/create-test-vault.sh")]
            proc.environment = ["PATH": "/usr/bin:/bin", "HOME": dir.path("home")]
            proc.standardOutput = FileHandle.nullDevice
            proc.standardError = FileHandle.nullDevice
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus
        }
        let dir = TempDir()
        let realSSH = dir.path("real-ssh")
        try fm.createDirectory(atPath: realSSH, withIntermediateDirectories: true)
        try "Host real\n".write(toFile: realSSH + "/config", atomically: false, encoding: .utf8)
        try fm.createDirectory(atPath: dir.path("home/WhoReadTestVault"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: dir.path("home/WhoReadTestVault/ssh"), withDestinationPath: realSSH)
        XCTAssertEqual(try create(dir), 1)
        XCTAssertEqual(try String(contentsOfFile: realSSH + "/config", encoding: .utf8), "Host real\n")
        XCTAssertFalse(fm.fileExists(atPath: realSSH + "/id_ed25519"))

        try fm.removeItem(atPath: dir.path("home/WhoReadTestVault/ssh"))
        let realCredentials = dir.path("real-credentials")
        try "real\n".write(toFile: realCredentials, atomically: false, encoding: .utf8)
        try fm.createDirectory(atPath: dir.path("home/WhoReadTestVault/aws"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: dir.path("home/WhoReadTestVault/aws/credentials"), withDestinationPath: realCredentials)
        XCTAssertEqual(try create(dir), 1)
        XCTAssertEqual(try String(contentsOfFile: realCredentials, encoding: .utf8), "real\n")

        // Without links it still builds the vault.
        try fm.removeItem(atPath: dir.path("home/WhoReadTestVault/aws/credentials"))
        XCTAssertEqual(try create(dir), 0)
        XCTAssertTrue(fm.fileExists(atPath: dir.path("home/WhoReadTestVault/ssh/id_ed25519")))
    }
}
