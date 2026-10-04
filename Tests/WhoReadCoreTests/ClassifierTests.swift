import XCTest
@testable import WhoReadCore

final class ClassifierTests: XCTestCase {
    var classifier: PathClassifier!

    override func setUpWithError() throws {
        let data = try defaultData()
        classifier = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: [home]),
                                    projectRoots: ["~/code", "/Users/alice/Work/项目"])
    }

    func c(_ path: String) -> Classification? { classifier.classify(path) }

    func testSSHSeverities() {
        XCTAssertEqual(c("/Users/alice/.ssh/id_ed25519")?.categoryID, "ssh")
        XCTAssertEqual(c("/Users/alice/.ssh/id_ed25519")?.severity, .critical)
        XCTAssertEqual(c("/Users/alice/.ssh/id_ed25519.pub")?.severity, .medium)
        XCTAssertEqual(c("/Users/alice/.ssh/config")?.severity, .medium)
        XCTAssertEqual(c("/Users/alice/.ssh/known_hosts")?.severity, .medium)
        XCTAssertEqual(c("/Users/alice/.ssh/known_hosts.old")?.severity, .medium)
        // Unknown names in ~/.ssh may be keys: critical.
        XCTAssertEqual(c("/Users/alice/.ssh/github-deploy")?.severity, .critical)
        // The directory itself (rename/readdir of ~/.ssh).
        XCTAssertEqual(c("/Users/alice/.ssh")?.categoryID, "ssh")
        XCTAssertEqual(c("/Users/alice/.ssh")?.relativePath, "")
    }

    func testSpellingsOfTheSameFile() {
        XCTAssertEqual(c("/System/Volumes/Data/Users/alice/.ssh/id_rsa")?.categoryID, "ssh")
        XCTAssertEqual(c("/USERS/ALICE/.SSH/ID_RSA")?.categoryID, "ssh")
        XCTAssertEqual(c("/Users/alice/.ssh/../.ssh/./id_rsa")?.categoryID, "ssh")
    }

    func testComponentBoundaries() {
        XCTAssertEqual(c("/Users/alice/.npmrc")?.categoryID, "npm")
        XCTAssertNil(c("/Users/alice/.npmrc.bak"))
        XCTAssertNil(c("/Users/alice/.sshfoo/id_rsa"))
        XCTAssertNil(c("/Users/alice/.ssh2"))
        XCTAssertNil(c("/Users/bob/.ssh/id_rsa"), "bob is not a monitored home here")
        XCTAssertEqual(c("/Users/alice/.docker/config.json")?.categoryID, "docker")
        XCTAssertNil(c("/Users/alice/.docker/contexts/meta.json"))
    }

    func testDevCredentialCategories() {
        XCTAssertEqual(c("/Users/alice/.aws/credentials")?.categoryID, "aws")
        XCTAssertEqual(c("/Users/alice/.config/gcloud/application_default_credentials.json")?.categoryID, "gcloud")
        XCTAssertEqual(c("/Users/alice/.kube/config")?.categoryID, "kube")
        XCTAssertEqual(c("/Users/alice/.config/gh/hosts.yml")?.severity, .critical)
        XCTAssertEqual(c("/Users/alice/.config/gh/config.yml")?.severity, .medium)
        XCTAssertNil(c("/Users/alice/.gnupg/S.gpg-agent"), "agent sockets are excluded")
        XCTAssertEqual(c("/Users/alice/.gnupg/private-keys-v1.d/ABC.key")?.severity, .critical)
    }

    func testBrowserPatterns() {
        let chrome = "/Users/alice/Library/Application Support/Google/Chrome"
        XCTAssertEqual(c(chrome + "/Default/Cookies")?.severity, .critical)
        XCTAssertEqual(c(chrome + "/Profile 1/Login Data")?.severity, .critical)
        XCTAssertEqual(c(chrome + "/Default/Web Data")?.severity, .critical)
        XCTAssertEqual(c(chrome + "/Default/History")?.severity, .high)
        XCTAssertEqual(c(chrome + "/Default/Preferences")?.severity, .medium)
        XCTAssertNil(c(chrome + "/Default/Cache/Cache_Data/f_000001"))
        XCTAssertEqual(c("/Users/alice/Library/Application Support/Firefox/Profiles/x.default/logins.json")?.severity, .critical)
        XCTAssertEqual(c("/Users/alice/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies")?.severity, .critical)
    }

    func testLongestPrefixWins() throws {
        var catalog = try defaultData().catalog
        catalog.categories.append(CategorySpec(id: "deep", name: LocalizedText("deep"), severity: .medium,
                                               paths: ["~/.ssh/work/"]))
        let k = PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: [home]))
        XCTAssertEqual(k.classify("/Users/alice/.ssh/work/id_rsa")?.categoryID, "deep")
        XCTAssertEqual(k.classify("/Users/alice/.ssh/id_rsa")?.categoryID, "ssh")
    }

    func testProjectRoots() {
        XCTAssertEqual(c("/Users/alice/code/web/.env")?.categoryID, "project-secrets")
        XCTAssertEqual(c("/Users/alice/code/web/.env.production")?.severity, .high)
        XCTAssertEqual(c("/Users/alice/code/web/certs/server.pem")?.severity, .critical)
        XCTAssertEqual(c("/Users/alice/code/api/tls.key")?.severity, .critical)
        XCTAssertNil(c("/Users/alice/code/web/.env.example"))
        XCTAssertNil(c("/Users/alice/code/web/node_modules/dotenv/.env"))
        XCTAssertNil(c("/Users/alice/code/web/src/index.ts"), "only patterns are sensitive in project roots")
        XCTAssertNil(c("/Users/alice/elsewhere/.env"), "outside project roots")
        // Non-ASCII project root, decomposed input.
        XCTAssertEqual(c("/Users/alice/Work/\u{9879}\u{76EE}/.env")?.categoryID, "project-secrets")
    }

    func testTestVault() {
        XCTAssertEqual(c("/Users/alice/WhoReadTestVault/ssh/id_ed25519")?.categoryID, "test-vault")
        XCTAssertEqual(c("/Users/alice/WhoReadTestVault/ssh/id_ed25519")?.severity, .critical)
        XCTAssertEqual(c("/Users/alice/WhoReadTestVault/ssh/id_ed25519.pub")?.severity, .medium)
        XCTAssertEqual(c("/Users/alice/WhoReadTestVault/notes/todo.txt")?.severity, .medium)
    }

    func testAncestorsOfSensitiveDirectories() {
        XCTAssertTrue(classifier.ancestors.contains("/Users/alice/.config"))
        XCTAssertTrue(classifier.ancestors.contains("/Users/alice/Library/Application Support"))
        XCTAssertFalse(classifier.ancestors.contains("/Users/alice/.ssh"))
        let below = classifier.categoriesBelow(normalized: "/Users/alice/.config")
        XCTAssertTrue(below.contains("gh"))
        XCTAssertTrue(below.contains("gcloud"))
        XCTAssertEqual(classifier.categoriesBelow(normalized: "/Users/alice/.ssh/id_rsa"), [], "inside a prefix is not an ancestor")
        XCTAssertEqual(classifier.categoriesBelow(normalized: "/Users/alice/Documents"), [])
    }

    func testSymlinkedPrefixAddsResolvedAlias() throws {
        let data = try defaultData()
        let k = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: [home]),
                               symlinks: MapSymlinkResolver(["/Users/alice/.ssh": "/Users/alice/Dropbox/dotfiles/ssh"]))
        XCTAssertEqual(k.classify("/Users/alice/Dropbox/dotfiles/ssh/id_rsa")?.categoryID, "ssh")
        XCTAssertTrue(k.prefixes.contains { $0.path == "/Users/alice/Dropbox/dotfiles/ssh" && $0.viaSymlink })
    }

    func testDisabledCategoryIsIgnored() throws {
        var catalog = try defaultData().catalog
        let i = catalog.categories.firstIndex { $0.id == "ssh" }!
        catalog.categories[i].enabled = false
        let k = PathClassifier(catalog: catalog, normalizer: PathNormalizer(homeDirectories: [home]))
        XCTAssertNil(k.classify("/Users/alice/.ssh/id_rsa"))
    }

    func testDetection() {
        let existing: Set<String> = ["/Users/alice/.ssh", "/Volumes"]
        let d = classifier.detection { existing.contains($0) }
        XCTAssertEqual(d["ssh"], true)
        XCTAssertEqual(d["volumes"], true)
        XCTAssertEqual(d["aws"], false)
        XCTAssertEqual(d["custom"], false)
    }

    func testCatalogRoundTripAndShape() throws {
        let data = try defaultData()
        let again = try Catalog.load(from: data.catalog.encoded())
        XCTAssertEqual(again, data.catalog)
        let ids = data.catalog.categories.map(\.id)
        XCTAssertEqual(Set(ids).count, ids.count, "category ids are unique")
        for required in ["ssh", "aws", "gcloud", "azure", "kube", "docker", "npm", "pypi", "netrc", "git-credentials", "gh",
                         "gnupg", "keychain", "chrome", "brave", "edge", "arc", "firefox", "safari", "1password", "bitwarden",
                         "proton-pass", "messages", "wechat", "telegram", "signal", "simplex", "mail", "contacts", "calendar",
                         "photos", "shell-history", "cloud-storage", "iphone-backup", "volumes", "claude-sessions",
                         "codex-sessions", "gemini-sessions", "cursor-data", "opencode-data", "test-vault",
                         "project-secrets", "custom"] {
            XCTAssertTrue(ids.contains(required), required)
        }
        for c in data.catalog.categories {
            XCTAssertFalse(c.name.en.isEmpty)
            XCTAssertFalse(c.name.zhHans.isEmpty)
        }
    }

    func testOwners() throws {
        let ssh = ProcessRecord(pid: 9, ppid: 1, executablePath: "/usr/bin/ssh", isPlatformBinary: true)
        XCTAssertTrue(classifier.isOwner(ssh, of: "ssh"))
        // Same name, not Apple-signed, not in a known location: not an owner.
        let fake = ProcessRecord(pid: 9, ppid: 1, executablePath: "/tmp/ssh", isPlatformBinary: false)
        XCTAssertFalse(classifier.isOwner(fake, of: "ssh"))
        // A copied Apple binary keeps its platform flag; outside system locations it is not an owner.
        let copied = ProcessRecord(pid: 9, ppid: 1, executablePath: "/usr/local/bin/ssh", isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(copied, of: "ssh"))
        let fakeKeychainApp = ProcessRecord(pid: 9, ppid: 1, executablePath: "/Users/alice/x/Keychain Access.app/Contents/MacOS/cp",
                                            isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(fakeKeychainApp, of: "keychain"))
        let keychainApp = ProcessRecord(pid: 9, ppid: 1, executablePath: "/System/Applications/Utilities/Keychain Access.app/Contents/MacOS/Keychain Access",
                                        isPlatformBinary: true)
        XCTAssertTrue(classifier.isOwner(keychainApp, of: "keychain"))
        // git does not read ~/.ssh itself (ssh does).
        let git = ProcessRecord(pid: 9, ppid: 1, executablePath: "/Library/Developer/CommandLineTools/usr/bin/git", isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(git, of: "ssh"))
        XCTAssertTrue(classifier.isOwner(git, of: "git-credentials"))
        // Shells and curl are not owners: they read on behalf of whoever runs them.
        let zsh = ProcessRecord(pid: 9, ppid: 1, executablePath: "/bin/zsh", isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(zsh, of: "shell-history"))
        let curl = ProcessRecord(pid: 9, ppid: 1, executablePath: "/usr/bin/curl", isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(curl, of: "netrc"))
        // Third-party bundles need a team ID (filled by `whoread catalog resolve-owners`).
        let chromeHelper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
        var chrome = ProcessRecord(pid: 9, ppid: 1, executablePath: chromeHelper, teamID: "TEAMCHROME")
        XCTAssertFalse(classifier.isOwner(chrome, of: "chrome"), "unresolved catalog: fail closed")
        var data = try defaultData()
        let i = data.catalog.categories.firstIndex { $0.id == "chrome" }!
        data.catalog.categories[i].owners[0].teamIDs = ["TEAMCHROME"]
        let resolved = PathClassifier(catalog: data.catalog, normalizer: PathNormalizer(homeDirectories: [home]))
        XCTAssertTrue(resolved.isOwner(chrome, of: "chrome"))
        XCTAssertFalse(resolved.isOwner(chrome, of: "firefox"))
        chrome.teamID = "OTHERTEAM"
        XCTAssertFalse(resolved.isOwner(chrome, of: "chrome"), "same path, different signer")
        let cat = ProcessRecord(pid: 9, ppid: 1, executablePath: "/bin/cat", isPlatformBinary: true)
        XCTAssertFalse(classifier.isOwner(cat, of: "ssh"))
        // Script owners: the interpreter location and the script position must both match.
        let python = ProcessRecord(pid: 9, ppid: 1,
            executablePath: "/opt/homebrew/Cellar/python@3.12/3.12.5/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python",
            argv: ["python3", "/opt/homebrew/bin/aws", "s3", "ls"])
        XCTAssertTrue(classifier.isOwner(python, of: "aws"))
        var randomScript = python
        randomScript.argv = ["python3", "/tmp/steal.py"]
        XCTAssertFalse(classifier.isOwner(randomScript, of: "aws"))
        var trailing = python
        trailing.argv = ["python3", "/tmp/steal.py", "/opt/homebrew/bin/aws"]
        XCTAssertFalse(classifier.isOwner(trailing, of: "aws"), "argv only counts at the script position")
        let catPosingAsAWS = ProcessRecord(pid: 9, ppid: 1, executablePath: "/bin/cat", isPlatformBinary: true,
                                           argv: ["cat", "/opt/homebrew/bin/aws", "/Users/alice/.aws/credentials"])
        XCTAssertFalse(classifier.isOwner(catPosingAsAWS, of: "aws"), "not an interpreter")
        let az = ProcessRecord(pid: 9, ppid: 1, executablePath: "/opt/homebrew/Cellar/python@3.12/3.12.5/bin/python3.12",
                               argv: ["python3", "-Im", "azure.cli", "account", "show"])
        XCTAssertTrue(classifier.isOwner(az, of: "azure"))
        // Names alone never make an owner.
        let fakeGH = ProcessRecord(pid: 9, ppid: 1, executablePath: "/tmp/gh")
        XCTAssertFalse(classifier.isOwner(fakeGH, of: "gh"))
        let gh = ProcessRecord(pid: 9, ppid: 1, executablePath: "/opt/homebrew/Cellar/gh/2.60.0/bin/gh")
        XCTAssertTrue(classifier.isOwner(gh, of: "gh"))
        // Each agent owns only its own transcripts.
        let claude = ProcessRecord(pid: 9, ppid: 1, executablePath: "/opt/homebrew/Cellar/node/22.1.0/bin/node",
                                   argv: ["node", "/opt/homebrew/bin/claude"])
        XCTAssertTrue(classifier.isOwner(claude, of: "claude-sessions"))
        XCTAssertFalse(classifier.isOwner(claude, of: "codex-sessions"))
    }
}
