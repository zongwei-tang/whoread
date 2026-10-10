import XCTest
@testable import WhoReadCore

/// privacy-2: commands that write a monitored credential file are stored with their argv (the
/// shell's `-c` string and every process in the chain). These forms kept the password. The
/// redirect targets here are test-vault stand-ins for the real files (netrc, pypirc, pgpass, the AWS
/// credentials file, Docker's config.json): the redactor does not look at the target.
final class RedactorGapTests: XCTestCase {
    let R = ArgvRedactor.placeholder
    let secret = "Hunter2pw"

    func r(_ argv: [String]) -> [String] { ArgvRedactor.redact(argv, maxArgs: 32, maxLength: 4000)! }

    func assertRedacted(_ argv: [String], _ expected: [String]? = nil, secret: String? = nil, file: StaticString = #filePath, line: UInt = #line) {
        let out = r(argv)
        XCTAssertFalse(out.joined(separator: " ").contains(secret ?? self.secret), "kept: \(out)", file: file, line: line)
        if let expected { XCTAssertEqual(out, expected, file: file, line: line) }
    }

    // MARK: - echo / printf / heredoc data written to a file or piped on

    func testEchoAndPrintfDataWrittenToAFileIsRedactedAndTheTargetKept() {
        assertRedacted(["/bin/zsh", "-c", "echo 'machine api.example.com login bob password Hunter2pw' >> ~/WhoReadTestVault/netrc"],
                       ["/bin/zsh", "-c", "echo '\(R)' >> ~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/zsh", "-c", "printf '[pypi]\\npassword = Hunter2pw\\n' > ~/WhoReadTestVault/pypirc"],
                       ["/bin/zsh", "-c", "printf '\(R)' > ~/WhoReadTestVault/pypirc"])
        assertRedacted(["/bin/sh", "-c", "echo 'db:5432:*:bob:Hunter2pw' >> ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "echo '\(R)' >> ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/sh", "-c", "echo '{\"auths\":{\"ghcr.io\":{\"auth\":\"Ym9iOkh1bnRlcjJwdw==\"}}}' > ~/WhoReadTestVault/docker/config.json"],
                       ["/bin/sh", "-c", "echo '\(R)' > ~/WhoReadTestVault/docker/config.json"], secret: "Ym9iOkh1bnRlcjJwdw")
        // Unquoted words, flags, attached and descriptor redirects.
        assertRedacted(["/bin/sh", "-c", "echo -n machine h login bob password Hunter2pw>>~/WhoReadTestVault/netrc"],
                       ["/bin/sh", "-c", "echo -n \(R) \(R) \(R) \(R) \(R) \(R)>>~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/sh", "-c", "cd /tmp && printf 'password=%s\\n' Hunter2pw 1>> ~/WhoReadTestVault/n; ls"],
                       ["/bin/sh", "-c", "cd /tmp && printf '\(R)' \(R) 1>> ~/WhoReadTestVault/n; ls"])
        // tee, through sudo.
        assertRedacted(["/bin/sh", "-c", "echo 'machine h login bob password Hunter2pw' | sudo tee -a ~/WhoReadTestVault/netrc"],
                       ["/bin/sh", "-c", "echo '\(R)' | sudo tee -a ~/WhoReadTestVault/netrc"])
    }

    func testDataPipedIntoAProgramIsRedacted() {
        assertRedacted(["/bin/sh", "-c", "printf 'protocol=https\\nhost=github.com\\nusername=bob\\npassword=Hunter2pw\\n' | git credential approve"],
                       ["/bin/sh", "-c", "printf '\(R)' | git credential approve"])
        assertRedacted(["/bin/sh", "-c", "echo Hunter2pw | docker login -u bob --password-stdin ghcr.io"],
                       ["/bin/sh", "-c", "echo \(R) | docker login -u bob --password-stdin ghcr.io"])
        // A here-string is data too.
        assertRedacted(["/bin/sh", "-c", "git credential approve <<< 'machine h login bob password Hunter2pw'"],
                       ["/bin/sh", "-c", "git credential approve <<< '\(R)'"])
    }

    func testHeredocsWrittenToAFileAreRedacted() {
        let ini = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = Hunter2Hunter2xx\n"
        let out = r(["/bin/bash", "-c", "cat > ~/WhoReadTestVault/aws/credentials <<EOF\n" + ini + "EOF"])[2]
        XCTAssertFalse(out.contains("Hunter2Hunter2xx"), out)
        XCTAssertFalse(out.contains("AKIA"), out)
        XCTAssertTrue(out.hasPrefix("cat > ~/WhoReadTestVault/aws/credentials <<EOF\n"), out)
        XCTAssertTrue(out.hasSuffix("\nEOF"), out)
        let teeOut = r(["/bin/bash", "-c", "tee -a ~/WhoReadTestVault/netrc <<'END'\nmachine h login bob password Hunter2pw\nEND"])[2]
        XCTAssertFalse(teeOut.contains(secret), teeOut)
        XCTAssertTrue(teeOut.hasPrefix("tee -a ~/WhoReadTestVault/netrc <<'END'"), teeOut)
        // `<< WORD`: the delimiter is a word of its own, and still goes through the token rules.
        let spaced = r(["/bin/bash", "-c", "cat << ghp_abcdefghijklmnopqrstuvwxyz0123456789 > ~/WhoReadTestVault/n\nx\nghp_abcdefghijklmnopqrstuvwxyz0123456789"])[2]
        XCTAssertFalse(spaced.contains("ghp_"), spaced)
        let after = r(["/bin/bash", "-c", "cat <<-EOF > ~/WhoReadTestVault/pypirc\n[pypi]\npassword = Hunter2pw\nEOF\necho done"])[2]
        XCTAssertFalse(after.contains(secret), after)
        XCTAssertTrue(after.hasSuffix("\nEOF\necho done"), "the command after the body is its own: \(after)")
    }

    // MARK: - key = value, flags, JSON, URLs

    func testINIStyleKeyEqualsValueWithSpaces() {
        // The review saw `aws_secret_access_key ‹redacted› Hunter2Hunter2xx`: the lone "=" took the redaction.
        let python = r(["/bin/bash", "-c", "python3 - <<EOF\naws_secret_access_key = Hunter2Hunter2xx\npassword = Hunter2pw\nEOF"])[2]
        XCTAssertEqual(python, "python3 - <<EOF\naws_secret_access_key = \(R)\npassword = \(R)\nEOF")
        assertRedacted(["aws", "configure", "set", "aws_secret_access_key", "=", "Hunter2pw"],
                       ["aws", "configure", "set", "aws_secret_access_key", "=", R])
        assertRedacted(["tool", "client_secret", ":", "Hunter2pw"], ["tool", "client_secret", ":", R])
    }

    func testPassAndPwdSuffixesInKeysAndFlags() {
        assertRedacted(["/bin/sh", "-c", "MYSQL_PWD=Hunter2pw mysql -u root db"], ["/bin/sh", "-c", "MYSQL_PWD=\(R) mysql -u root db"])
        assertRedacted(["/bin/sh", "-c", "DB_PASS=Hunter2pw ./migrate"], ["/bin/sh", "-c", "DB_PASS=\(R) ./migrate"])
        assertRedacted(["env", "SMTP-PASS=Hunter2pw", "redis.pwd=Hunter2pw", "app"], ["env", "SMTP-PASS=\(R)", "redis.pwd=\(R)", "app"])
        assertRedacted(["app", "--smtp-pass", "Hunter2pw"], ["app", "--smtp-pass", R])
        assertRedacted(["app", "--db_pwd=Hunter2pw"], ["app", "--db_pwd=\(R)"])
        assertRedacted(["app", "-password", "Hunter2pw", "-v"], ["app", "-password", R, "-v"])
        assertRedacted(["app", "-passwd", "Hunter2pw"], ["app", "-passwd", R])
        assertRedacted(["app", "-pass", "Hunter2pw"], ["app", "-pass", R])
        // Not secrets: paths, words that only end in "pass", and the shell's working directories.
        XCTAssertEqual(r(["env", "OLDPWD=/Users/alice/x", "PROJECT_PWD=/srv/p", "PWD=/tmp", "ls"]),
                       ["env", "OLDPWD=/Users/alice/x", "PROJECT_PWD=/srv/p", "PWD=/tmp", "ls"])
        XCTAssertEqual(r(["env", "ALLOW_BYPASS=yes", "COMPASS=north", "app", "--bypass", "cache", "--compass-dir", "x"]),
                       ["env", "ALLOW_BYPASS=yes", "COMPASS=north", "app", "--bypass", "cache", "--compass-dir", "x"])
        XCTAssertEqual(r(["app", "--db-pass", "/Users/alice/WhoReadTestVault/pw.txt"]), ["app", "--db-pass", "/Users/alice/WhoReadTestVault/pw.txt"])
        XCTAssertEqual(r(["app", "-p", "8080"]), ["app", "-p", "8080"])
    }

    func testEscapedJSONAndAuthKeys() {
        let curl = r(["/bin/sh", "-c", "curl -d \"{\\\"password\\\":\\\"Hunter2pw\\\"}\" https://x"])[2]
        XCTAssertEqual(curl, "curl -d \"{\\\"password\\\":\\\"\(R)\\\"}\" https://x")
        assertRedacted(["tool", "{\"auths\":{\"ghcr.io\":{\"auth\":\"Ym9iOkh1bnRlcjJwdw==\"}}}"],
                       ["tool", "{\"auths\":{\"ghcr.io\":{\"auth\":\"\(R)\"}}}"], secret: "Ym9iOkh1bnRlcjJwdw")
        assertRedacted(["tool", "{\"basic_auth\":\"Hunter2pw\"}"], ["tool", "{\"basic_auth\":\"\(R)\"}"])
        // Keys that only contain "auth" in another word are kept.
        XCTAssertEqual(r(["tool", "{\"author\":\"bob\",\"oauth_callback\":\"https://x/cb\"}"]),
                       ["tool", "{\"author\":\"bob\",\"oauth_callback\":\"https://x/cb\"}"])
    }

    func testSchemelessUserinfo() {
        assertRedacted(["mount", "-t", "smbfs", "//bob:Hunter2pw@nas/share", "/mnt/share"],
                       ["mount", "-t", "smbfs", "//bob:\(R)@nas/share", "/mnt/share"])
        assertRedacted(["mount_smbfs", "//bob:Hunter2pw@nas.local/share", "/mnt/s"], ["mount_smbfs", "//bob:\(R)@nas.local/share", "/mnt/s"])
        // npm's per-registry keys are not userinfo.
        XCTAssertEqual(r(["npm", "config", "set", "//registry.npmjs.org/:_authToken", "abc123"]),
                       ["npm", "config", "set", "//registry.npmjs.org/:_authToken", R])
        XCTAssertEqual(r(["ls", "//server/share"]), ["ls", "//server/share"])
    }

    // Variants: a newline starts a new command (the program's own flag table applies again), and a
    // line continuation between a flag and its value is not the value.
    func testMultiLineCommandsAndLineContinuations() {
        assertRedacted(["/bin/bash", "-c", "cd /tmp\ncurl -u admin:Hunter2pw https://x"],
                       ["/bin/bash", "-c", "cd /tmp\ncurl -u admin:\(R) https://x"])
        assertRedacted(["/bin/bash", "-c", "mysql --password \\\n  Hunter2pw -e 'select 1'"],
                       ["/bin/bash", "-c", "mysql --password \\\n  \(R) -e 'select 1'"])
        // A word that starts with a backslash kept its place (the space before it moved to the end).
        XCTAssertEqual(r(["/bin/sh", "-c", "echo \\$HOME done"]), ["/bin/sh", "-c", "echo \\$HOME done"])
        assertRedacted(["/bin/bash", "-c", "ls\necho 'machine h login bob password Hunter2pw' >> ~/WhoReadTestVault/netrc\nls"],
                       ["/bin/bash", "-c", "ls\necho '\(R)' >> ~/WhoReadTestVault/netrc\nls"])
    }

    func testNetrcLinesOutsideARedirect() {
        assertRedacted(["/bin/sh", "-c", "echo machine api.example.com login bob password Hunter2pw"],
                       ["/bin/sh", "-c", "echo machine api.example.com login bob password \(R)"])
    }

    // MARK: - Review round: forms of the same writes the first fix missed

    /// The data of an echo inside a `{ …; }` group or a `( … )` subshell goes where the group's
    /// redirect sends it, and a redirect may come before the program word.
    func testGroupsSubshellsAndRedirectsBeforeTheProgram() {
        assertRedacted(["/bin/sh", "-c", "{ echo 'db:5432:*:bob:Hunter2pw'; } > ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "{ echo '\(R)'; } > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/sh", "-c", "(echo 'db:5432:*:bob:Hunter2pw') >> ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "(echo '\(R)') >> ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/sh", "-c", "( echo 'machine h login bob password Hunter2pw'; echo x ) >> ~/WhoReadTestVault/netrc"],
                       ["/bin/sh", "-c", "( echo '\(R)'; echo \(R) ) >> ~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/sh", "-c", ">~/WhoReadTestVault/pgpass echo 'db:5432:*:bob:Hunter2pw'"],
                       ["/bin/sh", "-c", ">~/WhoReadTestVault/pgpass echo '\(R)'"])
        assertRedacted(["/bin/sh", "-c", "> ~/WhoReadTestVault/pgpass echo 'db:5432:*:bob:Hunter2pw'"],
                       ["/bin/sh", "-c", "> ~/WhoReadTestVault/pgpass echo '\(R)'"])
        // Not written anywhere: kept.
        for argv in [["/bin/sh", "-c", "{ echo hello; ls; }"], ["/bin/sh", "-c", "2>/dev/null echo hello"],
                     ["/bin/sh", "-c", "(cd /tmp && ls) > /tmp/out"], ["/bin/sh", "-c", "x=$(echo hello) && ls"]] {
            XCTAssertEqual(r(argv), argv)
        }
    }

    /// A pipe need not have spaces around it, and a quoted here-string is one word with spaces.
    func testUnspacedPipesAndAttachedHereStrings() {
        assertRedacted(["/bin/sh", "-c", "echo Hunter2pw|tee -a ~/WhoReadTestVault/n"],
                       ["/bin/sh", "-c", "echo \(R)|tee -a ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/sh", "-c", "printf 'password=Hunter2pw\\n'|git credential approve"],
                       ["/bin/sh", "-c", "printf '\(R)'|git credential approve"])
        assertRedacted(["/bin/sh", "-c", "echo Hunter2pw |docker login -u bob --password-stdin ghcr.io"],
                       ["/bin/sh", "-c", "echo \(R) |docker login -u bob --password-stdin ghcr.io"])
        assertRedacted(["/bin/sh", "-c", "tee -a ~/WhoReadTestVault/netrc <<<'machine h login bob password Hunter2pw'"],
                       ["/bin/sh", "-c", "tee -a ~/WhoReadTestVault/netrc <<<\(R)"])
        assertRedacted(["/bin/sh", "-c", "git credential approve <<<\"password=Hunter2pw host=h\""],
                       ["/bin/sh", "-c", "git credential approve <<<\(R)"])
        // `||` is not a pipe, and a quoted "|" is data written nowhere.
        for argv in [["/bin/sh", "-c", "echo hello||echo world"], ["/bin/sh", "-c", "echo 'a|b' ; ls"]] {
            XCTAssertEqual(r(argv), argv)
        }
    }

    /// JSON keys named like the key=value and flag rules (`pass`, `pwd`, `*_pass`).
    func testPassAndPwdJSONKeys() {
        assertRedacted(["curl", "-d", "{\"user\":\"bob\",\"pass\":\"Hunter2pw\"}", "https://x"],
                       ["curl", "-d", "{\"user\":\"bob\",\"pass\":\"\(R)\"}", "https://x"])
        assertRedacted(["curl", "-d", "{\"pwd\":\"Hunter2pw\",\"db_pass\":\"Hunter2pw\"}", "https://x"],
                       ["curl", "-d", "{\"pwd\":\"\(R)\",\"db_pass\":\"\(R)\"}", "https://x"])
        assertRedacted(["/bin/sh", "-c", "curl -d \"{\\\"user\\\":\\\"bob\\\",\\\"pass\\\":\\\"Hunter2pw\\\"}\" https://x"],
                       ["/bin/sh", "-c", "curl -d \"{\\\"user\\\":\\\"bob\\\",\\\"pass\\\":\\\"\(R)\\\"}\" https://x"])
        let kept = ["curl", "-d", "{\"bypass\":\"cache-please\",\"compass\":\"north\",\"passport\":\"P1234567\",\"pwd\":\"/Users/alice/x\"}", "https://x"]
        XCTAssertEqual(r(kept), kept)
    }

    // MARK: - What must stay

    func testOrdinaryCommandsAreKept() {
        for argv in [
            ["git", "commit", "-m", "update password reset flow"],
            ["git", "commit", "-m", "fix login password reset"],
            ["/bin/sh", "-c", "echo hello world"],
            ["/bin/sh", "-c", "cat ~/WhoReadTestVault/notes/todo.txt > /tmp/out"],
            ["/bin/sh", "-c", "grep -r token src/ | head -5"],
            ["/bin/sh", "-c", "ls -la | grep pass"],
            ["/bin/bash", "-c", "python3 - <<EOF\nprint(open('/Users/alice/WhoReadTestVault/x').read())\nEOF"],
            ["/bin/sh", "-c", "cp a b > /dev/null 2>&1"],
        ] {
            XCTAssertEqual(r(argv), argv, "\(argv)")
        }
        // In an argv (no shell), `>` and `<<` are ordinary arguments: no redirect keeps the next one whole.
        XCTAssertEqual(r(["tool", ">", "--password=Hunter2pw", "<<", "TOKEN=Hunter2pw"]), ["tool", ">", "--password=\(R)", "<<", "TOKEN=\(R)"])
        // Where the output goes is evidence: the target of a redirect is kept.
        XCTAssertEqual(r(["/bin/sh", "-c", "echo x > /tmp/out.txt"]), ["/bin/sh", "-c", "echo \(R) > /tmp/out.txt"])
    }
}
