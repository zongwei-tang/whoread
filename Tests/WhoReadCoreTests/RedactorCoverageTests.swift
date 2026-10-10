import XCTest
@testable import WhoReadCore

/// Command lines that put a password where the earlier redaction rules did not look: SQL that sets
/// one, passwords as positional arguments, `password:PW` tokens, URL userinfo with "/" or "@" in
/// the password, and data written by loops or after `exec > FILE`. Redirect targets are test-vault
/// stand-ins for the real credential files (the redactor does not look at the target).
final class RedactorCoverageTests: XCTestCase {
    let R = ArgvRedactor.placeholder
    let secret = "Hunter2pw"

    func r(_ argv: [String]) -> [String] { ArgvRedactor.redact(argv, maxArgs: 32, maxLength: 4000)! }

    func assertRedacted(_ argv: [String], _ expected: [String]? = nil, secrets: [String]? = nil,
                        file: StaticString = #filePath, line: UInt = #line) {
        let out = r(argv)
        for s in secrets ?? [secret] {
            XCTAssertFalse(out.joined(separator: " ").contains(s), "kept \(s): \(out)", file: file, line: line)
        }
        if let expected { XCTAssertEqual(out, expected, file: file, line: line) }
    }

    func assertKept(_ argvs: [[String]], file: StaticString = #filePath, line: UInt = #line) {
        for argv in argvs { XCTAssertEqual(r(argv), argv, file: file, line: line) }
    }

    // MARK: - SQL that sets a password

    func testSQLThatSetsAPasswordInClientArguments() {
        assertRedacted(["psql", "-c", "ALTER USER bob PASSWORD 'Hunter2pw'"], ["psql", "-c", "ALTER USER bob PASSWORD '\(R)'"])
        assertRedacted(["psql", "-c", "CREATE ROLE bob WITH LOGIN ENCRYPTED PASSWORD 'Hunter2pw' VALID UNTIL '2030-01-01'"],
                       ["psql", "-c", "CREATE ROLE bob WITH LOGIN ENCRYPTED PASSWORD '\(R)' VALID UNTIL '2030-01-01'"])
        assertRedacted(["psql", "-c", "ALTER ROLE bob PASSWORD $$Hunter2pw$$"], ["psql", "-c", "ALTER ROLE bob PASSWORD $$\(R)$$"])
        assertRedacted(["psql", "-c", "ALTER USER bob PASSWORD E'Hunter2pw'"], ["psql", "-c", "ALTER USER bob PASSWORD E'\(R)'"])
        assertRedacted(["mysql", "-e", "CREATE USER 'bob'@'%' IDENTIFIED BY 'Hunter2pw'"],
                       ["mysql", "-e", "CREATE USER 'bob'@'%' IDENTIFIED BY '\(R)'"])
        assertRedacted(["mysql", "-e", "ALTER USER 'bob'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'Hunter2pw'"],
                       ["mysql", "-e", "ALTER USER 'bob'@'localhost' IDENTIFIED WITH caching_sha2_password BY '\(R)'"])
        assertRedacted(["mysql", "-e", "SET PASSWORD FOR 'bob'@'%' = 'Hunter2pw'"], ["mysql", "-e", "SET PASSWORD FOR 'bob'@'%' = '\(R)'"])
        assertRedacted(["mysql", "-e", "SET PASSWORD = PASSWORD('Hunter2pw')"], ["mysql", "-e", "SET PASSWORD = PASSWORD('\(R)')"])
        assertRedacted(["mysql", "--execute=GRANT ALL ON db.* TO 'bob'@'%' IDENTIFIED BY \"Hunter2pw\""],
                       ["mysql", "--execute=GRANT ALL ON db.* TO 'bob'@'%' IDENTIFIED BY \"\(R)\""])
        assertRedacted(["mysql", "-e", "ALTER USER USER() IDENTIFIED BY 'Hunter2pw' REPLACE 'Old2pwxx'"],
                       ["mysql", "-e", "ALTER USER USER() IDENTIFIED BY '\(R)' REPLACE '\(R)'"], secrets: [secret, "Old2pwxx"])
        assertRedacted(["mariadb", "-e", "CREATE USER bob IDENTIFIED VIA ed25519 USING PASSWORD('Hunter2pw')"],
                       ["mariadb", "-e", "CREATE USER bob IDENTIFIED VIA ed25519 USING PASSWORD('\(R)')"])
        assertRedacted(["sqlcmd", "-Q", "ALTER LOGIN sa WITH PASSWORD = 'Hunter2pw' OLD_PASSWORD = 'Old2pwxx'"],
                       ["sqlcmd", "-Q", "ALTER LOGIN sa WITH PASSWORD = '\(R)' OLD_PASSWORD = '\(R)'"], secrets: [secret, "Old2pwxx"])
        assertRedacted(["snowsql", "-q", "ALTER USER bob SET PASSWORD = 'Hunter2pw'"], ["snowsql", "-q", "ALTER USER bob SET PASSWORD = '\(R)'"])
        // Cut short (a long command line is bounded) or closed outside this word: the rest of the line.
        assertRedacted(["psql", "-c", "ALTER USER bob PASSWORD 'Hunter2pw"], ["psql", "-c", "ALTER USER bob PASSWORD '\(R)"])
        assertRedacted(["mysql", "-e", "SET PASSWORD = \"Hunter2pw\nSELECT 1"], ["mysql", "-e", "SET PASSWORD = \"\(R)\nSELECT 1"])
        // A quote inside the literal ('' or \') does not end it.
        assertRedacted(["psql", "-c", "ALTER USER bob PASSWORD 'Hun''ter2pw;x'"], ["psql", "-c", "ALTER USER bob PASSWORD '\(R)'"],
                       secrets: ["ter2pw"])
    }

    func testSQLThatSetsAPasswordInShellCommandsAndHeredocs() {
        assertRedacted(["/bin/zsh", "-c", "docker exec db psql -U postgres -c \"ALTER USER bob PASSWORD 'Hunter2pw'\""],
                       ["/bin/zsh", "-c", "docker exec db psql -U postgres -c \"ALTER USER bob PASSWORD '\(R)'\""])
        assertRedacted(["/bin/sh", "-c", "mysql -e \"SET PASSWORD = \\\"Hunter2pw\\\"\""],
                       ["/bin/sh", "-c", "mysql -e \"SET PASSWORD = \\\"\(R)\\\"\""])
        assertRedacted(["/bin/sh", "-c", "mysql -e 'SET PASSWORD = \"Hunter2pw\"'"], ["/bin/sh", "-c", "mysql -e 'SET PASSWORD = \"\(R)\"'"])
        assertRedacted(["/bin/zsh", "-c", "psql -U postgres <<'SQL'\nALTER USER bob\n  WITH PASSWORD 'Hunter2pw';\nSELECT 1;\nSQL"],
                       ["/bin/zsh", "-c", "psql -U postgres <<'SQL'\nALTER USER bob\n  WITH PASSWORD '\(R)';\nSELECT 1;\nSQL"])
        // Oracle: an unquoted password inside such a statement, and a connect string.
        assertRedacted(["/bin/bash", "-c", "sqlplus -s /nolog <<EOF\nCONNECT system/Hunter2pw@db\nALTER USER bob IDENTIFIED BY Hunter2pw;\nEOF"],
                       ["/bin/bash", "-c", "sqlplus -s /nolog <<EOF\nCONNECT system/\(R)@db\nALTER USER bob IDENTIFIED BY \(R);\nEOF"])
    }

    func testSQLThatOnlyMentionsPasswordsIsKept() {
        assertKept([
            ["psql", "-c", "SELECT usename, passwd IS NOT NULL FROM pg_shadow"],
            ["psql", "-c", "SELECT password FROM users WHERE id = 1"],
            ["psql", "-c", "CREATE TABLE users (id int, password text)"],
            ["/bin/sh", "-c", "grep -rn \"IDENTIFIED BY\" ."],
            ["psql", "-c", "GRANT CONNECT ON DATABASE app TO bob"],
            ["psql", "-c", "SELECT id FROM t CONNECT BY PRIOR id = parent_id"],
            ["mysql", "-e", "ALTER USER 'bob'@'%' PASSWORD EXPIRE INTERVAL 90 DAY"],
            ["mysql", "-e", "CREATE USER 'bob'@'localhost' IDENTIFIED WITH auth_socket"],
            ["mysql", "-e", "ALTER USER bob IDENTIFIED BY RANDOM PASSWORD"],
            ["psql", "-c", "ALTER ROLE bob PASSWORD NULL"],
            ["psql", "-c", "\\password bob"],
            ["git", "commit", "-m", "Set password for the admin user"],
            ["git", "commit", "-m", "create user, then set password"],
            ["/bin/sh", "-c", "echo 'identified by its pid' && ls"],
        ])
    }
    // MARK: - Passwords as positional arguments

    func testHtpasswdBatchModePassword() {
        assertRedacted(["htpasswd", "-b", "~/WhoReadTestVault/htpasswd", "bob", "Hunter2pw"],
                       ["htpasswd", "-b", "~/WhoReadTestVault/htpasswd", "bob", R])
        assertRedacted(["htpasswd", "-cbB", "~/WhoReadTestVault/htpasswd", "bob", "Hunter2pw"],
                       ["htpasswd", "-cbB", "~/WhoReadTestVault/htpasswd", "bob", R])
        assertRedacted(["htpasswd", "-nb", "bob", "Hunter2pw"], ["htpasswd", "-nb", "bob", R])
        assertRedacted(["htpasswd", "-b", "-C", "12", "-B", "f", "bob", "Hunter2pw"], ["htpasswd", "-b", "-C", "12", "-B", "f", "bob", R])
        assertRedacted(["/bin/sh", "-c", "htpasswd -nbB bob Hunter2pw > ~/WhoReadTestVault/htpasswd && echo ok"],
                       ["/bin/sh", "-c", "htpasswd -nbB bob \(R) > ~/WhoReadTestVault/htpasswd && echo ok"])
        // No password argument: delete, verify or create with a prompt.
        assertKept([["htpasswd", "-bD", "f", "bob"], ["htpasswd", "-c", "f", "bob"], ["htpasswd", "-v", "f", "bob"], ["htpasswd", "-n", "bob"]])
    }

    func testPositionalPasswordsOfOtherTools() {
        // mysqladmin's `password NEW`.
        assertRedacted(["mysqladmin", "-u", "root", "-pOld2pwxx", "password", "Hunter2pw"],
                       ["mysqladmin", "-u", "root", "-p\(R)", "password", R], secrets: [secret, "Old2pwxx"])
        // macOS directory service: -passwd PATH [OLD] NEW, -authonly USER PASSWORD, -P PASSWORD, and a
        // password attribute.
        assertRedacted(["dscl", ".", "-passwd", "/Users/bob", "Hunter2pw"], ["dscl", ".", "-passwd", "/Users/bob", R])
        assertRedacted(["dscl", ".", "-passwd", "/Users/bob", "Old2pwxx", "Hunter2pw"], ["dscl", ".", "-passwd", "/Users/bob", R, R],
                       secrets: [secret, "Old2pwxx"])
        assertRedacted(["dscl", "/Local/Default", "-authonly", "bob", "Hunter2pw"], ["dscl", "/Local/Default", "-authonly", "bob", R])
        assertRedacted(["dscl", "-u", "admin", "-P", "Hunter2pw", ".", "-create", "/Users/bob"], ["dscl", "-u", "admin", "-P", R, ".", "-create", "/Users/bob"])
        assertRedacted(["dscl", ".", "-create", "/Users/bob", "Password", "Hunter2pw"], ["dscl", ".", "-create", "/Users/bob", "Password", R])
        // Wi-Fi and authenticated proxy passwords.
        assertRedacted(["networksetup", "-setairportnetwork", "en0", "Home WiFi", "Hunter2pw"],
                       ["networksetup", "-setairportnetwork", "en0", "Home WiFi", R])
        assertRedacted(["networksetup", "-addpreferredwirelessnetworkatindex", "en0", "Home", "0", "WPA2", "Hunter2pw"],
                       ["networksetup", "-addpreferredwirelessnetworkatindex", "en0", "Home", "0", "WPA2", R])
        assertRedacted(["networksetup", "-setsecurewebproxy", "Wi-Fi", "proxy.example.com", "8080", "on", "bob", "Hunter2pw"],
                       ["networksetup", "-setsecurewebproxy", "Wi-Fi", "proxy.example.com", "8080", "on", "bob", R])
        // openssl passwd hashes the password given as an argument.
        assertRedacted(["openssl", "passwd", "-6", "Hunter2pw"], ["openssl", "passwd", "-6", R])
        assertRedacted(["openssl", "passwd", "-1", "-salt", "abc", "Hunter2pw"], ["openssl", "passwd", "-1", "-salt", "abc", R])
        // Redis commands.
        assertRedacted(["redis-cli", "AUTH", "Hunter2pw"], ["redis-cli", "AUTH", R])
        assertRedacted(["redis-cli", "-h", "cache", "-p", "6380", "auth", "bob", "Hunter2pw"], ["redis-cli", "-h", "cache", "-p", "6380", "auth", "bob", R])
        assertRedacted(["redis-cli", "CONFIG", "SET", "requirepass", "Hunter2pw"], ["redis-cli", "CONFIG", "SET", "requirepass", R])
        assertRedacted(["redis-cli", "config", "set", "masterauth", "Hunter2pw"], ["redis-cli", "config", "set", "masterauth", R])
        assertRedacted(["redis-cli", "ACL", "SETUSER", "bob", "on", ">Hunter2pw", "~*", "+@all"],
                       ["redis-cli", "ACL", "SETUSER", "bob", "on", ">\(R)", "~*", "+@all"])
        assertRedacted(["redis-cli", "HELLO", "3", "AUTH", "bob", "Hunter2pw"], ["redis-cli", "HELLO", "3", "AUTH", "bob", R])
        // Oracle logons: user/password@db.
        assertRedacted(["sqlplus", "-s", "scott/Hunter2pw@orcl"], ["sqlplus", "-s", "scott/\(R)@orcl"])
        assertRedacted(["sqlplus", "system/Hunter2pw@//db.example.com:1521/ORCLPDB1", "@run.sql"],
                       ["sqlplus", "system/\(R)@//db.example.com:1521/ORCLPDB1", "@run.sql"])
        assertRedacted(["expdp", "userid=system/Hunter2pw@db", "directory=d"], ["expdp", "userid=system/\(R)@db", "directory=d"])
        assertRedacted(["rman", "target", "sys/Hunter2pw@db", "catalog", "rcat/Hunter2pw@rcat"],
                       ["rman", "target", "sys/\(R)@db", "catalog", "rcat/\(R)@rcat"])
        assertRedacted(["sqlldr", "scott/Hunter2pw", "control=x.ctl"], ["sqlldr", "scott/\(R)", "control=x.ctl"])
        assertKept([
            ["mysqladmin", "-u", "root", "-p", "status"], ["mysqladmin", "-u", "root", "-p", "password"],
            ["dscl", ".", "-read", "/Users/bob"], ["dscl", ".", "-list", "/Users"], ["dscl", ".", "-create", "/Users/bob", "UserShell", "/bin/zsh"],
            ["networksetup", "-setairportnetwork", "en0", "OpenNet"], ["networksetup", "-getairportnetwork", "en0"],
            ["networksetup", "-setairportpower", "en0", "on"], ["networksetup", "-setwebproxy", "Wi-Fi", "proxy", "8080"],
            ["openssl", "passwd", "-6", "-stdin"], ["openssl", "rand", "-hex", "16"],
            ["redis-cli", "GET", "auth"], ["redis-cli", "CONFIG", "GET", "requirepass"], ["redis-cli", "-h", "cache", "PING"],
            ["sqlplus", "/nolog"], ["sqlplus", "-s", "/", "as", "sysdba"], ["sqlplus", "scott@orcl"], ["sqlplus", "-s", "/@wallet_alias", "@x.sql"],
            ["rman", "target", "/"],
        ])
    }

    func testProgramSpecificPasswordFlags() {
        // security: the import/export passphrase, the partition-list and keychain passwords.
        assertRedacted(["security", "import", "cert.p12", "-k", "build.keychain", "-P", "Hunter2pw", "-T", "/usr/bin/codesign"],
                       ["security", "import", "cert.p12", "-k", "build.keychain", "-P", R, "-T", "/usr/bin/codesign"])
        assertRedacted(["security", "set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", "Hunter2pw", "build.keychain"],
                       ["security", "set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", R, "build.keychain"])
        assertRedacted(["security", "set-keychain-password", "-o", "Old2pwxx", "-p", "Hunter2pw", "build.keychain"],
                       ["security", "set-keychain-password", "-o", R, "-p", R, "build.keychain"], secrets: [secret, "Old2pwxx"])
        // SQL Server tools.
        assertRedacted(["sqlcmd", "-S", "db", "-U", "sa", "-P", "Hunter2pw", "-Q", "SELECT 1"], ["sqlcmd", "-S", "db", "-U", "sa", "-P", R, "-Q", "SELECT 1"])
        assertRedacted(["bcp", "t", "out", "f", "-S", "db", "-U", "sa", "-P", "Hunter2pw"], ["bcp", "t", "out", "f", "-S", "db", "-U", "sa", "-P", R])
        // HTTPie and xh: -a/--auth USER:PASS, or a bearer token.
        assertRedacted(["http", "-a", "bob:Hunter2pw", "https://x"], ["http", "-a", "bob:\(R)", "https://x"])
        assertRedacted(["xh", "--auth=bob:Hunter2pw", "https://x"], ["xh", "--auth=bob:\(R)", "https://x"])
        assertRedacted(["http", "--auth-type=bearer", "--auth", "Hunter2pwToken", "https://x"], ["http", "--auth-type=bearer", "--auth", R, "https://x"],
                       secrets: ["Hunter2pwToken"])
        // AppleScript run with administrator rights.
        assertRedacted(["osascript", "-e", "do shell script \"ls /var/root\" password \"Hunter2pw\" with administrator privileges"],
                       ["osascript", "-e", "do shell script \"ls /var/root\" password \"\(R)\" with administrator privileges"])
        assertRedacted(["/bin/zsh", "-c", "osascript -e 'do shell script \"id\" user name \"bob\" password \"Hunter2pw\" with administrator privileges'"],
                       ["/bin/zsh", "-c", "osascript -e 'do shell script \"id\" user name \"bob\" password \"\(R)\" with administrator privileges'"])
        assertRedacted(["/bin/sh", "-c", "osascript -e \"do shell script \\\"id\\\" password \\\"Hunter2pw\\\" with administrator privileges\""],
                       ["/bin/sh", "-c", "osascript -e \"do shell script \\\"id\\\" password \\\"\(R)\\\" with administrator privileges\""])
        assertKept([
            ["security", "create-keychain", "-P", "build.keychain"], ["security", "export", "-k", "build.keychain", "-t", "certs", "-o", "/tmp/certs.pem"],
            ["security", "find-generic-password", "-s", "svc", "-w"], ["curl", "-a", "-T", "f", "ftp://h/x"], ["http", "-a", "bob", "https://x"],
            ["osascript", "-e", "display dialog \"Enter your password\" default answer \"\" with hidden answer"],
        ])
    }

    // MARK: - key:value tokens, unquoted keys, quotes inside values

    func testSecretKeyColonValueInOneWord() {
        assertRedacted(["tool", "password:Hunter2pw"], ["tool", "password:\(R)"])
        assertRedacted(["tool", "--db", "passwd:Hunter2pw"], ["tool", "--db", "passwd:\(R)"])
        assertRedacted(["/bin/sh", "-c", "tool pwd:Hunter2pw api_key:Hunter2pw DB_PASSWORD:Hunter2pw"],
                       ["/bin/sh", "-c", "tool pwd:\(R) api_key:\(R) DB_PASSWORD:\(R)"])
        // `passwd=PW` was already redacted (key=value); kept here as coverage.
        assertRedacted(["tool", "passwd=Hunter2pw"], ["tool", "passwd=\(R)"])
        assertKept([
            ["tmux", "attach", "-t", "session:1"], ["tmux", "send-keys", "-t", "work:editor", "ls", "Enter"],
            ["git", "log", "--format=%an:%ae"], ["docker", "run", "-v", "/data:/data", "img"], ["ssh", "-L", "8080:localhost:80", "h"],
            ["gh", "auth", "refresh", "-s", "read:packages"], ["tool", "password:"], ["tool", "password:true"],
            ["tool", "secret_name:prod"], ["tool", "password_file:/Users/alice/WhoReadTestVault/pw"], ["tool", "pwd:/Users/alice/x"],
            ["kubectl", "get", "secret", "app:v1"], ["git", "show", "HEAD:password.txt"],
        ])
    }

    func testUnquotedKeysWithQuotedValues() {
        // JavaScript objects (mongosh --eval, node -e) and YAML.
        assertRedacted(["mongosh", "--eval", "db.createUser({user: 'bob', pwd: 'Hunter2pw', roles: []})"],
                       ["mongosh", "--eval", "db.createUser({user: 'bob', pwd: '\(R)', roles: []})"])
        assertRedacted(["mongosh", "--eval", "db.createUser({user:\"bob\",pwd:\"Hunter2pw\"})"],
                       ["mongosh", "--eval", "db.createUser({user:\"bob\",pwd:\"\(R)\"})"])
        assertRedacted(["node", "-e", "connect({host: 'db', password: \"Hunter2pw\", apiKey: 'Hunter2pw'})"],
                       ["node", "-e", "connect({host: 'db', password: \"\(R)\", apiKey: '\(R)'})"])
        assertRedacted(["/bin/bash", "-c", "node -e \"connect({password: 'Hunter2pw'})\""],
                       ["/bin/bash", "-c", "node -e \"connect({password: '\(R)'})\""])
        assertRedacted(["/bin/bash", "-c", "python3 - <<EOF\nconfig:\n  secret: \"Hunter2pw\"\nEOF"],
                       ["/bin/bash", "-c", "python3 - <<EOF\nconfig:\n  secret: \"\(R)\"\nEOF"])
        assertKept([
            ["node", "-e", "console.log({user: 'bob', author: 'alice', mode: 'x'})"],
            ["node", "-e", "f({tokenFile: '/Users/alice/x', secretName: 'prod'})"],
        ])
    }

    func testQuotesInsideJSONAndPythonValues() {
        assertRedacted(["curl", "-d", "{\"password\":\"Hun\\\"ter2pw\",\"user\":\"bob\"}", "https://x"],
                       ["curl", "-d", "{\"password\":\"\(R)\",\"user\":\"bob\"}", "https://x"], secrets: ["ter2pw"])
        assertRedacted(["curl", "-d", "{\"password\":\"Hun'ter2pw\"}", "https://x"], ["curl", "-d", "{\"password\":\"\(R)\"}", "https://x"],
                       secrets: ["ter2pw"])
        assertRedacted(["python3", "-c", "connect(**{'password': 'Hun\\'ter2pw', 'user': 'bob'})"],
                       ["python3", "-c", "connect(**{'password': '\(R)', 'user': 'bob'})"], secrets: ["ter2pw"])
        // Shell-escaped JSON: \" around the value, \\\" for a quote inside it.
        assertRedacted(["/bin/sh", "-c", "curl -d \"{\\\"password\\\":\\\"Hun\\\\\\\"ter2pw\\\",\\\"user\\\":\\\"bob\\\"}\" https://x"],
                       ["/bin/sh", "-c", "curl -d \"{\\\"password\\\":\\\"\(R)\\\",\\\"user\\\":\\\"bob\\\"}\" https://x"], secrets: ["ter2pw"])
        // A backslash at the end of the value: the quote after it closes it.
        assertRedacted(["tool", "{\"password\":\"Hunter2pw\\\\\",\"user\":\"bob\"}"], ["tool", "{\"password\":\"\(R)\",\"user\":\"bob\"}"])
    }

    // MARK: - URL userinfo

    func testURLPasswordsContainingSlashOrAt() {
        assertRedacted(["git", "clone", "https://bob:Hun/ter2pw@host/o/r.git"], ["git", "clone", "https://bob:\(R)@host/o/r.git"],
                       secrets: ["ter2pw", "Hun/"])
        assertRedacted(["git", "clone", "https://bob:Hun@ter2pw@host/o/r.git"], ["git", "clone", "https://bob:\(R)@host/o/r.git"],
                       secrets: ["ter2pw"])
        assertRedacted(["psql", "postgresql://app:Hun/ter@2pw@db.example.com:5432/prod"],
                       ["psql", "postgresql://app:\(R)@db.example.com:5432/prod"], secrets: ["ter", "2pw"])
        assertRedacted(["/bin/sh", "-c", "git clone 'https://bob:Hun@ter2pw@host/x' && ls"],
                       ["/bin/sh", "-c", "git clone 'https://bob:\(R)@host/x' && ls"], secrets: ["ter2pw"])
        assertRedacted(["redis-cli", "-u", "redis://:Hun@ter2pw@cache:6379/0"], ["redis-cli", "-u", "redis://:\(R)@cache:6379/0"],
                       secrets: ["ter2pw"])
        // A user name that is an e-mail address.
        assertRedacted(["curl", "ftp://bob@example.com:Hunter2pw@ftp.example.com/f"], ["curl", "ftp://bob@example.com:\(R)@ftp.example.com/f"])
        // No scheme (`mount -t smbfs //user:pw@host/share`).
        assertRedacted(["mount", "-t", "smbfs", "//bob:Hun/ter2pw@nas/share", "/mnt/share"],
                       ["mount", "-t", "smbfs", "//bob:\(R)@nas/share", "/mnt/share"], secrets: ["ter2pw"])
        assertKept([
            ["git", "clone", "ssh://git@github.com/o/r.git"], ["git", "clone", "git@github.com:o/r.git"],
            ["npm", "view", "http://localhost:4873/@scope/pkg"], ["curl", "https://user@host:8443/x@y"],
            ["curl", "https://medium.com/@user/post"], ["curl", "http://[::1]:8080/@x"], ["ls", "//server/share"],
            ["curl", "https://host/path?next=a:b@c"], ["curl", "http://localhost:3000/users/@me"],
            ["open", "https://example.com/search?q=a&page=2"], ["echo", "see // comment@here"],
        ])
    }
}
