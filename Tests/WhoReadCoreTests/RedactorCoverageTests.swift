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

    /// Statements that connect with a password: an Oracle database link (`CONNECT TO user IDENTIFIED
    /// BY pw`, the password unquoted) and Db2's `CONNECT TO db USER u USING pw [NEW pw CONFIRM pw]`,
    /// also as the separate words of a `db2` command.
    func testSQLThatConnectsWithAPassword() {
        assertRedacted(["sqlplus", "-s", "/nolog", "CREATE DATABASE LINK l CONNECT TO bob IDENTIFIED BY Hunter2pw USING 'db'"],
                       ["sqlplus", "-s", "/nolog", "CREATE DATABASE LINK l CONNECT TO bob IDENTIFIED BY \(R) USING 'db'"])
        assertRedacted(["/bin/zsh", "-c", "sqlplus -s /nolog <<EOF\nCREATE PUBLIC DATABASE LINK l CONNECT TO bob IDENTIFIED BY \"Hunter2pw\" USING 'db';\nEOF"],
                       ["/bin/zsh", "-c", "sqlplus -s /nolog <<EOF\nCREATE PUBLIC DATABASE LINK l CONNECT TO bob IDENTIFIED BY \"\(R)\" USING 'db';\nEOF"])
        assertRedacted(["/bin/sh", "-c", "db2 \"connect to sample user bob using 'Hunter2pw'\" && db2 \"select 1 from sysibm.sysdummy1\""],
                       ["/bin/sh", "-c", "db2 \"connect to sample user bob using '\(R)'\" && db2 \"select 1 from sysibm.sysdummy1\""])
        assertRedacted(["db2", "connect", "to", "sample", "user", "bob", "using", "Hunter2pw"],
                       ["db2", "connect", "to", "sample", "user", "bob", "using", R])
        assertRedacted(["db2", "CONNECT", "TO", "sample", "USER", "bob", "USING", "Old2pwxx", "NEW", "Hunter2pw", "CONFIRM", "Hunter2pw"],
                       ["db2", "CONNECT", "TO", "sample", "USER", "bob", "USING", R, "NEW", R, "CONFIRM", R], secrets: [secret, "Old2pwxx"])
        assertKept([
            ["db2", "connect", "to", "sample"], ["db2", "connect to sample"], ["db2", "list", "database", "directory"],
            ["psql", "-c", "SELECT * FROM t JOIN u USING (id)"], ["psql", "-c", "\\connect app"],
        ])
        // A logon after CONNECT is SQL*Plus, RMAN or DGMGRL syntax, read where one of them runs.
        assertRedacted(["/bin/sh", "-c", "rman <<EOF\nconnect target sys/Hunter2pw@db\nconnect catalog rcat/Hunter2pw@rcat\nEOF"],
                       ["/bin/sh", "-c", "rman <<EOF\nconnect target sys/\(R)@db\nconnect catalog rcat/\(R)@rcat\nEOF"])
        assertRedacted(["/bin/sh", "-c", "sqlplus /nolog <<EOF\nconn system/Hunter2pw\nEOF"], ["/bin/sh", "-c", "sqlplus /nolog <<EOF\nconn system/\(R)\nEOF"])
        assertKept([
            ["/bin/zsh", "-c", "grep -rn connect src/net && rg connect Sources/WhoReadIPC"],
            ["git", "commit", "-m", "connect src/main.swift to the db"], ["python3", "-c", "import db; db.connect('a/b')"],
            ["/bin/zsh", "-c", "grep -rn connect src/permanent"],
        ])
    }

    /// MySQL's `PASSWORD('x')` and pgcrypto's `crypt('x', …)` take the password in any statement: the
    /// root password reset that sets `authentication_string = PASSWORD('x')` was kept.
    func testSQLFunctionsThatTakeAPassword() {
        assertRedacted(["mysql", "-e", "UPDATE mysql.user SET authentication_string=PASSWORD('Hunter2pw') WHERE User='root'"],
                       ["mysql", "-e", "UPDATE mysql.user SET authentication_string=PASSWORD('\(R)') WHERE User='root'"])
        assertRedacted(["/bin/sh", "-c", "mysql -uroot <<EOF\nUPDATE mysql.user SET authentication_string=PASSWORD('Hunter2pw') WHERE User='root';\nFLUSH PRIVILEGES;\nEOF"],
                       ["/bin/sh", "-c", "mysql -uroot <<EOF\nUPDATE mysql.user SET authentication_string=PASSWORD('\(R)') WHERE User='root';\nFLUSH PRIVILEGES;\nEOF"])
        assertRedacted(["mysql", "-e", "SELECT OLD_PASSWORD(\"Hunter2pw\")"], ["mysql", "-e", "SELECT OLD_PASSWORD(\"\(R)\")"])
        assertRedacted(["psql", "-c", "INSERT INTO users (name, pw) VALUES ('bob', crypt('Hunter2pw', gen_salt('bf')))"],
                       ["psql", "-c", "INSERT INTO users (name, pw) VALUES ('bob', crypt('\(R)', gen_salt('bf')))"])
        assertRedacted(["/bin/sh", "-c", "psql -c \"UPDATE users SET pw = crypt('Hunter2pw', gen_salt('bf')) WHERE id = 1\""],
                       ["/bin/sh", "-c", "psql -c \"UPDATE users SET pw = crypt('\(R)', gen_salt('bf')) WHERE id = 1\""])
        assertRedacted(["python3", "-c", "import crypt; print(crypt.crypt('Hunter2pw', crypt.mksalt()))"],
                       ["python3", "-c", "import crypt; print(crypt.crypt('\(R)', crypt.mksalt()))"])
        assertKept([
            ["psql", "-c", "SELECT crypt(pw, gen_salt('bf')) FROM users"], ["psql", "-c", "CREATE EXTENSION pgcrypto"],
            ["mysql", "-e", "SELECT user, authentication_string FROM mysql.user"], ["gpg", "--encrypt", "-r", "bob", "file.txt"],
        ])
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

    /// The password is the word after the user, not the last word: a stray word after it (htpasswd
    /// refuses the command, but it ran and its argv is stored) used to be redacted instead.
    /// htdbm and mosquitto_passwd take the same arguments.
    func testBatchModePasswordIsFoundByPosition() {
        assertRedacted(["htpasswd", "-b", "f", "bob", "Hunter2pw", "extra"], ["htpasswd", "-b", "f", "bob", R, R])
        assertRedacted(["htpasswd", "-nb", "bob", "Hunter2pw", "extra"], ["htpasswd", "-nb", "bob", R, R])
        assertRedacted(["htpasswd", "-bv", "f", "bob", "Hunter2pw"], ["htpasswd", "-bv", "f", "bob", R])
        assertRedacted(["htdbm", "-bt", "-T", "SDBM", "users.db", "bob", "Hunter2pw", "a comment"],
                       ["htdbm", "-bt", "-T", "SDBM", "users.db", "bob", R, R])
        assertRedacted(["mosquitto_passwd", "-b", "/opt/homebrew/etc/mosquitto/passwd", "bob", "Hunter2pw"],
                       ["mosquitto_passwd", "-b", "/opt/homebrew/etc/mosquitto/passwd", "bob", R])
        assertRedacted(["mosquitto_passwd", "-c", "-H", "sha512", "-b", "passwd", "bob", "Hunter2pw"],
                       ["mosquitto_passwd", "-c", "-H", "sha512", "-b", "passwd", "bob", R])
        assertRedacted(["/bin/sh", "-c", "docker exec mqtt mosquitto_passwd -b /mosquitto/config/passwd bob Hunter2pw"],
                       ["/bin/sh", "-c", "docker exec mqtt mosquitto_passwd -b /mosquitto/config/passwd bob \(R)"])
        assertKept([
            ["htdbm", "-l", "users.db"], ["htdbm", "-bx", "users.db", "bob"], ["mosquitto_passwd", "-U", "passwd"],
            ["mosquitto_passwd", "-D", "passwd", "bob"], ["mosquitto_passwd", "-c", "passwd", "bob"],
            ["mosquitto_sub", "-h", "localhost", "-t", "home/#"],
        ])
    }

    /// `rabbitmqctl add_user USER PW`: the password is the word after the user. `change_password`
    /// used to read as a setting's name, so the user was redacted and the password kept.
    func testRabbitMQUserPasswords() {
        assertRedacted(["rabbitmqctl", "add_user", "bob", "Hunter2pw"], ["rabbitmqctl", "add_user", "bob", R])
        assertRedacted(["rabbitmqctl", "change_password", "bob", "Hunter2pw"], ["rabbitmqctl", "change_password", "bob", R])
        assertRedacted(["rabbitmqctl", "-n", "rabbit@host", "authenticate_user", "bob", "Hunter2pw"],
                       ["rabbitmqctl", "-n", "rabbit@host", "authenticate_user", "bob", R])
        assertRedacted(["/bin/sh", "-c", "docker exec rabbit rabbitmqctl add_user bob Hunter2pw && rabbitmqctl set_user_tags bob administrator"],
                       ["/bin/sh", "-c", "docker exec rabbit rabbitmqctl add_user bob \(R) && rabbitmqctl set_user_tags bob administrator"])
        assertRedacted(["rabbitmqctl", "--erlang-cookie", "Hunter2pw", "status"], ["rabbitmqctl", "--erlang-cookie", R, "status"])
        // Options after the command and `--` are not the user: the password is the argument after it.
        assertRedacted(["rabbitmqctl", "add_user", "--", "bob", "Hunter2pw"], ["rabbitmqctl", "add_user", "--", "bob", R])
        assertRedacted(["rabbitmqctl", "add_user", "--pre-hashed-password", "bob", "Hunter2pwHash"],
                       ["rabbitmqctl", "add_user", "--pre-hashed-password", "bob", R], secrets: ["Hunter2pwHash"])
        assertRedacted(["rabbitmqctl", "change_password", "-n", "rabbit@host", "bob", "Hunter2pw"],
                       ["rabbitmqctl", "change_password", "-n", "rabbit@host", "bob", R])
        assertKept([
            ["rabbitmqctl", "change_password", "bob"], ["rabbitmqctl", "add_user", "bob"], ["rabbitmqctl", "list_users"],
            ["rabbitmqctl", "set_user_tags", "bob", "administrator"], ["rabbitmqctl", "delete_user", "bob"],
            ["rabbitmqctl", "add_user", "--", "bob"], ["rabbitmqctl", "add_vhost", "--description", "test", "vh"],
        ])
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

    /// A command run in a container, a pod or over ssh has the rules of its own program: the htpasswd
    /// line Docker's registry guide gives, `docker exec db mysql -pPW`, `kubectl exec … -- …`.
    func testCommandsRunInAContainerOrOverSSHKeepTheirRules() {
        assertRedacted(["docker", "run", "--rm", "--entrypoint", "htpasswd", "httpd:2", "-Bbn", "testuser", "Hunter2pw"],
                       ["docker", "run", "--rm", "--entrypoint", "htpasswd", "httpd:2", "-Bbn", "testuser", R])
        assertRedacted(["/bin/sh", "-c", "docker run --entrypoint=htpasswd httpd:2 -Bbn testuser Hunter2pw > auth/htpasswd"],
                       ["/bin/sh", "-c", "docker run --entrypoint=htpasswd httpd:2 -Bbn testuser \(R) > auth/htpasswd"])
        assertRedacted(["docker", "run", "--rm", "-it", "-v", "/srv/auth:/auth", "httpd:2", "htpasswd", "-Bbn", "bob", "Hunter2pw"],
                       ["docker", "run", "--rm", "-it", "-v", "/srv/auth:/auth", "httpd:2", "htpasswd", "-Bbn", "bob", R])
        assertRedacted(["docker", "exec", "-it", "-e", "TERM=xterm", "db", "mysql", "-uroot", "-pHunter2pw"],
                       ["docker", "exec", "-it", "-e", "TERM=xterm", "db", "mysql", "-uroot", "-p\(R)"])
        assertRedacted(["podman", "container", "exec", "cache", "redis-cli", "AUTH", "Hunter2pw"],
                       ["podman", "container", "exec", "cache", "redis-cli", "AUTH", R])
        assertRedacted(["/bin/sh", "-c", "docker compose -f dev.yml exec -T db mysqladmin -uroot password Hunter2pw"],
                       ["/bin/sh", "-c", "docker compose -f dev.yml exec -T db mysqladmin -uroot password \(R)"])
        assertRedacted(["docker-compose", "run", "--rm", "web", "htpasswd", "-nb", "bob", "Hunter2pw"],
                       ["docker-compose", "run", "--rm", "web", "htpasswd", "-nb", "bob", R])
        assertRedacted(["kubectl", "exec", "-n", "prod", "-it", "mysql-0", "--", "mysql", "-pHunter2pw"],
                       ["kubectl", "exec", "-n", "prod", "-it", "mysql-0", "--", "mysql", "-p\(R)"])
        assertRedacted(["ssh", "-p", "2222", "-i", "/Users/alice/keys/id", "web", "htpasswd", "-b", "/etc/nginx/htpasswd", "bob", "Hunter2pw"],
                       ["ssh", "-p", "2222", "-i", "/Users/alice/keys/id", "web", "htpasswd", "-b", "/etc/nginx/htpasswd", "bob", R])
        assertRedacted(["/bin/sh", "-c", "ssh -tt db sudo mysql -pHunter2pw"], ["/bin/sh", "-c", "ssh -tt db sudo mysql -p\(R)"])
        assertKept([
            ["docker", "run", "--rm", "-p", "8080:80", "nginx"], ["docker", "exec", "db", "mysql", "-uroot", "-p", "dbname"],
            ["docker", "run", "-e", "MODE=prod", "img", "echo", "hello"], ["docker", "exec", "-it", "web", "bash"],
            ["docker", "compose", "up", "-d"], ["kubectl", "exec", "pod", "--", "ls", "-la"], ["kubectl", "get", "pods"],
            ["ssh", "host", "ls", "-la"], ["ssh", "-o", "StrictHostKeyChecking=no", "-p", "2222", "bob@host", "uptime"],
            ["/bin/sh", "-c", "docker run --rm -v \"$PWD\":/app -w /app node:20 npm test"],
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
        // ldappasswd: the bind password, the old (-a) and the new (-s) password. Elsewhere -s is a scope.
        assertRedacted(["ldappasswd", "-x", "-D", "cn=admin", "-w", "Hunter2pw", "-a", "Old2pwxx", "-s", "Hunter2pw", "uid=bob"],
                       ["ldappasswd", "-x", "-D", "cn=admin", "-w", R, "-a", R, "-s", R, "uid=bob"], secrets: [secret, "Old2pwxx"])
        // getopt takes them attached too.
        assertRedacted(["ldappasswd", "-x", "-D", "cn=admin", "-wHunter2pw", "-aOld2pwxx", "-sHunter2pw", "uid=bob"],
                       ["ldappasswd", "-x", "-D", "cn=admin", "-w\(R)", "-a\(R)", "-s\(R)", "uid=bob"], secrets: [secret, "Old2pwxx"])
        assertRedacted(["ldapsearch", "-x", "-D", "cn=admin", "-wHunter2pw", "-b", "dc=example,dc=com"],
                       ["ldapsearch", "-x", "-D", "cn=admin", "-w\(R)", "-b", "dc=example,dc=com"])
        // Samba's USER%PW, lftp's USER,PW, and the password hash useradd and usermod set.
        assertRedacted(["smbclient", "//nas/share", "-U", "bob%Hunter2pw"], ["smbclient", "//nas/share", "-U", "bob%\(R)"])
        assertRedacted(["/bin/sh", "-c", "smbclient -L nas -Ubob%Hunter2pw && rpcclient -U 'DOM\\bob%Hunter2pw' nas"],
                       ["/bin/sh", "-c", "smbclient -L nas -Ubob%\(R) && rpcclient -U 'DOM\\bob%\(R)' nas"])
        assertRedacted(["smbclient", "//nas/share", "--user=bob%Hunter2pw"], ["smbclient", "//nas/share", "--user=bob%\(R)"])
        assertRedacted(["lftp", "-u", "bob,Hunter2pw", "sftp://files.example.com"], ["lftp", "-u", "bob,\(R)", "sftp://files.example.com"])
        assertRedacted(["/bin/sh", "-c", "docker exec web usermod -p '$6$salt$Hunter2pwHash' bob"],
                       ["/bin/sh", "-c", "docker exec web usermod -p '\(R)' bob"], secrets: ["Hunter2pwHash"])
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
            ["ldapsearch", "-x", "-s", "base", "-b", "dc=example,dc=com"], ["ldappasswd", "-x", "-D", "cn=admin", "-W", "-S", "uid=bob"],
            ["ldapsearch", "-x", "-ssub", "-b", "dc=example,dc=com"], ["ldapsearch", "-x", "-W", "-D", "cn=admin"],
            ["smbclient", "-L", "nas", "-U", "bob"], ["smbclient", "-L", "nas", "-N"], ["lftp", "-u", "bob", "sftp://files.example.com"],
            ["usermod", "-aG", "staff", "bob"],
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
        // A list of pairs: from the secret on, the rest goes (a password may hold a comma).
        assertRedacted(["tool", "user:bob,password:Hunter2pw"], ["tool", "user:bob,password:\(R)"])
        assertRedacted(["tool", "-o", "a:1,password:Hun,ter2pw,b:2"], ["tool", "-o", "a:1,password:\(R)"], secrets: ["Hun", "ter2pw"])
        assertRedacted(["tool", "user=bob,password:Hunter2pw"], ["tool", "user=bob,password:\(R)"])
        assertRedacted(["/bin/sh", "-c", "tool --opt user:bob,token:Hunter2pw"], ["/bin/sh", "-c", "tool --opt user:bob,token:\(R)"])
        assertKept([
            ["tmux", "attach", "-t", "session:1"], ["tmux", "send-keys", "-t", "work:editor", "ls", "Enter"],
            ["git", "log", "--format=%an:%ae"], ["docker", "run", "-v", "/data:/data", "img"], ["ssh", "-L", "8080:localhost:80", "h"],
            ["gh", "auth", "refresh", "-s", "read:packages"], ["tool", "password:"], ["tool", "password:true"],
            ["tool", "secret_name:prod"], ["tool", "password_file:/Users/alice/WhoReadTestVault/pw"], ["tool", "pwd:/Users/alice/x"],
            ["kubectl", "get", "secret", "app:v1"], ["git", "show", "HEAD:password.txt"],
            ["tool", "--opt", "a:1,b:2"], ["tool", "user:bob,role:admin"], ["docker", "run", "-p", "80:80,443:443", "img"],
            ["mongosh", "mongodb://h1:27017,h2:27017/db"], ["tool", "user:bob,password_file:/Users/alice/x"],
            // A search for the key: nothing follows the colon but a space.
            ["rg", "password: ", "config/"], ["/bin/sh", "-c", "grep -rn 'password: ' ."], ["/bin/sh", "-c", "grep -rn \"api_key:  \" src"],
        ])
    }

    /// PowerShell and .NET options give a value after a colon: `-Password:PW`, `--password:PW`,
    /// `sqlpackage /TargetPassword:PW`. Before, `--password:PW` kept PW and redacted the next word.
    func testPasswordOptionsWithAColon() {
        assertRedacted(["tool", "--password:Hunter2pw", "next"], ["tool", "--password:\(R)", "next"])
        assertRedacted(["pwsh", "-Command", "Connect-Db -Server db -Password:Hunter2pw -User bob"],
                       ["pwsh", "-Command", "Connect-Db -Server db -Password:\(R) -User bob"])
        assertRedacted(["sqlpackage", "/Action:Publish", "/TargetUser:sa", "/TargetPassword:Hunter2pw", "/SourceFile:app.dacpac"],
                       ["sqlpackage", "/Action:Publish", "/TargetUser:sa", "/TargetPassword:\(R)", "/SourceFile:app.dacpac"])
        // An attached value that holds a colon is still the attached flag's (`mysql -pPW`).
        assertRedacted(["mysql", "-uroot", "-pHun:ter2pw"], ["mysql", "-uroot", "-p\(R)"], secrets: ["ter2pw"])
        assertKept([
            ["tool", "--auth-type:bearer", "next"], ["tool", "--secret-name:prod", "next"], ["msbuild", "/t:Build", "/v:m"],
            ["docker", "run", "-v", "/secret:/data", "img"], ["tool", "--password:", "next"],
        ])
    }

    /// A hidden file (`.htpasswd`) or a jq path (`.db.password`) is not the name of a setting whose
    /// value follows: the next word is kept.
    func testHiddenFilesAndJqPathsDoNotNameASetting() {
        assertKept([
            ["ls", "-la", ".htpasswd", "README.md"], ["htpasswd", "-v", ".htpasswd", "bob"], ["jq", ".password", "config.json"],
            ["jq", "-r", ".db.password", "config.json"], ["/bin/zsh", "-c", "cat .pgpass.example | head"],
        ])
        assertRedacted(["aws", "configure", "set", "aws_secret_access_key", "Hunter2pw"],
                       ["aws", "configure", "set", "aws_secret_access_key", R])
        assertRedacted(["npm", "config", "set", "//registry.npmjs.org/:_authToken", "Hunter2pw"],
                       ["npm", "config", "set", "//registry.npmjs.org/:_authToken", R])
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

    /// Calls that take a user name and then a password: mongosh's `db.auth` and
    /// `db.changeUserPassword` (MongoDB's ALTER USER), and Python's basic-auth tuple and `login`.
    func testCredentialCalls() {
        assertRedacted(["mongosh", "--eval", "db.changeUserPassword('bob', 'Hunter2pw')"],
                       ["mongosh", "--eval", "db.changeUserPassword('bob', '\(R)')"])
        assertRedacted(["mongosh", "admin", "--eval=db.auth('bob','Hunter2pw')"], ["mongosh", "admin", "--eval=db.auth('bob','\(R)')"])
        assertRedacted(["/bin/sh", "-c", "mongosh --quiet --eval 'db.getSiblingDB(\"admin\").changeUserPassword(\"bob\", \"Hunter2pw\")'"],
                       ["/bin/sh", "-c", "mongosh --quiet --eval 'db.getSiblingDB(\"admin\").changeUserPassword(\"bob\", \"\(R)\")'"])
        assertRedacted(["/bin/sh", "-c", "mongosh --eval \"db.auth(\\\"bob\\\", \\\"Hunter2pw\\\")\""],
                       ["/bin/sh", "-c", "mongosh --eval \"db.auth(\\\"bob\\\", \\\"\(R)\\\")\""])
        assertRedacted(["python3", "-c", "import requests; print(requests.get('https://x', auth=('bob', 'Hunter2pw')).status_code)"],
                       ["python3", "-c", "import requests; print(requests.get('https://x', auth=('bob', '\(R)')).status_code)"])
        assertRedacted(["python3", "-c", "requests.get(u, auth=HTTPBasicAuth('bob', 'Hunter2pw'))"],
                       ["python3", "-c", "requests.get(u, auth=HTTPBasicAuth('bob', '\(R)'))"])
        assertRedacted(["python3", "-c", "s = smtplib.SMTP_SSL('smtp.example.com'); s.login('bob@example.com', 'Hunter2pw')"],
                       ["python3", "-c", "s = smtplib.SMTP_SSL('smtp.example.com'); s.login('bob@example.com', '\(R)')"])
        assertKept([
            ["mongosh", "--eval", "db.auth(user, pass)"], ["mongosh", "--eval", "db.getUsers()"], ["node", "-e", "auth()"],
            ["python3", "-c", "print(login('a'))"], ["gh", "auth", "login"], ["python3", "-c", "auth(\"a\") + f(\"b\", \"c\")"],
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
        // "@" and then "/" in the password: the "@" in the first path segment ends it.
        assertRedacted(["mongosh", "mongodb+srv://bob:Hun@ter/2pw@cluster0.x.mongodb.net/db?retryWrites=true"],
                       ["mongosh", "mongodb+srv://bob:\(R)@cluster0.x.mongodb.net/db?retryWrites=true"], secrets: ["Hun", "2pw"])
        assertRedacted(["git", "clone", "https://bob:Hun@ter/2pw@host/o/r.git"], ["git", "clone", "https://bob:\(R)@host/o/r.git"],
                       secrets: ["ter", "2pw"])
        // The price of that: a URL with a password and an "@" in its first path segment loses its host.
        assertRedacted(["curl", "https://bob:Hunter2pw@host/me@example.com"], ["curl", "https://bob:\(R)@example.com"])
        // A user name that is an e-mail address.
        assertRedacted(["curl", "ftp://bob@example.com:Hunter2pw@ftp.example.com/f"], ["curl", "ftp://bob@example.com:\(R)@ftp.example.com/f"])
        // No scheme (`mount -t smbfs //user:pw@host/share`).
        assertRedacted(["mount", "-t", "smbfs", "//bob:Hun/ter2pw@nas/share", "/mnt/share"],
                       ["mount", "-t", "smbfs", "//bob:\(R)@nas/share", "/mnt/share"], secrets: ["ter2pw"])
        assertKept([
            ["git", "clone", "ssh://git@github.com/o/r.git"], ["git", "clone", "git@github.com:o/r.git"],
            ["npm", "view", "http://localhost:4873/@scope/pkg"], ["curl", "https://user@host:8443/x@y"],
            ["curl", "https://medium.com/@user/post"], ["curl", "http://[::1]:8080/@x"], ["ls", "//server/share"],
            ["git", "clone", "https://bob@host/@scope/x"], ["curl", "https://host/me@x.com/y"],
            ["curl", "https://host/path?next=a:b@c"], ["curl", "http://localhost:3000/users/@me"],
            ["open", "https://example.com/search?q=a&page=2"], ["echo", "see // comment@here"],
        ])
    }

    // MARK: - Single quotes inside single-quoted words

    /// `'\''` and `'"'"'` put a single quote into a single-quoted word, as commands are quoted for
    /// `sh -c` and `eval` (agents run commands that way); `$'…'` is ANSI-C quoting. The rules read the
    /// word's value: before, a SQL or JavaScript literal opened by such a quote ended at the `\'`.
    func testSingleQuotesInsideSingleQuotedWords() {
        assertRedacted(["/bin/sh", "-c", #"psql -c 'ALTER USER app WITH PASSWORD '\''Hunter2pw'\'''"#],
                       ["/bin/sh", "-c", #"psql -c "ALTER USER app WITH PASSWORD '\#(R)'""#])
        assertRedacted(["/bin/sh", "-c", #"psql -c 'ALTER USER app WITH PASSWORD '"'"'Hunter2pw'"'"''"#],
                       ["/bin/sh", "-c", #"psql -c "ALTER USER app WITH PASSWORD '\#(R)'""#])
        assertRedacted(["/bin/bash", "-c", #"psql -c $'ALTER USER bob PASSWORD \'Hunter2pw\'' && ls"#],
                       ["/bin/bash", "-c", #"psql -c "ALTER USER bob PASSWORD '\#(R)'" && ls"#])
        assertRedacted(["/bin/sh", "-c", #"node -e 'connect({password: '\''Hunter2pw'\''})'"#],
                       ["/bin/sh", "-c", #"node -e "connect({password: '\#(R)'})""#])
        // A command quoted for eval inside the shell's own command line.
        let zsh = "source /Users/alice/snap.sh && eval "
        let tail = #" \< /dev/null && pwd -P >| /tmp/cwd"#
        assertRedacted(["/bin/zsh", "-c", "-l", zsh + #"'psql -c "ALTER USER bob PASSWORD '\''Hunter2pw'\''"'"# + tail],
                       ["/bin/zsh", "-c", "-l", zsh + #""psql -c \"ALTER USER bob PASSWORD '\#(R)'\"""# + tail])
        assertRedacted(["/bin/zsh", "-c", "-l", zsh + #"'echo '\''db:5432:*:bob:Hunter2pw'\'' > ~/WhoReadTestVault/pgpass'"# + tail],
                       ["/bin/zsh", "-c", "-l", zsh + #""echo '\#(R)' > ~/WhoReadTestVault/pgpass""# + tail])
        assertRedacted(["/bin/bash", "-c", #"bash -c 'mysql -e "CREATE USER '\''bob'\''@'\''%'\'' IDENTIFIED BY '\''Hunter2pw'\''"'"#],
                       ["/bin/bash", "-c", #"bash -c "mysql -e \"CREATE USER 'bob'@'%' IDENTIFIED BY '\#(R)'\"""#])
        assertRedacted(["/bin/sh", "-c", #"echo 'machine h login bob password '\''Hunter2pw'\''' >> ~/WhoReadTestVault/netrc"#],
                       ["/bin/sh", "-c", #"echo "\#(R)" >> ~/WhoReadTestVault/netrc"#])
        // Quoted pieces joined into one word are read as the one value the shell makes of them. A word
        // that did not start with a quote is written back without the quotes it was read in.
        assertRedacted(["/bin/sh", "-c", #"psql -c 'ALTER USER bob PASSWORD '"'Hunter2pw'""#],
                       ["/bin/sh", "-c", #"psql -c "ALTER USER bob PASSWORD '\#(R)'""#])
        assertRedacted(["/bin/sh", "-c", "tool password:'Hun''ter2pw'"], ["/bin/sh", "-c", "tool password:\(R)"], secrets: ["Hun", "ter2pw"])
        assertRedacted(["/bin/sh", "-c", "PGPASSWORD='Hun'\"ter2pw\" psql -h db"], ["/bin/sh", "-c", "PGPASSWORD=\(R) psql -h db"],
                       secrets: ["Hun", "ter2pw"])
        assertRedacted(["/bin/sh", "-c", "git clone https://bob:'Hun''ter2pw'@host/x"], ["/bin/sh", "-c", "git clone https://bob:\(R)@host/x"],
                       secrets: ["Hun", "ter2pw"])
        // A single quote in a URL's password: the URL ends at the quote it is in, not at that one.
        assertRedacted(["/bin/sh", "-c", #"git clone 'https://bob:Hun'\''ter2pw@host/x' && ls"#],
                       ["/bin/sh", "-c", #"git clone "https://bob:\#(R)@host/x" && ls"#], secrets: ["Hun", "ter2pw"])
        assertRedacted(["git", "clone", "https://bob:Hun'ter2pw@host/x"], ["git", "clone", "https://bob:\(R)@host/x"], secrets: ["Hun", "ter2pw"])
        // Nothing to redact: the word stays as written.
        assertKept([
            ["/bin/zsh", "-c", #"git commit -m 'Don'\''t log the password' && git log -1"#],
            ["/bin/zsh", "-c", #"python3 -c 'print("it'\''s ok")'"#],
            ["/bin/zsh", "-c", "-l", zsh + #"'grep -rn '\''IDENTIFIED BY'\'' migrations/'"# + tail],
            ["/bin/bash", "-c", #"echo $'a\tb' && ls"#],
            ["/bin/sh", "-c", "psql -c \"SELECT 'it''s'\""],
            ["/bin/sh", "-c", "echo 'a'\"b\" && ls"], ["/bin/sh", "-c", "ls \"$HOME\"'/x y'"],
            ["/bin/sh", "-c", "git commit -m 'fix: '\"quote\"' handling'"], ["/bin/sh", "-c", "grep -rn 'pass''word' src/"],
            ["/bin/sh", "-c", "curl -s 'https://api.example.com/x?q=a' -H 'Accept: application/json'"],
            ["/bin/sh", "-c", "echo \"see 'https://example.com/@user' and 'mail@example.com'\""],
        ])
    }

    // MARK: - Data written by compound commands and after exec > FILE

    /// A pgpass line: no key=value or netrc rule would catch it, only the data rules.
    let pg = "'db:5432:*:bob:Hunter2pw'"

    func testLoopsAndConditionalsWhoseOutputGoesToAFile() {
        assertRedacted(["/bin/sh", "-c", "while true; do echo \(pg); break; done > ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "while true; do echo '\(R)'; break; done > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/sh", "-c", "if true; then printf '%s\\n' \(pg); fi >> ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "if true; then printf '\(R)' '\(R)'; fi >> ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/sh", "-c", "until false; do echo Hunter2pw; break; done | tee -a ~/WhoReadTestVault/n"],
                       ["/bin/sh", "-c", "until false; do echo \(R); break; done | tee -a ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/sh", "-c", "if false; then :; else echo Hunter2pw; fi>~/WhoReadTestVault/n"],
                       ["/bin/sh", "-c", "if false; then :; else echo \(R); fi>~/WhoReadTestVault/n"])
        assertRedacted(["/bin/sh", "-c", "case x in x) echo Hunter2pw;; esac > ~/WhoReadTestVault/n"],
                       ["/bin/sh", "-c", "case x in x) echo \(R);; esac > ~/WhoReadTestVault/n"])
        // Over several lines; a `done` in a heredoc body closes nothing.
        assertRedacted(["/bin/bash", "-c", "{\n  echo \(pg)\n} > ~/WhoReadTestVault/pgpass"],
                       ["/bin/bash", "-c", "{\n  echo '\(R)'\n} > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "while true; do\n  python3 - <<EOF\ndone\nEOF\n  echo Hunter2pw\n  break\ndone > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "while true; do\n  python3 - <<EOF\ndone\nEOF\n  echo \(R)\n  break\ndone > ~/WhoReadTestVault/n"])
        // The list of a for loop is what its body writes. `"$l"` holds no text of its own and stays.
        assertRedacted(["/bin/sh", "-c", "for l in \(pg) 'x'; do echo \"$l\"; done >> ~/WhoReadTestVault/pgpass"],
                       ["/bin/sh", "-c", "for l in '\(R)' '\(R)'; do echo \"$l\"; done >> ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "for l in \(pg)\ndo\n  echo \"$l\"\ndone > ~/WhoReadTestVault/pgpass"],
                       ["/bin/bash", "-c", "for l in '\(R)'\ndo\n  echo \"$l\"\ndone > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "yes Hunter2pw | head -1 > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "yes \(R) | head -1 > ~/WhoReadTestVault/n"])
        // The body writes the loop's variable itself (`echo "$l" >> FILE`, through a pipe, inside an `if`).
        assertRedacted(["/bin/bash", "-c", "for l in 'db:5432:*:bob:Hunter2pw'; do echo \"$l\" >> ~/WhoReadTestVault/pgpass; done"],
                       ["/bin/bash", "-c", "for l in '\(R)'; do echo \"$l\" >> ~/WhoReadTestVault/pgpass; done"])
        assertRedacted(["/bin/bash", "-c", "for l in 'machine h' 'password Hunter2pw'; do echo \"$l\" | tee -a ~/WhoReadTestVault/netrc; done"],
                       ["/bin/bash", "-c", "for l in '\(R)' '\(R)'; do echo \"$l\" | tee -a ~/WhoReadTestVault/netrc; done"])
        assertRedacted(["/bin/bash", "-c", "for l in Hunter2pw; do\n  if true; then printf '%s\\n' \"$l\" > ~/WhoReadTestVault/n; fi\ndone"],
                       ["/bin/bash", "-c", "for l in \(R); do\n  if true; then printf '\(R)' \"$l\" > ~/WhoReadTestVault/n; fi\ndone"])
        // A loop cut short before its `done` (long command lines are bounded).
        assertRedacted(["/bin/bash", "-c", "for l in 'Hunter2pw' x; do echo \"$l\" >> ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "for l in '\(R)' \(R); do echo \"$l\" >> ~/WhoReadTestVault/n"])
        assertKept([
            ["/bin/bash", "-c", "for f in *.log; do gzip \"$f\"; done"], ["/bin/bash", "-c", "for f in a.txt b.txt; do wc -l \"$f\" >> counts.txt; done"],
            ["/bin/bash", "-c", "for f in src/*.swift; do echo \"== $f\"; done"],
        ])
        // A function body's redirect.
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; } > ~/WhoReadTestVault/n; f"],
                       ["/bin/bash", "-c", "f() { echo \(R); } > ~/WhoReadTestVault/n; f"])
    }

    /// A function writes where the command that calls it sends its output: `f() { echo pw; }` then
    /// `f > FILE` writes pw to FILE, also through a pipe, a group or another function.
    func testFunctionsCalledWithTheirOutputRedirected() {
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; }\nf > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "f() { echo \(R); }\nf > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "creds() {\n  echo 'machine h'\n  echo 'password Hunter2pw'\n}\ncreds >> ~/WhoReadTestVault/netrc"],
                       ["/bin/bash", "-c", "creds() {\n  echo '\(R)'\n  echo '\(R)'\n}\ncreds >> ~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/bash", "-c", "function g { printf '%s' Hunter2pw; }; g | tee ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "function g { printf '\(R)' \(R); }; g | tee ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "function g() { echo Hunter2pw; }; g 1> ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "function g() { echo \(R); }; g 1> ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "f() ( echo Hunter2pw ); { f; } > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "f() ( echo \(R) ); { f; } > ~/WhoReadTestVault/n"])
        // A function that calls another.
        assertRedacted(["/bin/bash", "-c", "a() { echo Hunter2pw; }; b() { a; }; b > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "a() { echo \(R); }; b() { a; }; b > ~/WhoReadTestVault/n"])
        // Defined first, called after `exec > FILE`.
        assertRedacted(["/bin/bash", "-c", "function f() {\n  echo Hunter2pw\n}\nexec > ~/WhoReadTestVault/n\nf"],
                       ["/bin/bash", "-c", "function f() {\n  echo \(R)\n}\nexec > ~/WhoReadTestVault/n\nf"])
        assertKept([
            ["/bin/bash", "-c", "f() { echo hello; }; f\nexec > out.txt"], ["/bin/bash", "-c", "f() { echo hello; }; exec 2>/dev/null; f"],
            ["/bin/bash", "-c", "f() { echo hello; }; f"], ["/bin/bash", "-c", "f() { echo hello; }; f 2>/dev/null"],
            ["/bin/bash", "-c", "f() { echo hello; }; f; ls > out.txt"], ["/bin/bash", "-c", "f() { ls; }; f > out.txt"],
            // Called before it is defined: not this body.
            ["/bin/bash", "-c", "f > out.txt; f() { echo hello; }"],
        ])
    }

    /// Chains of any depth, a function that calls one defined after it (the shell looks the name up
    /// when the call runs), and calls written `(f)`, `f>FILE` or `f|tee`. A call at the top runs the
    /// definition before it.
    func testFunctionChainsAndCallsWithShellSyntaxInTheirWord() {
        assertRedacted(["/bin/bash", "-c", "c() { echo Hunter2pw; }; b() { c; }; a() { b; }; a > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "c() { echo \(R); }; b() { c; }; a() { b; }; a > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "d() { printf '%s' Hunter2pw; }; c() { d; }; b() { c; }; a() { b; }; a | tee ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "d() { printf '\(R)' \(R); }; c() { d; }; b() { c; }; a() { b; }; a | tee ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "a() { b; }; b() { echo Hunter2pw; }; a > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "a() { b; }; b() { echo \(R); }; a > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "a() {\n  b | cat\n}\nb() {\n  echo Hunter2pw\n}\na >> ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "a() {\n  b | cat\n}\nb() {\n  echo \(R)\n}\na >> ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; }; (f) > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "f() { echo \(R); }; (f) > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; }; f>~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "f() { echo \(R); }; f>~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; }; f>>~/WhoReadTestVault/n; ls"],
                       ["/bin/bash", "-c", "f() { echo \(R); }; f>>~/WhoReadTestVault/n; ls"])
        // Defined again later: the call ran the first definition.
        assertRedacted(["/bin/bash", "-c", "f() { echo Hunter2pw; }; f > ~/WhoReadTestVault/n; f() { ls; }"],
                       ["/bin/bash", "-c", "f() { echo \(R); }; f > ~/WhoReadTestVault/n; f() { ls; }"])
        assertKept([
            ["/bin/bash", "-c", "f() { echo hello; }; f; f() { ls; }; f > out.txt"],
            ["/bin/bash", "-c", "a() { b; }; b() { echo hello; }; a"], ["/bin/bash", "-c", "f() { echo hello; }; (f) 2>/dev/null"],
            ["/bin/bash", "-c", "f() { echo hello; }; f 2>/dev/null; ls>out.txt"],
        ])
    }

    func testExecRedirectAndProcessSubstitution() {
        // exec > FILE: everything the shell writes afterwards goes there, on later lines too.
        assertRedacted(["/bin/sh", "-c", "exec > ~/WhoReadTestVault/pgpass\necho \(pg)"],
                       ["/bin/sh", "-c", "exec > ~/WhoReadTestVault/pgpass\necho '\(R)'"])
        assertRedacted(["/bin/sh", "-c", "exec 1>>~/WhoReadTestVault/pgpass; printf '%s\\n' \(pg)"],
                       ["/bin/sh", "-c", "exec 1>>~/WhoReadTestVault/pgpass; printf '\(R)' '\(R)'"])
        assertRedacted(["/bin/bash", "-c", "exec &> ~/WhoReadTestVault/n\nls\necho Hunter2pw"],
                       ["/bin/bash", "-c", "exec &> ~/WhoReadTestVault/n\nls\necho \(R)"])
        // `1<>FILE` opens FILE for reading and writing as standard output.
        assertRedacted(["/bin/bash", "-c", "exec 1<>~/WhoReadTestVault/n; echo Hunter2pw"], ["/bin/bash", "-c", "exec 1<>~/WhoReadTestVault/n; echo \(R)"])
        assertRedacted(["/bin/bash", "-c", "echo Hunter2pw 1<> ~/WhoReadTestVault/n"], ["/bin/bash", "-c", "echo \(R) 1<> ~/WhoReadTestVault/n"])
        assertKept([["/bin/bash", "-c", "exec <>/dev/null; echo hello"], ["/bin/bash", "-c", "exec 0<>/dev/null; echo hello"]])
        // Process substitution: echo writes into a pipe; the command around it goes on as before.
        assertRedacted(["/bin/bash", "-c", "cat <(echo \(pg)) > ~/WhoReadTestVault/pgpass"],
                       ["/bin/bash", "-c", "cat <(echo '\(R)') > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "while read l; do echo \"$l\"; done < <(echo \(pg)) > ~/WhoReadTestVault/pgpass"],
                       ["/bin/bash", "-c", "while read l; do echo \"$l\"; done < <(echo '\(R)') > ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "diff <(echo Hunter2pw) ~/WhoReadTestVault/n && curl -u admin:Hunter2pw https://x"],
                       ["/bin/bash", "-c", "diff <(echo \(R)) ~/WhoReadTestVault/n && curl -u admin:\(R) https://x"])
        // As an option's value: the shell puts the pipe's path there (a client config with the password).
        assertRedacted(["/bin/bash", "-c", "mysql --defaults-extra-file=<(printf '[client]\\npassword=%s\\n' Hunter2pw) -e 'select 1'"],
                       ["/bin/bash", "-c", "mysql --defaults-extra-file=<(printf '\(R)' \(R)) -e 'select 1'"])
        assertRedacted(["/bin/bash", "-c", "tool --password-file=<(echo Hunter2pw) --user bob"],
                       ["/bin/bash", "-c", "tool --password-file=<(echo \(R)) --user bob"])
        assertKept([
            ["/bin/bash", "-c", "mysql --defaults-extra-file=<(cat my.cnf) -e 'select 1'"], ["/bin/bash", "-c", "ls --color=auto x=1"],
            ["/bin/bash", "-c", "tool --input=<(sort a.txt) > out.txt"],
        ])
    }

    /// A command line run by a shell, eval or ssh writes where that command's output goes:
    /// `sh -c 'echo pw' > FILE` writes pw to FILE.
    func testCommandLinesRunByAShellWriteWhereItsOutputGoes() {
        assertRedacted(["/bin/bash", "-c", "sh -c 'echo Hunter2pw' > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "sh -c 'echo \(R)' > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "sudo bash -lc \"printf '%s' \(pg)\" | tee ~/WhoReadTestVault/pgpass"],
                       ["/bin/bash", "-c", "sudo bash -lc \"printf '\(R)' '\(R)'\" | tee ~/WhoReadTestVault/pgpass"])
        assertRedacted(["/bin/bash", "-c", "eval 'echo Hunter2pw' >> ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "eval 'echo \(R)' >> ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "ssh host 'echo Hunter2pw' > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "ssh host 'echo \(R)' > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "{ zsh -c 'echo Hunter2pw'; } > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "{ zsh -c 'echo \(R)'; } > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "exec > ~/WhoReadTestVault/n\nsh -c 'sh -c \"echo Hunter2pw\"'"],
                       ["/bin/bash", "-c", "exec > ~/WhoReadTestVault/n\nsh -c 'sh -c \"echo \(R)\"'"])
        // zsh's `repeat N` runs the command after it.
        assertRedacted(["/bin/zsh", "-c", "repeat 1 echo Hunter2pw > ~/WhoReadTestVault/n"],
                       ["/bin/zsh", "-c", "repeat 1 echo \(R) > ~/WhoReadTestVault/n"])
        assertKept([
            ["/bin/bash", "-c", "sh -c 'echo hello'"], ["/bin/bash", "-c", "sh -c 'echo hello' 2>/dev/null"],
            ["/bin/bash", "-c", "sh -c 'cd /tmp && ls' > out.txt"], ["/bin/bash", "-c", "sh -c 'echo hello'; ls > out.txt"],
            ["/bin/bash", "-c", "git commit -m 'echo hello' > log.txt"], ["/bin/bash", "-c", "grep 'echo foo' src/*.sh > hits.txt"],
            ["/bin/bash", "-c", "timeout 10s sh -c 'echo hello'"],
        ])
    }

    /// A variable set to a literal and then written (`PW='…'; echo "$PW" > FILE`, a heredoc body, a
    /// here-string) holds what the file gets: its value is redacted where it is set. The expansion
    /// itself (`"$PW"`, `${PW}`) holds no text of its own and stays.
    func testVariablesWrittenAsData() {
        assertRedacted(["/bin/bash", "-c", "PW=\(pg)\necho \"machine h login bob password $PW\" >> ~/WhoReadTestVault/netrc"],
                       ["/bin/bash", "-c", "PW=\(R)\necho \"\(R)\" >> ~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/bash", "-c", "x=Hunter2pw; printf '%s\\n' \"$x\" | sudo tee ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "x=\(R); printf '\(R)' \"$x\" | sudo tee ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "export PW=Hunter2pw\ncat > ~/WhoReadTestVault/n <<EOF\npassword ${PW}\nEOF"],
                       ["/bin/bash", "-c", "export PW=\(R)\ncat > ~/WhoReadTestVault/n <<EOF\n\(R) ${PW}\nEOF"])
        assertRedacted(["/bin/bash", "-c", "v=Hunter2pw; tee ~/WhoReadTestVault/n <<< \"$v\""],
                       ["/bin/bash", "-c", "v=\(R); tee ~/WhoReadTestVault/n <<< \"$v\""])
        assertRedacted(["/bin/bash", "-c", "v=Hunter2pw; tee ~/WhoReadTestVault/n <<<$v"], ["/bin/bash", "-c", "v=\(R); tee ~/WhoReadTestVault/n <<<$v"])
        assertRedacted(["/bin/bash", "-c", "local v=Hunter2pw; echo $v>~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "local v=\(R); echo $v>~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "v=Hunter2pw; for l in \"$v\"; do echo $l|tee ~/WhoReadTestVault/n; done"],
                       ["/bin/bash", "-c", "v=\(R); for l in \"$v\"; do echo $l|tee ~/WhoReadTestVault/n; done"])
        assertKept([
            ["/bin/bash", "-c", "DIR=/tmp/x; ls \"$DIR\" > out.txt"], ["/bin/bash", "-c", "NAME=world; echo \"hello $NAME\""],
            ["/bin/bash", "-c", "v=Hunter2pw; cat \"$v\" > out.txt"],
            // Another variable is another value, set outside the command line.
            ["/bin/bash", "-c", "X=keep1; echo $Y > f"], ["/bin/bash", "-c", "while read l; do echo \"$l\"; done < a.txt > b.txt"],
            ["/bin/bash", "-c", "echo \"$@\" > args.txt"], ["/bin/bash", "-c", "echo \"${HOME}\" \"$1\" | tee out.txt"],
        ])
        // Single quotes do not expand: '$X' is text. So are a default value and text next to the name.
        assertRedacted(["/bin/bash", "-c", "X=keep1; echo '$X' > f"], ["/bin/bash", "-c", "X=keep1; echo '\(R)' > f"], secrets: [])
        assertRedacted(["/bin/bash", "-c", "echo \"${PW:-Hunter2pw}\" > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "echo \"\(R)\" > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "echo $1Hunter2pw > ~/WhoReadTestVault/n"], ["/bin/bash", "-c", "echo \(R) > ~/WhoReadTestVault/n"])
    }

    /// Loops whose words name each other's variables: each variable is followed once. Following every
    /// path instead took minutes for ten such loops (the analyzer would stall on one command line).
    func testLoopsNamingEachOtherAreFollowedOnce() {
        let names = "abcdefghij".map(String.init)
        let loops = names.map { n in
            "for \(n) in " + (names.filter { $0 != n } + ["z"]).map { "$" + $0 }.joined() + "; do echo $\(n) >> f; done; "
        }.joined()
        let start = Date()
        assertRedacted(["/bin/bash", "-c", "z=Hunter2pw; " + loops], ["/bin/bash", "-c", "z=\(R); " + loops])
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }

    /// `;`, `&&`, `||`, `|` and `&` end a command with no space around them too: the command after one
    /// has its own rules, and a loop written `for …;do …;done > FILE` is a loop.
    func testOperatorsWithNoSpaceAroundThem() {
        assertRedacted(["/bin/bash", "-c", "ls;curl -u admin:Hunter2pw https://x"], ["/bin/bash", "-c", "ls;curl -u admin:\(R) https://x"])
        assertRedacted(["/bin/bash", "-c", "cd /tmp&&mysql -uroot -pHunter2pw"], ["/bin/bash", "-c", "cd /tmp&&mysql -uroot -p\(R)"])
        assertRedacted(["/bin/bash", "-c", "x=1;htpasswd -nb bob Hunter2pw"], ["/bin/bash", "-c", "x=1;htpasswd -nb bob \(R)"])
        assertRedacted(["/bin/bash", "-c", "cd /tmp;echo Hunter2pw > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "cd /tmp;echo \(R) > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "for x in 'Hunter2pw';do echo $x;done > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "for x in '\(R)';do echo $x;done > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "while true;do echo Hunter2pw;break;done > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "while true;do echo \(R);break;done > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "if true;then echo Hunter2pw;fi > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "if true;then echo \(R);fi > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "{ echo Hunter2pw;} > ~/WhoReadTestVault/n"], ["/bin/bash", "-c", "{ echo \(R);} > ~/WhoReadTestVault/n"])
        assertRedacted(["/bin/bash", "-c", "if mysql -pHunter2pw;then echo ok;fi"], ["/bin/bash", "-c", "if mysql -p\(R);then echo ok;fi"])
        // After a redacted value the operator and the next word are shown as part of it (the value may
        // hold them), but that word still starts a command with its own rules.
        assertRedacted(["/bin/bash", "-c", "mysql -uroot -pHunter2pw&&curl -u admin:Hunter2pw https://x"],
                       ["/bin/bash", "-c", "mysql -uroot -p\(R) -u admin:\(R) https://x"])
        assertRedacted(["/bin/bash", "-c", "ldapsearch -x -w Hunter2pw;sshpass -p Hunter2pw ssh h"],
                       ["/bin/bash", "-c", "ldapsearch -x -w \(R) -p \(R) ssh h"])
        assertRedacted(["/bin/bash", "-c", "tool --token Hunter2pw|htpasswd -nb bob Hunter2pw"], ["/bin/bash", "-c", "tool --token \(R) -nb bob \(R)"])
        assertRedacted(["/bin/bash", "-c", "export PW=Hunter2pw&&echo Hunter2pw > ~/WhoReadTestVault/n"],
                       ["/bin/bash", "-c", "export PW=\(R) \(R) > ~/WhoReadTestVault/n"])
        // A redirect attached to a word: the word keeps the rules it has there.
        assertRedacted(["/bin/bash", "-c", "mysql -uroot -pHunter2pw>out.txt"], ["/bin/bash", "-c", "mysql -uroot -p\(R)>out.txt"])
        assertRedacted(["/bin/bash", "-c", "htpasswd -nb bob Hunter2pw>>~/WhoReadTestVault/htpasswd"],
                       ["/bin/bash", "-c", "htpasswd -nb bob \(R)>>~/WhoReadTestVault/htpasswd"])
        assertRedacted(["/bin/bash", "-c", "ldapsearch -x -w Hunter2pw>out.ldif; security add-generic-password -a bob -s svc -w Hunter2pw>/dev/null"],
                       ["/bin/bash", "-c", "ldapsearch -x -w \(R)>out.ldif; security add-generic-password -a bob -s svc -w \(R)>/dev/null"])
        assertRedacted(["/bin/bash", "-c", "curl -u bob:Hunter2pw>out.html https://x"], ["/bin/bash", "-c", "curl -u bob:\(R)>out.html https://x"])
        assertRedacted(["/bin/bash", "-c", "echo>~/WhoReadTestVault/n Hunter2pw"], ["/bin/bash", "-c", "echo>~/WhoReadTestVault/n \(R)"])
        // Also after a quoted word with spaces in it.
        assertRedacted(["/bin/bash", "-c", "echo 'machine h login bob password Hunter2pw'>~/WhoReadTestVault/netrc"],
                       ["/bin/bash", "-c", "echo '\(R)'>~/WhoReadTestVault/netrc"])
        assertRedacted(["/bin/bash", "-c", "sh -c 'echo Hunter2pw'>~/WhoReadTestVault/n; eval 'sshpass -p Hunter2pw ssh h'>log"],
                       ["/bin/bash", "-c", "sh -c 'echo \(R)'>~/WhoReadTestVault/n; eval 'sshpass -p \(R) ssh h'>log"])
        assertKept([
            ["/bin/bash", "-c", "ls -la>out.txt"], ["/bin/bash", "-c", "make>build.log 2>&1"], ["/bin/bash", "-c", "tool --key ~/.ssh/id_ed25519>f"],
            ["/bin/bash", "-c", "python3 run.py --token-file /etc/x>out"], ["/bin/bash", "-c", "sudo ls>out; time make>log"],
            ["/bin/bash", "-c", "git commit -m 'fix the thing'>log.txt"], ["/bin/bash", "-c", "grep 'a b' file>out.txt; ls 'my dir'>out"],
        ])
        // In text that is not a command line (a connection string, YAML fed to a program), an operator
        // may be part of a value: what is glued to a redacted value goes with it.
        assertRedacted(["/bin/sh", "-c", "kubectl apply -f - <<EOF\nstringData:\n  password: Hun;ter&2pw|x\nEOF"],
                       ["/bin/sh", "-c", "kubectl apply -f - <<EOF\nstringData:\n  password: \(R)\nEOF"], secrets: ["Hun", "ter", "2pw"])
        assertRedacted(["dotnet", "ef", "database", "update", "--connection", "Server=db;User Id=sa;Password=Hun;ter2pw"],
                       ["dotnet", "ef", "database", "update", "--connection", "Server=db;User Id=sa;Password=\(R)"], secrets: ["Hun", "ter2pw"])
        assertRedacted(["curl", "-d", "user=bob password=Hun&ter2pw", "https://x"], ["curl", "-d", "user=bob password=\(R)", "https://x"],
                       secrets: ["Hun", "ter2pw"])
        assertRedacted(["/bin/sh", "-c", "cat <<EOF > ~/WhoReadTestVault/n\nHun;ter&2pw\nEOF"], ["/bin/sh", "-c", "cat <<EOF > ~/WhoReadTestVault/n\n\(R)\nEOF"],
                       secrets: ["Hun", "ter", "2pw"])
        // A URL's query and password are read before the split: `&` and `;` belong to them there.
        assertRedacted(["git", "commit", "-m", "see https://h/x?sv=1&sig=Hunter2pw"], ["git", "commit", "-m", "see https://h/x?sv=1&sig=\(R)"])
        assertRedacted(["/bin/sh", "-c", "curl https://h/cb?state=1&code=Hunter2pw"], ["/bin/sh", "-c", "curl https://h/cb?state=1&code=\(R)"])
        assertRedacted(["/bin/sh", "-c", "curl https://h/x?X-Amz-Date=1&X-Amz-Signature=Hunter2pw"],
                       ["/bin/sh", "-c", "curl https://h/x?X-Amz-Date=1&X-Amz-Signature=\(R)"])
        assertRedacted(["/bin/sh", "-c", "curl https://h/x;jsessionid=Hunter2pw"], ["/bin/sh", "-c", "curl https://h/x;jsessionid=\(R)"])
        assertRedacted(["/bin/sh", "-c", "curl -s https://h/x?a=1&auth=Hunter2pw | jq ."], ["/bin/sh", "-c", "curl -s https://h/x?a=1&auth=\(R) | jq ."])
        assertRedacted(["git", "commit", "-m", "clone https://bob:Hun;ter2pw@host/x"], ["git", "commit", "-m", "clone https://bob:\(R)@host/x"],
                       secrets: ["Hun", "ter2pw"])
        assertRedacted(["/bin/sh", "-c", "git clone https://bob:Hun&ter2pw@host/x"], ["/bin/sh", "-c", "git clone https://bob:\(R)@host/x"],
                       secrets: ["Hun", "ter2pw"])
        assertKept([
            ["/bin/sh", "-c", "echo hello;ls -la"], ["/bin/sh", "-c", "for x in a b;do echo $x;done"], ["/bin/sh", "-c", "x=1;y=2;ls"],
            ["/bin/sh", "-c", "find . -name '*.o' -exec rm {} \\;"], ["/bin/sh", "-c", "make 2>&1|tee log"], ["/bin/sh", "-c", "cmd &>/dev/null&"],
            ["/bin/sh", "-c", "echo ${x//;/,}"], ["/bin/sh", "-c", "cmd >|out.txt"], ["git", "commit", "-m", "Fix a;b and c&&d, e|f"],
            ["psql", "-c", "SELECT a||b FROM t; SELECT 1"], ["/bin/sh", "-c", "case $1 in a|b) echo x;; esac"],
            ["/bin/sh", "-c", "curl https://h/x?a=1&b=2"], ["/bin/sh", "-c", "curl https://user@host/x;ls"],
            ["/bin/sh", "-c", "echo // comment@here; ls"], ["/bin/sh", "-c", "sleep 1&echo done"],
        ])
    }

    /// The command after `if`, `while`, `until`, `elif` and `!` is a program with its own rules.
    func testCommandsInConditionsKeepTheirFlagRules() {
        assertRedacted(["/bin/sh", "-c", "if curl -u admin:Hunter2pw https://x; then echo ok; fi"],
                       ["/bin/sh", "-c", "if curl -u admin:\(R) https://x; then echo ok; fi"])
        assertRedacted(["/bin/sh", "-c", "while ! curl -u admin:Hunter2pw https://x; do sleep 1; done"],
                       ["/bin/sh", "-c", "while ! curl -u admin:\(R) https://x; do sleep 1; done"])
        assertRedacted(["/bin/sh", "-c", "until mysql -pHunter2pw -e 'select 1'; do sleep 1; done"],
                       ["/bin/sh", "-c", "until mysql -p\(R) -e 'select 1'; do sleep 1; done"])
        assertRedacted(["/bin/sh", "-c", "if false; then :; elif sshpass -p Hunter2pw ssh h; then :; fi"],
                       ["/bin/sh", "-c", "if false; then :; elif sshpass -p \(R) ssh h; then :; fi"])
        assertRedacted(["/bin/sh", "-c", "case $1 in up) htpasswd -nb bob Hunter2pw;; esac"],
                       ["/bin/sh", "-c", "case $1 in up) htpasswd -nb bob \(R);; esac"])
    }

    func testCompoundCommandsThatWriteNowhereAreKept() {
        assertKept([
            ["/bin/sh", "-c", "for f in *.txt; do echo \"$f\"; done"],
            ["/bin/sh", "-c", "while read l; do echo \"$l\"; done < input.txt"],
            ["/bin/sh", "-c", "if [ -f x ]; then echo yes; else echo no; fi"],
            ["/bin/sh", "-c", "for f in *.txt; do wc -l \"$f\"; done > counts.txt"],
            ["/bin/bash", "-c", "for i in 1 2; do\n  echo $i\ndone\nls > out.txt"],
            ["/bin/sh", "-c", "exec 2>/dev/null; echo hello"],
            ["/bin/sh", "-c", "cat <(ls) > /tmp/out"],
            ["/bin/bash", "-c", "diff <(sort a) <(sort b)"],
            ["/bin/sh", "-c", "case $1 in start) echo starting;; esac"],
            ["/bin/sh", "-c", "x=$(echo hello) && { echo $x; }"],
            ["/bin/sh", "-c", "{ echo hello; ls; } 2>/dev/null"],
            ["/bin/sh", "-c", "while true; do echo tick; sleep 1; done 2>&1"],
        ])
    }
}
