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
}
