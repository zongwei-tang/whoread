import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

/// Minimal SQLite wrapper: one connection, statements prepared per call, errors as Swift errors.
/// Not thread-safe by itself; `SQLiteEventStore` serializes access.
final class SQLiteDatabase {
    struct Error: Swift.Error, CustomStringConvertible {
        var code: Int32
        var message: String
        var description: String { "SQLite error \(code): \(message)" }
    }

    private(set) var handle: OpaquePointer?

    init(path: String) throws {
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        guard rc == SQLITE_OK, let db else {
            let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            sqlite3_close(db)
            throw Error(code: rc, message: msg)
        }
        handle = db
        sqlite3_busy_timeout(db, 5000)
    }

    deinit {
        sqlite3_close_v2(handle)
    }

    func error(_ rc: Int32) -> Error {
        Error(code: rc, message: handle.map { String(cString: sqlite3_errmsg($0)) } ?? "no handle")
    }

    func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "exec failed"
            sqlite3_free(err)
            throw Error(code: rc, message: msg)
        }
    }

    func prepare(_ sql: String) throws -> Statement {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw error(rc) }
        return Statement(db: self, stmt: stmt)
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try exec("BEGIN IMMEDIATE")
        do {
            let v = try body()
            try exec("COMMIT")
            return v
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    var changes: Int { Int(sqlite3_changes(handle)) }
}

/// SQLITE_TRANSIENT: tell SQLite to copy bound buffers.
private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

final class Statement {
    private let db: SQLiteDatabase
    private let stmt: OpaquePointer

    init(db: SQLiteDatabase, stmt: OpaquePointer) {
        self.db = db
        self.stmt = stmt
    }

    deinit { sqlite3_finalize(stmt) }

    enum Value {
        case int(Int64)
        case double(Double)
        case text(String)
        case blob(Data)
        case null
    }

    @discardableResult
    func bind(_ values: [Value]) throws -> Statement {
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
        for (i, v) in values.enumerated() {
            let idx = Int32(i + 1)
            let rc: Int32
            switch v {
            case .int(let x): rc = sqlite3_bind_int64(stmt, idx, x)
            case .double(let x): rc = sqlite3_bind_double(stmt, idx, x)
            case .text(let s): rc = sqlite3_bind_text(stmt, idx, s, -1, transient)
            case .blob(let d):
                rc = d.withUnsafeBytes { buf in
                    sqlite3_bind_blob(stmt, idx, buf.baseAddress, Int32(buf.count), transient)
                }
            case .null: rc = sqlite3_bind_null(stmt, idx)
            }
            guard rc == SQLITE_OK else { throw db.error(rc) }
        }
        return self
    }

    /// Runs a statement that returns no rows.
    func run(_ values: [Value] = []) throws {
        try bind(values)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw db.error(rc) }
        sqlite3_reset(stmt)
    }

    /// Iterates result rows.
    func query(_ values: [Value] = [], _ row: (Row) throws -> Void) throws {
        try bind(values)
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw db.error(rc) }
            try row(Row(stmt: stmt))
        }
        sqlite3_reset(stmt)
    }

    struct Row {
        let stmt: OpaquePointer
        func int(_ i: Int32) -> Int64 { sqlite3_column_int64(stmt, i) }
        func double(_ i: Int32) -> Double { sqlite3_column_double(stmt, i) }
        func isNull(_ i: Int32) -> Bool { sqlite3_column_type(stmt, i) == SQLITE_NULL }
        func text(_ i: Int32) -> String? {
            guard let p = sqlite3_column_text(stmt, i) else { return nil }
            return String(cString: p)
        }
        func blob(_ i: Int32) -> Data {
            let n = Int(sqlite3_column_bytes(stmt, i))
            guard n > 0, let p = sqlite3_column_blob(stmt, i) else { return Data() }
            return Data(bytes: p, count: n)
        }
    }
}
