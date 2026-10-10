import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Process identity, Engine side: what the native source reads from es_process_t (parent and responsible
// tokens, the kernel's signing category, code signing flags).

#if canImport(EndpointSecurity)
import EndpointSecurity

/// An es_process_t built by hand in zeroed memory, laid out by the real SDK headers.
private final class FakeESProcess {
    private var blocks: [UnsafeMutableRawPointer] = []
    let process: UnsafeMutablePointer<es_process_t>

    init(pid: Int32, pidVersion: Int32, path: String) {
        func zeroed(_ size: Int, _ alignment: Int) -> UnsafeMutableRawPointer {
            let raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: max(alignment, 16))
            raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            return raw
        }
        let p = zeroed(MemoryLayout<es_process_t>.stride, MemoryLayout<es_process_t>.alignment)
        let bytes = Array(path.utf8)
        let chars = zeroed(bytes.count + 1, 1)
        bytes.withUnsafeBytes { chars.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let f = zeroed(MemoryLayout<es_file_t>.stride, MemoryLayout<es_file_t>.alignment).bindMemory(to: es_file_t.self, capacity: 1)
        f.initialize(to: es_file_t(path: es_string_token_t(length: bytes.count, data: chars.assumingMemoryBound(to: CChar.self)),
                                   path_truncated: false, stat: stat()))
        blocks = [p, chars, UnsafeMutableRawPointer(f)]
        process = p.bindMemory(to: es_process_t.self, capacity: 1)
        set(\.executable, f)
        set(\.audit_token, FakeESProcess.token(pid: pid, version: pidVersion))
    }

    deinit { blocks.forEach { $0.deallocate() } }

    static func token(pid: Int32, version: Int32) -> audit_token_t {
        // audit_token_to_pid reads val[5], audit_token_to_pidversion val[7] (libbsm).
        audit_token_t(val: (0, 501, 20, 501, 20, UInt32(bitPattern: pid), 100_017, UInt32(bitPattern: version)))
    }

    func set<T>(_ field: PartialKeyPath<es_process_t>, _ value: T) {
        let offset = MemoryLayout<es_process_t>.offset(of: field)!
        (UnsafeMutableRawPointer(process) + offset).storeBytes(of: value, as: T.self)
    }
}

final class NativeProcessRecordTests: XCTestCase {
    /// sdk-D3/D4: the parent token, the responsible token (the process itself = none), the signing
    /// category and the code signing flags, each read only from the message version that has it.
    func testTheRecordCarriesTokensSigningCategoryAndFlags() {
        let fake = FakeESProcess(pid: 501, pidVersion: 5_010, path: "/Applications/Tool.app/Contents/MacOS/Tool")
        fake.set(\.ppid, Int32(500))
        fake.set(\.original_ppid, Int32(500))
        fake.set(\.parent_audit_token, FakeESProcess.token(pid: 500, version: 5_000))
        fake.set(\.responsible_audit_token, FakeESProcess.token(pid: 501, version: 5_010))
        fake.set(\.cs_validation_category, ES_CS_VALIDATION_CATEGORY_DEVELOPMENT)
        fake.set(\.codesigning_flags, UInt32(0x2201_3b15))

        let r = NativeESSource.record(fake.process, version: 10)
        XCTAssertEqual(r.pid, 501)
        XCTAssertEqual(r.pidVersion, 5_010)
        XCTAssertEqual(r.parentToken, ProcessToken(pid: 500, pidVersion: 5_000))
        XCTAssertNil(r.responsiblePID, "the process itself: no responsible process")
        XCTAssertEqual(r.signingCategory, .development)
        XCTAssertEqual(r.codeSigningFlags, 0x2201_3b15)
        XCTAssertTrue(r.isControllable, "CS_GET_TASK_ALLOW")
        XCTAssertFalse(r.hasDistributionSignature)

        // Another responsible process is kept.
        fake.set(\.responsible_audit_token, FakeESProcess.token(pid: 400, version: 4_000))
        XCTAssertEqual(NativeESSource.record(fake.process, version: 10).responsiblePID, 400)

        // Fields newer than the message are not read.
        let v9 = NativeESSource.record(fake.process, version: 9)
        XCTAssertNil(v9.signingCategory)
        XCTAssertNotNil(v9.parentToken)
        let v3 = NativeESSource.record(fake.process, version: 3)
        XCTAssertNil(v3.parentToken)
        XCTAssertNil(v3.responsiblePID)
        XCTAssertEqual(v3.codeSigningFlags, 0x2201_3b15, "codesigning_flags exists in every version")
    }
}
#endif
