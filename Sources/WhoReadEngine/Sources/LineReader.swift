import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Blocking line splitter over a file descriptor. Calls `onLine` with each line's bytes (without
/// the newline) on the calling thread; returns at EOF or error. Lines longer than `maxLine` are
/// dropped (eslogger exec lines with huge environments can be large, but not megabytes).
struct LineReader {
    var fd: Int32
    var maxLine = 4 * 1024 * 1024
    var chunk = 256 * 1024

    func run(_ onLine: (UnsafeRawBufferPointer) -> Void) {
        var pending = [UInt8]()
        pending.reserveCapacity(chunk)
        var buffer = [UInt8](repeating: 0, count: chunk)
        var discarding = false
        while true {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, chunk) }
            if n < 0 {
                if errno == EINTR { continue }
                break
            }
            if n == 0 { break }
            var start = 0
            buffer.withUnsafeBytes { raw in
                let bytes = raw.bindMemory(to: UInt8.self)
                var i = 0
                while i < n {
                    if bytes[i] == 0x0A {
                        if discarding {
                            discarding = false
                            pending.removeAll(keepingCapacity: true)
                        } else if pending.isEmpty {
                            onLine(UnsafeRawBufferPointer(rebasing: raw[start..<i]))
                        } else {
                            pending.append(contentsOf: bytes[start..<i])
                            pending.withUnsafeBytes { onLine($0) }
                            pending.removeAll(keepingCapacity: true)
                        }
                        start = i + 1
                    }
                    i += 1
                }
                if start < n && !discarding {
                    pending.append(contentsOf: bytes[start..<n])
                    if pending.count > maxLine {
                        discarding = true
                        pending.removeAll(keepingCapacity: true)
                    }
                }
            }
        }
        if !pending.isEmpty && !discarding {
            pending.withUnsafeBytes { onLine($0) }
        }
    }
}
