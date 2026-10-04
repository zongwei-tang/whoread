import Foundation

public struct LatencyStats: Codable, Hashable, Sendable {
    public var samples: Int
    public var p50Micros: Double
    public var p99Micros: Double
    public var maxMicros: Double
    public var deadlineMisses: Int
    public var totalResponses: Int

    public init(samples: Int = 0, p50Micros: Double = 0, p99Micros: Double = 0, maxMicros: Double = 0,
                deadlineMisses: Int = 0, totalResponses: Int = 0) {
        self.samples = samples
        self.p50Micros = p50Micros
        self.p99Micros = p99Micros
        self.maxMicros = maxMicros
        self.deadlineMisses = deadlineMisses
        self.totalResponses = totalResponses
    }
}

/// Records how long each AUTH response took. `record` is cheap enough for the ES callback
/// (lock + array store); percentiles are computed off the callback path by `evaluate`, which the
/// daemon calls from a timer.
///
/// Trips (and stays tripped until `reset`) when a deadline is missed, or when p99 over the window
/// exceeds the threshold with enough samples. The daemon turns enforcement off when it trips.
public final class LatencyMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var ring: [UInt32]
    private var head = 0
    private var filled = 0
    private var misses = 0
    private var total = 0
    private var tripped: String?

    public var p99ThresholdMicros: Double
    public var minimumSamples: Int

    public init(capacity: Int = 4096, p99ThresholdMicros: Double = 50_000, minimumSamples: Int = 50) {
        ring = Array(repeating: 0, count: max(16, capacity))
        self.p99ThresholdMicros = p99ThresholdMicros
        self.minimumSamples = minimumSamples
    }

    /// `micros`: time from message arrival to response. `missedDeadline`: responded at/after the deadline.
    @inline(__always)
    public func record(micros: UInt64, missedDeadline: Bool) {
        lock.lock()
        ring[head] = UInt32(clamping: micros)
        head = (head + 1) % ring.count
        if filled < ring.count { filled += 1 }
        total += 1
        if missedDeadline {
            misses += 1
            if tripped == nil { tripped = "deadline missed" }
        }
        lock.unlock()
    }

    public var trippedReason: String? {
        lock.lock(); defer { lock.unlock() }
        return tripped
    }

    public var isTripped: Bool { trippedReason != nil }

    /// Stats only (status display); never trips.
    public func evaluateWithoutTripping() -> LatencyStats { evaluate(trip: false) }

    /// Computes stats over the window and trips on p99. Returns the stats.
    @discardableResult
    public func evaluate(trip: Bool = true) -> LatencyStats {
        lock.lock()
        let samples = Array(ring.prefix(filled))
        let misses = self.misses
        let total = self.total
        lock.unlock()

        guard !samples.isEmpty else { return LatencyStats(deadlineMisses: misses, totalResponses: total) }
        let sorted = samples.sorted()
        func percentile(_ p: Double) -> Double {
            let rank = Int((p * Double(sorted.count - 1)).rounded(.up))
            return Double(sorted[min(max(rank, 0), sorted.count - 1)])
        }
        let stats = LatencyStats(samples: sorted.count, p50Micros: percentile(0.50), p99Micros: percentile(0.99),
                                 maxMicros: Double(sorted.last ?? 0), deadlineMisses: misses, totalResponses: total)
        if trip && sorted.count >= minimumSamples && stats.p99Micros > p99ThresholdMicros {
            lock.lock()
            if tripped == nil {
                tripped = String(format: "p99 latency %.1f ms over %.1f ms", stats.p99Micros / 1000, p99ThresholdMicros / 1000)
            }
            lock.unlock()
        }
        return stats
    }

    /// Clears the trip and the window (when the user re-enables enforcement).
    public func reset() {
        lock.lock()
        tripped = nil
        head = 0
        filled = 0
        misses = 0
        lock.unlock()
    }
}
