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
/// Trips (and stays tripped until `reset`) when a deadline is missed, or when p99 exceeds the
/// threshold in `breachesToTrip` consecutive evaluations. The daemon turns enforcement off when it trips.
///
/// An evaluation breaches when the p99 over the window (with enough samples) and the p99 of the
/// responses recorded since the previous evaluation are both over the threshold. A short burst stays
/// in the window long after it ended, so the second condition is what makes a breach "persist": any
/// local process can queue a burst of AUTH messages by opening a covered file from many threads.
public final class LatencyMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var ring: [UInt32]
    private var head = 0
    private var filled = 0
    private var misses = 0
    private var total = 0
    private var tripped: String?
    /// Responses, and those over the threshold, since the previous tripping evaluation.
    private var recent = 0
    private var recentSlow = 0
    private var breaches = 0

    private var threshold: Double
    /// Settings change it while `record` reads it on the ES callback thread, so it is behind the lock.
    public var p99ThresholdMicros: Double {
        get { lock.lock(); defer { lock.unlock() }; return threshold }
        set { lock.lock(); threshold = newValue; lock.unlock() }
    }
    public var minimumSamples: Int
    public var breachesToTrip: Int

    public init(capacity: Int = 4096, p99ThresholdMicros: Double = 50_000, minimumSamples: Int = 50, breachesToTrip: Int = 1) {
        ring = Array(repeating: 0, count: max(16, capacity))
        self.threshold = p99ThresholdMicros
        self.minimumSamples = minimumSamples
        self.breachesToTrip = max(1, breachesToTrip)
    }

    /// `micros`: time from message arrival to response. `missedDeadline`: responded at/after the deadline.
    @inline(__always)
    public func record(micros: UInt64, missedDeadline: Bool) {
        lock.lock()
        ring[head] = UInt32(clamping: micros)
        head = (head + 1) % ring.count
        if filled < ring.count { filled += 1 }
        total += 1
        recent += 1
        if Double(micros) > threshold { recentSlow += 1 }
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

    /// Computes stats over the window and counts a p99 breach (trips after enough in a row). Returns the stats.
    @discardableResult
    public func evaluate(trip: Bool = true) -> LatencyStats {
        lock.lock()
        let samples = Array(ring.prefix(filled))
        let misses = self.misses
        let total = self.total
        let recent = self.recent, recentSlow = self.recentSlow, threshold = self.threshold
        if trip {
            self.recent = 0
            self.recentSlow = 0
        }
        lock.unlock()

        guard !samples.isEmpty else {
            if trip { lock.lock(); breaches = 0; lock.unlock() }
            return LatencyStats(deadlineMisses: misses, totalResponses: total)
        }
        let sorted = samples.sorted()
        func rank(_ p: Double, _ count: Int) -> Int { min(max(Int((p * Double(count - 1)).rounded(.up)), 0), count - 1) }
        func percentile(_ p: Double) -> Double { Double(sorted[rank(p, sorted.count)]) }
        let stats = LatencyStats(samples: sorted.count, p50Micros: percentile(0.50), p99Micros: percentile(0.99),
                                 maxMicros: Double(sorted.last ?? 0), deadlineMisses: misses, totalResponses: total)
        if trip {
            // The p99 of the `recent` responses is over the threshold when at least `recent - rank` are.
            let recentBreach = recent > 0 && recentSlow >= recent - rank(0.99, recent)
            let breach = sorted.count >= minimumSamples && stats.p99Micros > threshold && recentBreach
            lock.lock()
            breaches = breach ? breaches + 1 : 0
            if breaches >= breachesToTrip && tripped == nil {
                tripped = String(format: "p99 latency %.1f ms over %.1f ms", stats.p99Micros / 1000, threshold / 1000)
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
        recent = 0
        recentSlow = 0
        breaches = 0
        lock.unlock()
    }
}
