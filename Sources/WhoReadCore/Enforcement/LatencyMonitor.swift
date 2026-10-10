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

/// Records how long each AUTH response took. Statistics only: slow responses and missed deadlines
/// never switch enforcement off (ask mode, docs/ASK_MODE.md); they are counted and shown. `record` is
/// cheap enough for the ES callback (lock + array store); percentiles are computed off the callback
/// path by `evaluate`, which the daemon calls from a timer.
///
/// `evaluate` also says whether p99 stays over the threshold (`isSlow`, for a log warning). An
/// evaluation breaches when the p99 over the window (with enough samples) and the p99 of the
/// responses recorded since the previous evaluation are both over the threshold; `isSlow` holds after
/// `breachesToWarn` breaches in a row and clears at the next evaluation that does not breach. A short
/// burst stays in the window long after it ended, so the second condition is what makes a breach
/// "persist".
public final class LatencyMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var ring: [UInt32]
    private var head = 0
    private var filled = 0
    private var misses = 0
    private var total = 0
    /// Responses, and those over the threshold, since the previous counting evaluation.
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
    public var breachesToWarn: Int

    public init(capacity: Int = 4096, p99ThresholdMicros: Double = 50_000, minimumSamples: Int = 50, breachesToWarn: Int = 1) {
        ring = Array(repeating: 0, count: max(16, capacity))
        self.threshold = p99ThresholdMicros
        self.minimumSamples = minimumSamples
        self.breachesToWarn = max(1, breachesToWarn)
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
        if missedDeadline { misses += 1 }
        lock.unlock()
    }

    /// p99 has been over the threshold for `breachesToWarn` evaluations in a row.
    public var isSlow: Bool {
        lock.lock(); defer { lock.unlock() }
        return breaches >= breachesToWarn
    }

    /// Stats only (status display); counts no breach.
    public func snapshot() -> LatencyStats { evaluate(count: false) }

    /// Computes stats over the window and counts a p99 breach (see `isSlow`). Returns the stats.
    @discardableResult
    public func evaluate() -> LatencyStats { evaluate(count: true) }

    private func evaluate(count: Bool) -> LatencyStats {
        lock.lock()
        let samples = Array(ring.prefix(filled))
        let misses = self.misses
        let total = self.total
        let recent = self.recent, recentSlow = self.recentSlow, threshold = self.threshold
        if count {
            self.recent = 0
            self.recentSlow = 0
        }
        lock.unlock()

        guard !samples.isEmpty else {
            if count { lock.lock(); breaches = 0; lock.unlock() }
            return LatencyStats(deadlineMisses: misses, totalResponses: total)
        }
        let sorted = samples.sorted()
        func rank(_ p: Double, _ count: Int) -> Int { min(max(Int((p * Double(count - 1)).rounded(.up)), 0), count - 1) }
        func percentile(_ p: Double) -> Double { Double(sorted[rank(p, sorted.count)]) }
        let stats = LatencyStats(samples: sorted.count, p50Micros: percentile(0.50), p99Micros: percentile(0.99),
                                 maxMicros: Double(sorted.last ?? 0), deadlineMisses: misses, totalResponses: total)
        if count {
            // The p99 of the `recent` responses is over the threshold when at least `recent - rank` are.
            let recentBreach = recent > 0 && recentSlow >= recent - rank(0.99, recent)
            let breach = sorted.count >= minimumSamples && stats.p99Micros > threshold && recentBreach
            lock.lock()
            breaches = breach ? breaches + 1 : 0
            lock.unlock()
        }
        return stats
    }

    /// Clears the window and the streak (when the user turns enforcement on: a fresh measurement).
    public func reset() {
        lock.lock()
        head = 0
        filled = 0
        misses = 0
        recent = 0
        recentSlow = 0
        breaches = 0
        lock.unlock()
    }
}
