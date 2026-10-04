import Foundation

/// One process instance (a fork), with its current image.
public struct ProcessNode: Sendable, Hashable {
    public let id: UInt64
    public var image: ProcessRecord
    /// Parent at fork time. Not updated when the process is reparented to launchd.
    public var parentID: UInt64?
    /// Agent ID of the current image, if it is a known AI agent.
    public var agentID: String?
    public var exitedAt: Date?
    public var lastSeen: Date
    var childCount: Int
}

/// In-memory process tree, seeded from a libproc snapshot and maintained from fork/exec/exit.
///
/// Children link to parents by internal node ID, not pid, so chains survive reparenting to
/// launchd and pid reuse. Exited processes stay as tombstones for `tombstoneTTL` (and while
/// they still have children) so late file events and descendants still resolve their ancestry.
///
/// Thread-safe. All lookups are memory-only; `parentResolver` (libproc in the daemon) is the only
/// escape hatch and does syscalls, never disk or XPC.
public final class ProcessTree: @unchecked Sendable {
    public typealias ParentResolver = @Sendable (Int32) -> ProcessRecord?

    private let lock = NSLock()
    private var nodes: [UInt64: ProcessNode] = [:]
    private var byPID: [Int32: [UInt64]] = [:]
    private var nextID: UInt64 = 1
    private let detector: AgentDetector
    private let normalizePath: @Sendable (String) -> String

    public var tombstoneTTL: TimeInterval
    public var maxDepth: Int
    public var maxNodes: Int
    public var parentResolver: ParentResolver?

    /// Start times closer than this are considered equal (sources round differently).
    static let startTimeTolerance: TimeInterval = 0.002

    public init(
        detector: AgentDetector,
        normalizePath: @escaping @Sendable (String) -> String = { $0 },
        tombstoneTTL: TimeInterval = 600,
        maxDepth: Int = 64,
        maxNodes: Int = 100_000,
        parentResolver: ParentResolver? = nil
    ) {
        self.detector = detector
        self.normalizePath = normalizePath
        self.tombstoneTTL = tombstoneTTL
        self.maxDepth = maxDepth
        self.maxNodes = maxNodes
        self.parentResolver = parentResolver
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return nodes.count
    }

    public var liveCount: Int {
        lock.lock(); defer { lock.unlock() }
        return nodes.values.filter { $0.exitedAt == nil }.count
    }

    // MARK: - Mutations

    /// Builds the initial tree from a snapshot of running processes.
    public func seed(_ records: [ProcessRecord], at time: Date) {
        lock.lock(); defer { lock.unlock() }
        var created: [UInt64] = []
        for r in records {
            let r = normalized(r)
            if currentNodeID(for: r, at: time) != nil { continue }
            created.append(createNode(r, parentID: nil, at: time))
        }
        for id in created {
            guard let node = nodes[id], node.parentID == nil else { continue }
            if let parent = findParentNode(for: node.image, excluding: id, at: time, allowResolver: false) {
                link(child: id, to: parent)
            }
        }
    }

    public func fork(parent: ProcessRecord, child: ProcessRecord, at time: Date) {
        lock.lock(); defer { lock.unlock() }
        let parentID = observeLocked(normalized(parent), at: time, depth: 0)
        let child = normalized(child)
        if let existing = currentNodeID(for: child, at: time), nodes[existing]?.exitedAt == nil || child.startTime != nil {
            // A file event from the child raced ahead of the fork event.
            update(existing, with: child, at: time)
            if nodes[existing]?.parentID != parentID { link(child: existing, to: parentID) }
            return
        }
        let id = createNode(child, parentID: nil, at: time)
        link(child: id, to: parentID)
    }

    public func exec(old: ProcessRecord, new: ProcessRecord, at time: Date) {
        lock.lock(); defer { lock.unlock() }
        let id = observeLocked(normalized(old), at: time, depth: 0)
        guard var node = nodes[id] else { return }
        var image = normalized(new)
        // Fork-scoped facts survive exec.
        if image.startTime == nil { image.startTime = node.image.startTime }
        if image.originalPPID == nil { image.originalPPID = node.image.originalPPID }
        node.image = image
        node.agentID = detector.detect(image)
        node.lastSeen = time
        node.exitedAt = nil
        nodes[id] = node
    }

    public func exit(_ process: ProcessRecord, at time: Date) {
        lock.lock(); defer { lock.unlock() }
        let p = normalized(process)
        guard let id = currentNodeID(for: p, at: time) else { return }
        nodes[id]?.exitedAt = time
        nodes[id]?.lastSeen = time
    }

    /// Ensures a node exists for an acting process and returns its ID.
    @discardableResult
    public func observe(_ process: ProcessRecord, at time: Date) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return observeLocked(normalized(process), at: time, depth: 0)
    }

    /// Removes old tombstones. Returns how many nodes were dropped.
    @discardableResult
    public func prune(now: Date) -> Int {
        lock.lock(); defer { lock.unlock() }
        var removed = 0
        func expired(_ n: ProcessNode) -> Bool {
            guard let e = n.exitedAt else { return false }
            return now.timeIntervalSince(e) > tombstoneTTL && n.childCount <= 0
        }
        // Worklist: removing a leaf tombstone may expire its parent. O(n), not O(n × depth), so a
        // deep fork-and-exit chain cannot hold the lock the AUTH path needs.
        var queue = nodes.values.filter(expired).map(\.id)
        while let id = queue.popLast() {
            guard let node = nodes[id] else { continue }
            remove(id)
            removed += 1
            if let p = node.parentID, let parent = nodes[p], expired(parent) { queue.append(p) }
        }
        if nodes.count > maxNodes {
            // Hard cap: evict childless tombstones first; exited ancestors are spliced out (their
            // children re-linked to the grandparent) so no live chain is cut, and exited agents with
            // live descendants are never evicted.
            let excess = nodes.count - maxNodes
            let victims = nodes.values
                .filter { $0.exitedAt != nil && !($0.agentID != nil && $0.childCount > 0) }
                .sorted { a, b in
                    let ka = a.childCount > 0 ? 1 : 0, kb = b.childCount > 0 ? 1 : 0
                    if ka != kb { return ka < kb }
                    return a.exitedAt! < b.exitedAt!
                }
                .prefix(excess)
            var children: [UInt64: [UInt64]] = [:]
            if victims.contains(where: { $0.childCount > 0 }) {
                for (id, n) in nodes { if let p = n.parentID { children[p, default: []].append(id) } }
            }
            for v in victims {
                guard let current = nodes[v.id] else { continue }
                for c in children[v.id] ?? [] where nodes[c]?.parentID == v.id {
                    nodes[c]?.parentID = current.parentID
                    if let gp = current.parentID {
                        nodes[gp]?.childCount += 1
                        children[gp, default: []].append(c)
                    }
                }
                nodes[v.id]?.childCount = 0
                remove(v.id)
                removed += 1
            }
        }
        return removed
    }

    // MARK: - Queries

    /// Chain for an acting process, leaf first, ending at launchd (or wherever ancestry is lost).
    public func chain(for process: ProcessRecord, at time: Date) -> [ProcessNode] {
        lock.lock(); defer { lock.unlock() }
        let id = observeLocked(normalized(process), at: time, depth: 0)
        return chainLocked(from: id)
    }

    public func chain(nodeID: UInt64) -> [ProcessNode] {
        lock.lock(); defer { lock.unlock() }
        return chainLocked(from: nodeID)
    }

    public func node(_ id: UInt64) -> ProcessNode? {
        lock.lock(); defer { lock.unlock() }
        return nodes[id]
    }

    /// Current node for a live pid, if known.
    public func node(pid: Int32) -> ProcessNode? {
        lock.lock(); defer { lock.unlock() }
        guard let id = byPID[pid]?.last else { return nil }
        return nodes[id]
    }

    // MARK: - Internals (lock held)

    private func normalized(_ r: ProcessRecord) -> ProcessRecord {
        var r = r
        r.executablePath = normalizePath(r.executablePath)
        return r
    }

    private func chainLocked(from id: UInt64) -> [ProcessNode] {
        var out: [ProcessNode] = []
        var visited = Set<UInt64>()
        var current: UInt64? = id
        // No depth cap: `visited` guarantees termination, and capping would let 70 nested shells hide
        // the agent at the top of the chain.
        while let c = current, let node = nodes[c], !visited.contains(c) {
            visited.insert(c)
            out.append(node)
            current = node.parentID
        }
        return out
    }

    private func observeLocked(_ p: ProcessRecord, at time: Date, depth: Int) -> UInt64 {
        if let id = currentNodeID(for: p, at: time) {
            update(id, with: p, at: time)
            if nodes[id]?.parentID == nil, p.pid > 1,
               let parent = findParentNode(for: p, excluding: id, at: time, allowResolver: depth < maxDepth) {
                link(child: id, to: parent)
            }
            return id
        }
        let id = createNode(p, parentID: nil, at: time)
        if p.pid > 1, let parent = findParentNode(for: p, excluding: id, at: time, allowResolver: depth < maxDepth, depth: depth) {
            link(child: id, to: parent)
        }
        return id
    }

    /// The node currently representing this process instance, if any.
    private func currentNodeID(for p: ProcessRecord, at time: Date) -> UInt64? {
        guard let ids = byPID[p.pid] else { return nil }
        for id in ids.reversed() {
            guard let node = nodes[id] else { continue }
            if let a = node.image.startTime, let b = p.startTime {
                if abs(a.timeIntervalSince(b)) <= ProcessTree.startTimeTolerance { return id }
                continue
            }
            // Without start times, the most recent instance is it — unless it exited long ago.
            if let exited = node.exitedAt, time.timeIntervalSince(exited) > tombstoneTTL { return nil }
            return id
        }
        return nil
    }

    private func update(_ id: UInt64, with p: ProcessRecord, at time: Date) {
        guard var node = nodes[id] else { return }
        let sameImage = node.image.executablePath == p.executablePath
            && (node.image.pidVersion == nil || p.pidVersion == nil || node.image.pidVersion == p.pidVersion)
        if sameImage {
            var merged = p.filling(from: node.image)
            // Keep argv from exec (sources other than exec do not carry it).
            if merged.argv == nil { merged.argv = node.image.argv }
            // Keep the fork-time parent relationship facts.
            if node.image.originalPPID != nil { merged.originalPPID = node.image.originalPPID }
            node.image = merged
            if node.agentID == nil, merged.argv != nil || merged.teamID != nil {
                node.agentID = detector.detect(merged)
            }
        } else if node.image.executablePath != p.executablePath {
            // We missed an exec: adopt the new image.
            var image = p
            if image.startTime == nil { image.startTime = node.image.startTime }
            node.image = image
            node.agentID = detector.detect(image)
        }
        node.lastSeen = time
        nodes[id] = node
    }

    private func createNode(_ p: ProcessRecord, parentID: UInt64?, at time: Date) -> UInt64 {
        let id = nextID
        nextID += 1
        nodes[id] = ProcessNode(
            id: id, image: p, parentID: nil, agentID: detector.detect(p),
            exitedAt: nil, lastSeen: time, childCount: 0)
        byPID[p.pid, default: []].append(id)
        if byPID[p.pid]!.count > 8 {
            // Keep only recent instances per pid in the index; older ones stay reachable via links.
            byPID[p.pid]!.removeFirst(byPID[p.pid]!.count - 8)
        }
        if let parentID { link(child: id, to: parentID) }
        return id
    }

    private func findParentNode(
        for p: ProcessRecord, excluding selfID: UInt64, at time: Date, allowResolver: Bool, depth: Int = 0
    ) -> UInt64? {
        var parentPID = p.ppid
        if parentPID == 1, let original = p.originalPPID, original > 1 {
            parentPID = original
        }
        guard parentPID > 0, parentPID != p.pid else { return nil }
        if parentPID == 1 { return launchdNode(at: time) }

        if let ids = byPID[parentPID] {
            for id in ids.reversed() where id != selfID {
                guard let node = nodes[id] else { continue }
                if let childStart = p.startTime {
                    if let parentStart = node.image.startTime,
                       parentStart.timeIntervalSince(childStart) > ProcessTree.startTimeTolerance {
                        continue // started after the child: a reused pid, not the parent
                    }
                    if let exited = node.exitedAt, exited.addingTimeInterval(ProcessTree.startTimeTolerance) < childStart {
                        continue // gone before the child existed
                    }
                }
                return id
            }
        }
        if allowResolver, let resolver = parentResolver, let record = resolver(parentPID), record.pid == parentPID {
            return observeLocked(normalized(record), at: time, depth: depth + 1)
        }
        // Reparented and the original parent is unknown: at least end the chain at launchd.
        if p.ppid == 1 { return launchdNode(at: time) }
        return nil
    }

    /// Chains end at launchd. Synthesized if the snapshot did not include it.
    private func launchdNode(at time: Date) -> UInt64 {
        if let id = byPID[1]?.last, nodes[id] != nil { return id }
        let record = ProcessRecord(pid: 1, ppid: 0, executablePath: "/sbin/launchd", isPlatformBinary: true)
        return createNode(record, parentID: nil, at: time)
    }

    private func link(child: UInt64, to parent: UInt64) {
        guard child != parent, nodes[child] != nil, nodes[parent] != nil else { return }
        // Refuse links that would create a cycle.
        var cursor: UInt64? = parent
        var steps = 0
        while let c = cursor, steps <= nodes.count {
            if c == child { return }
            cursor = nodes[c]?.parentID
            steps += 1
        }
        if let old = nodes[child]?.parentID { nodes[old]?.childCount -= 1 }
        nodes[child]?.parentID = parent
        nodes[parent]?.childCount += 1
    }

    private func remove(_ id: UInt64) {
        guard let node = nodes.removeValue(forKey: id) else { return }
        if let parent = node.parentID { nodes[parent]?.childCount -= 1 }
        if var ids = byPID[node.image.pid] {
            ids.removeAll { $0 == id }
            byPID[node.image.pid] = ids.isEmpty ? nil : ids
        }
    }
}

extension Array where Element == ProcessNode {
    /// Nearest agent in the chain (leaf first), including the leaf itself.
    public var nearestAgent: String? { first(where: { $0.agentID != nil })?.agentID }

    /// "launchd → Terminal → zsh → cat"
    public func displayString(separator: String = " → ") -> String {
        reversed().map { $0.image.name }.joined(separator: separator)
    }
}
