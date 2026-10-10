import Foundation

/// One process instance (a fork), with its current image.
public struct ProcessNode: Sendable, Hashable {
    public let id: UInt64
    public var image: ProcessRecord
    /// Parent at fork time. Not updated when the process is reparented to launchd. nil while that
    /// parent is unknown: the chain then stops here instead of reaching launchd.
    public var parentID: UInt64?
    /// AI agent this process is: its current image is a known agent, or an earlier image was and the
    /// process exec'd something else since (an agent that runs `exec cat key` is still the agent).
    public var agentID: String? {
        didSet { if agentID != nil { everAgent = true } }
    }
    /// The agent identity is held from an earlier image (see `agentID`); `heldAgentTeamID` is that
    /// image's team.
    var agentHeld = false
    var heldAgentTeamID: String?
    /// Team ID of the image that made this process an agent.
    public var agentTeamID: String? { agentHeld ? heldAgentTeamID : image.teamID }
    public var exitedAt: Date?
    public var lastSeen: Date
    var childCount: Int
    /// The image comes from a libproc snapshot (seed or parent resolver), not from an event: it has
    /// no code signing data and its platform flag is guessed from the path. The next event replaces it.
    var fromSnapshot: Bool
    /// What lies above this node (see `Ancestry`).
    var ancestry: Ancestry
    /// An ancestor between this node and its parent was evicted by the node cap (`prune`): the chain
    /// through here skips it, so it does not count as reaching launchd.
    var ancestorEvicted = false
    /// Some image of this process was an AI agent. Its descendants may have recorded it as their only
    /// mark for that agent (see `recordedAncestors`), so the node cap never evicts it while it has
    /// children, even after an exec to something else.
    var everAgent = false
    /// pidversions this process instance was seen with (each exec gives a new one), latest last.
    var pidVersions: [UInt32] = []
}

/// What lies above a node, so that a chain query costs the same however deep the tree is: a process
/// running as the user can nest fork-and-exit generations by the tens of thousands (exited ancestors
/// stay as tombstones while they have children). Recorded from the parent when the node is linked;
/// recomputed for a whole subtree when an ancestor is relinked or unlinked, or turns out to be an AI
/// agent. Each mark is a node and its distance above this node; the node is read back at query time.
struct Ancestry: Sendable, Hashable {
    struct Mark: Sendable, Hashable {
        var id: UInt64
        var distance: Int
    }

    struct AgentMark: Sendable, Hashable {
        var mark: Mark
        var agentID: String
        var teamID: String?
    }

    /// Nearest ancestor inside an `.app` bundle or that is an AI agent (Attributor steps 1-2).
    var attributable: Mark?
    /// AI agent ancestors, nearest first, one per agent and team.
    var agents: [AgentMark] = []
    /// Nearest ancestor that is not a platform binary (Attributor step 3).
    var nonPlatform: Mark?
    /// Topmost known ancestor below launchd (Attributor step 4).
    var top: Mark?
}

/// In-memory process tree, seeded from a libproc snapshot and maintained from fork/exec/exit.
///
/// Children link to parents by internal node ID, not pid, so chains survive reparenting to
/// launchd and pid reuse. Exited processes stay as tombstones for `tombstoneTTL` (and while
/// they still have children) so late file events and descendants still resolve their ancestry.
/// A parent is the process that forked the child (`originalPPID`); a process whose fork-time parent
/// is unknown is left unlinked (ancestry unknown), never attached to launchd.
///
/// Thread-safe. All lookups are memory-only; `parentResolver` (libproc in the daemon) is the only
/// escape hatch and does syscalls, never disk or XPC.
public final class ProcessTree: @unchecked Sendable {
    public typealias ParentResolver = @Sendable (Int32) -> ProcessRecord?

    private let lock = NSLock()
    private var nodes: [UInt64: ProcessNode] = [:]
    private var byPID: [Int32: [UInt64]] = [:]
    private var children: [UInt64: Set<UInt64>] = [:]
    /// Unlinked nodes whose fork-time parent pid the resolver could not give: it is dead, so whoever
    /// holds that pid later started after the child too. Not asked again on every AUTH decision.
    private var unresolvable: [UInt64: Int32] = [:]
    private var nextID: UInt64 = 1
    private let detector: AgentDetector
    private let normalizePath: @Sendable (String) -> String
    /// While seeding: links do not refresh descendants; everything is recomputed once at the end.
    private var deferAncestry = false
    /// Bumped when a process with an AI agent in its ancestry appears, changes or exits.
    private var agentGeneration: UInt64 = 0

    public var tombstoneTTL: TimeInterval
    /// How deep the parent resolver may recurse for one lookup.
    public var maxDepth: Int
    public var maxNodes: Int
    /// Links a chain query walks. Past it, the chain continues with the nodes `Ancestry` recorded for
    /// the rest (agents, the responsible app, the topmost process) and does not end at launchd.
    public var chainLimit: Int
    public var parentResolver: ParentResolver?

    /// Start times closer than this are considered equal (sources round differently).
    static let startTimeTolerance: TimeInterval = 0.002
    /// Distinct agent ancestors (agent, team) a node records. Bounded by the agent catalog in practice.
    static let maxAgentMarks = 32

    public init(
        detector: AgentDetector,
        normalizePath: @escaping @Sendable (String) -> String = { $0 },
        tombstoneTTL: TimeInterval = 600,
        maxDepth: Int = 64,
        maxNodes: Int = 100_000,
        chainLimit: Int = 64,
        parentResolver: ParentResolver? = nil
    ) {
        self.detector = detector
        self.normalizePath = normalizePath
        self.tombstoneTTL = tombstoneTTL
        self.maxDepth = maxDepth
        self.maxNodes = maxNodes
        self.chainLimit = max(1, chainLimit)
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

    /// Builds the initial tree from a snapshot of running processes (libproc: no fork-time parent, so
    /// a process reparented to launchd stays unlinked until an event tells who started it).
    public func seed(_ records: [ProcessRecord], at time: Date) {
        lock.lock(); defer { lock.unlock() }
        var created: [UInt64] = []
        for r in records {
            let r = normalized(r)
            if currentNodeID(for: r, at: time) != nil { continue }
            created.append(createNode(r, at: time, fromSnapshot: true))
        }
        deferAncestry = true
        for id in created {
            guard let node = nodes[id], node.parentID == nil else { continue }
            if let parent = findParentNode(for: node.image, excluding: id, at: time, allowResolver: false) {
                link(child: id, to: parent)
            }
        }
        deferAncestry = false
        rebuildAncestry()
    }

    public func fork(parent: ProcessRecord, child: ProcessRecord, at time: Date) {
        lock.lock(); defer { lock.unlock() }
        let parentID = observeLocked(normalized(parent), at: time, depth: 0)
        let child = normalized(child)
        if let existing = currentNodeID(for: child, at: time), nodes[existing]?.exitedAt == nil || child.startTime != nil {
            // A file event from the child raced ahead of the fork event.
            update(existing, with: child, at: time, fromSnapshot: false)
            if nodes[existing]?.parentID != parentID {
                link(child: existing, to: parentID)
            } else {
                // Linked by that file event, perhaps before the parent's exec was seen (see exec()).
                refreshAncestry(of: existing)
            }
            return
        }
        let id = createNode(child, at: time, fromSnapshot: false)
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
        adopt(image, into: &node)
        ProcessTree.note(image.pidVersion, in: &node)
        node.fromSnapshot = false
        node.lastSeen = time
        node.exitedAt = nil
        nodes[id] = node
        // What a process records about its ancestors is taken from its parent when it is linked. A
        // file event can link it before the process client has delivered its parent's exec (an agent
        // starting up). The process client delivers that exec before this process's own fork and exec,
        // so re-reading the parent here, O(1), brings it up to date; descendants follow at their own.
        refreshAncestry(of: id)
    }

    public func exit(_ process: ProcessRecord, at time: Date) {
        lock.lock(); defer { lock.unlock() }
        let p = normalized(process)
        guard let id = currentNodeID(for: p, at: time) else { return }
        nodes[id]?.exitedAt = time
        nodes[id]?.lastSeen = time
        if let node = nodes[id], ProcessTree.hasAgents(node) { agentGeneration &+= 1 }
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
            // live descendants are never evicted (nor a process that was one before an exec). Descendants keep their recorded ancestry; marks of
            // evicted nodes are skipped when read. A chain with a spliced-out link is incomplete: it
            // never counts as reaching launchd (an exited app's helper is not all-Apple).
            let excess = nodes.count - maxNodes
            let victims = nodes.values
                .filter { $0.exitedAt != nil && !($0.everAgent && $0.childCount > 0) }
                .sorted { a, b in
                    let ka = a.childCount > 0 ? 1 : 0, kb = b.childCount > 0 ? 1 : 0
                    if ka != kb { return ka < kb }
                    return a.exitedAt! < b.exitedAt!
                }
                .prefix(excess)
            for v in victims {
                guard let current = nodes[v.id] else { continue }
                for c in children[v.id] ?? [] where nodes[c]?.parentID == v.id {
                    setParent(c, current.parentID)
                    nodes[c]?.ancestorEvicted = true
                }
                remove(v.id)
                removed += 1
            }
        }
        return removed
    }

    // MARK: - Queries

    /// Chain for an acting process, leaf first, ending at launchd, or wherever ancestry is lost. At
    /// most `chainLimit` links are walked; a longer chain continues with the nodes its ancestry
    /// recorded (agents, responsible app, topmost process), in chain order, and does not end at launchd.
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

    // MARK: - Agent ancestry across restarts

    /// Changes whenever a process with an AI agent in its ancestry appears, changes or exits: callers
    /// save `agentAncestry()` again only then.
    public var agentAncestryGeneration: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return agentGeneration
    }

    /// The AI agent ancestry of live processes, to be restored after a daemon restart: libproc has no
    /// fork-time parent, so a job an agent started whose shell has exited would come back with its
    /// ancestry unknown and the agent gone. At most `limit` processes (the oldest first: long-running
    /// jobs are the ones still there after a restart) and `AgentAncestryRecord.maxAgents` agents each.
    public func agentAncestry(limit: Int = AgentAncestryRecord.maxRecords) -> [AgentAncestryRecord] {
        lock.lock(); defer { lock.unlock() }
        var out: [AgentAncestryRecord] = []
        for node in nodes.values where node.exitedAt == nil && node.image.pid > 1 && ProcessTree.hasAgents(node) {
            guard let start = node.image.startTime else { continue }
            let parent = node.parentID.flatMap { nodes[$0] }.flatMap { $0.image.isSystemRoot ? nil : $0 }
            var agents: [AgentAncestryRecord.Link] = []
            for mark in node.ancestry.agents.prefix(AgentAncestryRecord.maxAgents) {
                guard let n = nodes[mark.mark.id], !n.image.isSystemRoot else { continue }
                agents.append(AgentAncestryRecord.Link(n, agentID: mark.agentID, agentTeamID: mark.teamID))
            }
            out.append(AgentAncestryRecord(
                pid: node.image.pid, startTime: start, agentID: node.agentID, agentTeamID: node.agentID == nil ? nil : node.agentTeamID,
                parent: parent.map { AgentAncestryRecord.Link($0, agentID: $0.agentID, agentTeamID: $0.agentID == nil ? nil : $0.agentTeamID) },
                agentsAbove: agents))
        }
        out.sort { ($0.startTime, $0.pid) < ($1.startTime, $1.pid) }
        return Array(out.prefix(max(0, limit)))
    }

    /// After `seed`: gives processes that are still running the AI agents they had before the restart.
    /// A process that was an agent is one again (libproc has no code identity to recognise it by). A
    /// process whose fork-time parent is gone, so it is left unlinked, gets placeholders above it: its
    /// parent as last seen, then the agents above that, nearest first; an agent that is still running is
    /// linked to as itself. Placeholders count as exited and never as a chain that reaches launchd, so
    /// the restored chain carries the agents but no trust. They are reachable only through the processes
    /// restored below them: not by pid, so a process that holds one of their pids now, or a child of it,
    /// is never taken for them. Records that match no running process (by pid and start time) are ignored.
    public func restoreAgentAncestry(_ records: [AgentAncestryRecord], at time: Date) {
        lock.lock(); defer { lock.unlock() }
        struct Instance: Hashable { var pid: Int32; var start: Date }
        // One placeholder per process instance, however many records name it (the siblings of a job).
        var placeholders: [Instance: UInt64] = [:]
        for record in records.prefix(AgentAncestryRecord.maxRecords) {
            guard let id = liveNode(pid: record.pid, startTime: record.startTime), var node = nodes[id] else { continue }
            // The agent it was, with its team, even if libproc's image now looks like another agent or like
            // the same one without a team (it exec'd that: see `adopt`).
            if let agent = record.agentID, node.agentID != agent || node.agentTeamID != record.agentTeamID {
                node.agentID = agent
                node.agentHeld = true
                node.heldAgentTeamID = record.agentTeamID
                nodes[id] = node
                refreshAncestry(below: id)
            }
            guard node.parentID == nil else { continue }
            var links = Array(record.agentsAbove.prefix(AgentAncestryRecord.maxAgents))
            if let parent = record.parent, !(links.first.map { $0.pid == parent.pid && $0.startTime == parent.startTime } ?? false) {
                links.insert(parent, at: 0)
            }
            guard !links.isEmpty else { continue }
            // Top down: each placeholder is linked below the one farther up; a running process is used as is.
            var above: UInt64?
            for entry in links.reversed() {
                let instance = entry.startTime.map { Instance(pid: entry.pid, start: $0) }
                if let instance, let live = liveNode(pid: instance.pid, startTime: instance.start) {
                    above = live
                    continue
                }
                if let instance, let existing = placeholders[instance], nodes[existing] != nil {
                    if let above, nodes[existing]?.parentID == nil { link(child: existing, to: above) }
                    above = existing
                    continue
                }
                let ghost = createNode(entry.record, at: time, fromSnapshot: true, indexed: false)
                nodes[ghost]?.exitedAt = time
                nodes[ghost]?.ancestorEvicted = true
                nodes[ghost]?.agentID = entry.agentID
                nodes[ghost]?.agentHeld = entry.agentID != nil
                nodes[ghost]?.heldAgentTeamID = entry.agentTeamID
                if let instance { placeholders[instance] = ghost }
                if let above { link(child: ghost, to: above) }
                above = ghost
            }
            if let above, above != id {
                nodes[id]?.ancestorEvicted = true
                link(child: id, to: above)
            }
        }
        agentGeneration &+= 1
    }

    // MARK: - Internals (lock held)

    /// The live node for a process instance, by pid and start time.
    private func liveNode(pid: Int32, startTime: Date) -> UInt64? {
        byPID[pid]?.last { id in
            guard let n = nodes[id], n.exitedAt == nil, let s = n.image.startTime else { return false }
            return abs(s.timeIntervalSince(startTime)) <= ProcessTree.startTimeTolerance
        }
    }

    private func normalized(_ r: ProcessRecord) -> ProcessRecord {
        var r = r
        r.executablePath = normalizePath(r.executablePath)
        return r
    }

    private func chainLocked(from id: UInt64) -> [ProcessNode] {
        var out: [ProcessNode] = []
        var current: UInt64? = id
        while let c = current, let node = nodes[c] {
            if node.image.isSystemRoot {
                out.append(node)
                return out
            }
            if out.count == chainLimit {
                // Cut short (no walk proportional to the depth an attacker can build). Capping without
                // the recorded ancestry would let 70 nested shells hide the agent at the top.
                return out + recordedAncestors(of: out[out.count - 1], excluding: Set(out.map(\.id)))
            }
            out.append(node)
            current = node.parentID
        }
        return out
    }

    /// The nodes `node`'s ancestry recorded, nearest first, without launchd. An agent ancestor keeps
    /// the identity (agent and team) it had when recorded: only the nearest instance of each agent (and
    /// team) is recorded, so if that identity could change later, the farther, real agent it stood in
    /// for would be lost.
    private func recordedAncestors(of node: ProcessNode, excluding walked: Set<UInt64>) -> [ProcessNode] {
        let a = node.ancestry
        var marks = a.agents.map(\.mark)
        for m in [a.attributable, a.nonPlatform, a.top] { if let m { marks.append(m) } }
        marks.sort { $0.distance < $1.distance }
        var recordedAgent: [UInt64: Ancestry.AgentMark] = [:]
        for agent in a.agents { recordedAgent[agent.mark.id] = agent }
        var seen = walked
        var out: [ProcessNode] = []
        for m in marks where seen.insert(m.id).inserted {
            guard var n = nodes[m.id], !n.image.isSystemRoot else { continue }
            if let agent = recordedAgent[m.id], n.agentID != agent.agentID || n.agentTeamID != agent.teamID {
                n.agentID = agent.agentID
                n.agentHeld = true
                n.heldAgentTeamID = agent.teamID
            }
            out.append(n)
        }
        return out
    }

    /// What a child of `parent` has above it.
    private func ancestry(below parent: ProcessNode) -> Ancestry {
        if parent.image.isSystemRoot { return Ancestry() }
        var a = parent.ancestry
        func up(_ m: Ancestry.Mark) -> Ancestry.Mark { Ancestry.Mark(id: m.id, distance: m.distance + 1) }
        a.attributable = a.attributable.map(up)
        a.nonPlatform = a.nonPlatform.map(up)
        a.top = a.top.map(up) ?? Ancestry.Mark(id: parent.id, distance: 1)
        a.agents = a.agents.map { Ancestry.AgentMark(mark: up($0.mark), agentID: $0.agentID, teamID: $0.teamID) }
        let here = Ancestry.Mark(id: parent.id, distance: 1)
        if parent.agentID != nil || parent.image.outermostAppBundle != nil { a.attributable = here }
        if !parent.image.isPlatformBinary { a.nonPlatform = here }
        if let agent = parent.agentID {
            let team = parent.agentTeamID
            a.agents.removeAll { $0.agentID == agent && $0.teamID == team }
            a.agents.insert(Ancestry.AgentMark(mark: here, agentID: agent, teamID: team), at: 0)
            if a.agents.count > ProcessTree.maxAgentMarks { a.agents.removeLast(a.agents.count - ProcessTree.maxAgentMarks) }
        }
        return a
    }

    private func observeLocked(_ p: ProcessRecord, at time: Date, depth: Int, fromSnapshot: Bool = false) -> UInt64 {
        if let id = currentNodeID(for: p, at: time) {
            let learnsOrigin = nodes[id]?.image.originalPPID == nil && p.originalPPID != nil
            update(id, with: p, at: time, fromSnapshot: fromSnapshot)
            if learnsOrigin, let node = nodes[id], let parent = node.parentID,
               nodes[parent]?.image.pid != ProcessTree.forkParentPID(of: node.image) {
                // Linked before the fork-time parent was known (libproc reports the current ppid, which
                // for a traced process is its debugger): look again.
                setParent(id, nil)
                refreshAncestry(of: id)
                refreshAncestry(below: id)
            }
            if nodes[id]?.parentID == nil, p.pid > 1,
               let parent = findParentNode(for: nodes[id]?.image ?? p, excluding: id, at: time,
                                           allowResolver: depth < maxDepth, depth: depth) {
                link(child: id, to: parent)
            }
            return id
        }
        let id = createNode(p, at: time, fromSnapshot: fromSnapshot)
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

    private func update(_ id: UInt64, with p: ProcessRecord, at time: Date, fromSnapshot: Bool) {
        guard var node = nodes[id] else { return }
        let wasAgent = node.agentID != nil
        let sameImage = node.image.executablePath == p.executablePath
            && (node.image.pidVersion == nil || p.pidVersion == nil || node.image.pidVersion == p.pidVersion)
        if sameImage {
            var merged = p.filling(from: node.image)
            // Keep argv from exec (sources other than exec do not carry it).
            if merged.argv == nil { merged.argv = node.image.argv }
            // Keep the fork-time parent relationship facts.
            if node.image.originalPPID != nil { merged.originalPPID = node.image.originalPPID }
            // A platform flag guessed from the path (libproc) never outlives the one an event reports,
            // and never overrides it.
            if node.fromSnapshot && !fromSnapshot {
                merged.isPlatformBinary = p.isPlatformBinary
            } else if !node.fromSnapshot && fromSnapshot {
                merged.isPlatformBinary = node.image.isPlatformBinary
            }
            node.image = merged
            node.fromSnapshot = node.fromSnapshot && fromSnapshot
            if node.agentID == nil, merged.argv != nil || merged.teamID != nil {
                node.agentID = detector.detect(merged)
            }
        } else if node.image.executablePath != p.executablePath {
            // We missed an exec: adopt the new image.
            var image = p
            if image.startTime == nil { image.startTime = node.image.startTime }
            adopt(image, into: &node)
            node.fromSnapshot = fromSnapshot
        }
        ProcessTree.note(p.pidVersion, in: &node)
        node.lastSeen = time
        nodes[id] = node
        if sameImage && !wasAgent && node.agentID != nil && node.childCount > 0 {
            // Only now recognised as an agent (code identity arrived after a snapshot): what it
            // started must carry it.
            refreshAncestry(below: id)
        }
    }

    /// A new image for the same process instance (exec). A process that was an AI agent stays that agent,
    /// with its team, whatever it execs: exec replaces the program, not who is running it. That includes
    /// a program that looks like another agent, or like the same agent from another team: a copy of cat
    /// named `codex`, or run as `exec -a claude`, would otherwise shed the agent and its team-pinned
    /// rules. Not when it was only a fork-time copy of its agent parent (the agent forking a shell for a
    /// command): the parent already puts that agent in the chain, and the new image is what it started.
    private func adopt(_ image: ProcessRecord, into node: inout ProcessNode) {
        let previous = node.agentID.map { ($0, node.agentTeamID) }
        let parent = node.parentID.flatMap { nodes[$0] }
        node.image = image
        let detected = detector.detect(image)
        if let (agent, team) = previous, !(parent?.agentID == agent && parent?.agentTeamID == team) {
            node.agentID = agent
            node.agentHeld = true
            // A team that was not known (the agent was recognised from a libproc image, which has no code
            // identity, or it has none) is taken from a new image of the same agent; a known one stays.
            node.heldAgentTeamID = team ?? (detected == agent ? image.teamID : nil)
        } else if let detected {
            node.agentID = detected
            node.agentHeld = false
            node.heldAgentTeamID = nil
        } else {
            node.agentID = nil
        }
    }

    /// `indexed`: found by pid (every node but the placeholders `restoreAgentAncestry` makes).
    private func createNode(_ p: ProcessRecord, at time: Date, fromSnapshot: Bool, indexed: Bool = true) -> UInt64 {
        let id = nextID
        nextID += 1
        let agentID = detector.detect(p)
        nodes[id] = ProcessNode(
            id: id, image: p, parentID: nil, agentID: agentID,
            exitedAt: nil, lastSeen: time, childCount: 0, fromSnapshot: fromSnapshot, ancestry: Ancestry(),
            everAgent: agentID != nil, pidVersions: p.pidVersion.map { [$0] } ?? [])
        guard indexed else { return id }
        byPID[p.pid, default: []].append(id)
        if byPID[p.pid]!.count > 8 {
            // Keep only recent instances per pid in the index; older ones stay reachable via links.
            byPID[p.pid]!.removeFirst(byPID[p.pid]!.count - 8)
        }
        return id
    }

    /// The pid of the process that forked `p`; nil when unknown. ppid alone only says who adopted it:
    /// launchd for a reparented process (libproc has no fork-time parent), a debugger for a traced one.
    static func forkParentPID(of p: ProcessRecord) -> Int32? {
        if let original = p.originalPPID { return original > 0 ? original : nil }
        return p.ppid > 1 ? p.ppid : nil
    }

    /// The exact execution (pid, pidversion) of the process that forked `p`, when the source names it.
    /// parent_audit_token stands in for ppid, so after reparenting it may name launchd, and under a
    /// debugger the debugger: it is only taken when its pid is the fork-time parent's.
    static func parentExecution(of p: ProcessRecord) -> ProcessToken? {
        guard let token = p.parentToken, let parent = forkParentPID(of: p), token.pid == parent, parent > 1 else { return nil }
        return token
    }

    /// Keeps the pidversions a process instance was seen with (bounded: a process execs a few times).
    private static func note(_ version: UInt32?, in node: inout ProcessNode) {
        guard let version, node.pidVersions.last != version else { return }
        node.pidVersions.removeAll { $0 == version }
        node.pidVersions.append(version)
        if node.pidVersions.count > 8 { node.pidVersions.removeFirst(node.pidVersions.count - 8) }
    }

    private func findParentNode(
        for p: ProcessRecord, excluding selfID: UInt64, at time: Date, allowResolver: Bool, depth: Int = 0
    ) -> UInt64? {
        // Unknown (reparented, or the original parent was never seen and cannot be resolved): no
        // parent at all, so the chain does not reach launchd and grants no trust.
        guard let parentPID = ProcessTree.forkParentPID(of: p), parentPID != p.pid else { return nil }
        if parentPID == 1 { return launchdNode(at: time) }
        var exact = ProcessTree.parentExecution(of: p)

        // A candidate that fits the start times but was only seen with other pidversions than the one
        // the source names: it may have exec'd since (an event not processed yet), or be an earlier
        // holder of the pid whose exit was not seen yet. libproc tells which, below. Older candidates
        // are not taken before it is settled.
        var unconfirmed: UInt64?
        if let ids = byPID[parentPID] {
            if let token = exact, let id = ids.last(where: { $0 != selfID && nodes[$0]?.pidVersions.contains(token.pidVersion) == true }) {
                // The very execution the source names, unless it started after the child: then the token
                // names a later holder of the pid that adopted the child (a debugger that got the pid
                // after the parent exited), and says nothing about who forked it.
                if !ProcessTree.startedAfter(nodes[id]?.image.startTime, p.startTime) { return id }
                exact = nil
            }
            for id in ids.reversed() where id != selfID {
                guard let node = nodes[id] else { continue }
                if let childStart = p.startTime {
                    if ProcessTree.startedAfter(node.image.startTime, childStart) {
                        continue // started after the child: a reused pid, not the parent
                    }
                    if let exited = node.exitedAt, exited.addingTimeInterval(ProcessTree.startTimeTolerance) < childStart {
                        continue // gone before the child existed
                    }
                }
                if exact != nil, !node.pidVersions.isEmpty || unconfirmed != nil {
                    if unconfirmed == nil { unconfirmed = id }
                    continue
                }
                return id
            }
        }
        if allowResolver, unresolvable[selfID] != parentPID, let resolver = parentResolver {
            if let record = resolver(parentPID), record.pid == parentPID, !ProcessTree.startedAfter(record.startTime, p.startTime) {
                // libproc reports whoever holds the pid now: one that started after the child reused it.
                // Its start time finds the node it is, if any (an unconfirmed candidate that exec'd).
                return observeLocked(normalized(record), at: time, depth: depth + 1, fromSnapshot: true)
            }
            if nodes[selfID] != nil { unresolvable[selfID] = parentPID }
        }
        // Not settled by libproc: the candidate stands, as it would without a pidversion.
        return unconfirmed
    }

    /// `start` is later than `childStart` (beyond rounding): a process holding the parent's pid that
    /// cannot be the parent.
    private static func startedAfter(_ start: Date?, _ childStart: Date?) -> Bool {
        guard let start, let childStart else { return false }
        return start.timeIntervalSince(childStart) > startTimeTolerance
    }

    /// Chains end at launchd. Synthesized if the snapshot did not include it.
    private func launchdNode(at time: Date) -> UInt64 {
        if let id = byPID[1]?.last, nodes[id] != nil { return id }
        let record = ProcessRecord(pid: 1, ppid: 0, executablePath: "/sbin/launchd", isPlatformBinary: true)
        return createNode(record, at: time, fromSnapshot: false)
    }

    private func link(child: UInt64, to parent: UInt64) {
        guard child != parent, let c = nodes[child], nodes[parent] != nil, c.parentID != parent else { return }
        if c.childCount == 0 {
            // A childless node cannot close a cycle: O(1), whatever the depth (forks hold the lock the
            // AUTH path needs).
            setParent(child, parent)
            refreshAncestry(of: child)
            return
        }
        if deferAncestry {
            // Seeding: every ancestry is recomputed once at the end; only refuse a cycle.
            if isAncestor(child, of: parent) { return }
            setParent(child, parent)
            return
        }
        // Relinking a node with descendants: refuse a link below them, then update what they record.
        let below = descendants(of: child)
        if below.set.contains(parent) { return }
        setParent(child, parent)
        refreshAncestry(of: child)
        refreshAncestry(of: below.order)
    }

    private func isAncestor(_ ancestor: UInt64, of id: UInt64) -> Bool {
        var cursor: UInt64? = id
        var steps = 0
        while let c = cursor, steps <= nodes.count {
            if c == ancestor { return true }
            cursor = nodes[c]?.parentID
            steps += 1
        }
        return false
    }

    private func setParent(_ child: UInt64, _ parent: UInt64?) {
        if let old = nodes[child]?.parentID {
            nodes[old]?.childCount -= 1
            children[old]?.remove(child)
            if children[old]?.isEmpty == true { children[old] = nil }
        }
        nodes[child]?.parentID = parent
        if let parent {
            nodes[parent]?.childCount += 1
            children[parent, default: []].insert(child)
        }
    }

    /// Descendants of `id` (not `id` itself), parents before children.
    private func descendants(of id: UInt64) -> (order: [UInt64], set: Set<UInt64>) {
        var order: [UInt64] = []
        var seen: Set<UInt64> = [id]
        var i = 0
        var frontier = Array(children[id] ?? [])
        while true {
            for c in frontier where seen.insert(c).inserted { order.append(c) }
            guard i < order.count else { break }
            frontier = Array(children[order[i]] ?? [])
            i += 1
        }
        seen.remove(id)
        return (order, seen)
    }

    private func refreshAncestry(of id: UInt64) {
        guard let node = nodes[id] else { return }
        let parent = node.parentID.flatMap { nodes[$0] }
        let a = parent.map(ancestry(below:)) ?? Ancestry()
        nodes[id]?.ancestry = a
        if node.agentID != nil || !a.agents.isEmpty || !node.ancestry.agents.isEmpty { agentGeneration &+= 1 }
    }

    static func hasAgents(_ node: ProcessNode) -> Bool { node.agentID != nil || !node.ancestry.agents.isEmpty }

    private func refreshAncestry(of ordered: [UInt64]) {
        for id in ordered { refreshAncestry(of: id) }
    }

    /// After `id` was unlinked or became an agent. O(subtree), once per such change.
    private func refreshAncestry(below id: UInt64) {
        if deferAncestry { return }
        refreshAncestry(of: descendants(of: id).order)
    }

    /// Recomputes every node's ancestry, roots first. O(n); used after seeding.
    private func rebuildAncestry() {
        let roots = nodes.values.filter { n in n.parentID.map { nodes[$0] == nil } ?? true }.map(\.id)
        for r in roots {
            refreshAncestry(of: r)
            refreshAncestry(of: descendants(of: r).order)
        }
    }

    private func remove(_ id: UInt64) {
        guard let node = nodes[id] else { return }
        if node.parentID != nil { setParent(id, nil) }
        nodes.removeValue(forKey: id)
        children[id] = nil
        unresolvable[id] = nil
        if var ids = byPID[node.image.pid] {
            ids.removeAll { $0 == id }
            byPID[node.image.pid] = ids.isEmpty ? nil : ids
        }
    }
}

/// What a running process had above it: kept across daemon restarts (`ProcessTree.agentAncestry`).
public struct AgentAncestryRecord: Codable, Hashable, Sendable {
    /// Bounds on what is kept and restored.
    public static let maxAgents = 8
    public static let maxRecords = 512

    /// One process above it, as last seen (no argv).
    public struct Link: Codable, Hashable, Sendable {
        public var pid: Int32
        public var startTime: Date?
        public var executablePath: String
        public var signingID: String?
        public var teamID: String?
        public var isPlatformBinary: Bool
        public var agentID: String?
        public var agentTeamID: String?

        init(_ node: ProcessNode, agentID: String?, agentTeamID: String?) {
            pid = node.image.pid
            startTime = node.image.startTime
            executablePath = node.image.executablePath
            signingID = node.image.signingID
            teamID = node.image.teamID
            isPlatformBinary = node.image.isPlatformBinary
            self.agentID = agentID
            self.agentTeamID = agentTeamID
        }

        public init(pid: Int32, startTime: Date?, executablePath: String, signingID: String? = nil, teamID: String? = nil,
                    isPlatformBinary: Bool = false, agentID: String? = nil, agentTeamID: String? = nil) {
            self.pid = pid
            self.startTime = startTime
            self.executablePath = executablePath
            self.signingID = signingID
            self.teamID = teamID
            self.isPlatformBinary = isPlatformBinary
            self.agentID = agentID
            self.agentTeamID = agentTeamID
        }

        /// A placeholder image: no fork-time parent, nothing about it is current.
        var record: ProcessRecord {
            ProcessRecord(pid: pid, ppid: 0, executablePath: executablePath, signingID: signingID, teamID: teamID,
                          isPlatformBinary: isPlatformBinary, startTime: startTime)
        }
    }

    /// The process: pid and fork time.
    public var pid: Int32
    public var startTime: Date
    /// The AI agent it is itself, if any.
    public var agentID: String?
    public var agentTeamID: String?
    /// Its fork-time parent.
    public var parent: Link?
    /// The AI agents above it, nearest first.
    public var agentsAbove: [Link]

    public init(pid: Int32, startTime: Date, agentID: String? = nil, agentTeamID: String? = nil, parent: Link? = nil,
                agentsAbove: [Link] = []) {
        self.pid = pid
        self.startTime = startTime
        self.agentID = agentID
        self.agentTeamID = agentTeamID
        self.parent = parent
        self.agentsAbove = agentsAbove
    }
}

extension Array where Element == ProcessNode {
    /// Nearest agent in the chain (leaf first), including the leaf itself.
    public var nearestAgent: String? { first(where: { $0.agentID != nil })?.agentID }

    /// The chain reaches launchd: every ancestor is known. A chain whose ancestry was lost (a parent
    /// never seen and not resolvable, a reparented process whose fork-time parent is unknown, a link
    /// spliced out by the node cap) or cut short (`ProcessTree.chainLimit`) does not.
    public var reachesLaunchd: Bool { last?.image.isSystemRoot == true && !contains(where: \.ancestorEvicted) }

    /// "launchd → Terminal → zsh → cat"
    public func displayString(separator: String = " → ") -> String {
        reversed().map { $0.image.name }.joined(separator: separator)
    }
}
