import crypto from 'node:crypto';
import {
  DEFAULT_EDGE_PROFILES,
  IdentityGraphDocumentSchema,
  type AttackHop,
  type AttackPathResult,
  type GraphEdge,
  type GraphNode,
  type IdentityDomain,
  type IdentityGraphDocument,
  type PathRoutingMode,
  type RemediationChokepoint,
  type ShadowAdminFinding,
} from './schema.js';

/**
 * Deterministic binary min-heap priority queue for Dijkstra's algorithm.
 */
class MinPriorityQueue<T> {
  private readonly heap: Array<{ item: T; priority: number }> = [];

  public get size(): number {
    return this.heap.length;
  }

  public enqueue(item: T, priority: number): void {
    this.heap.push({ item, priority });
    this.bubbleUp(this.heap.length - 1);
  }

  public dequeue(): { item: T; priority: number } | undefined {
    if (this.heap.length === 0) {
      return undefined;
    }
    const top = this.heap[0]!;
    const bottom = this.heap.pop()!;
    if (this.heap.length > 0) {
      this.heap[0] = bottom;
      this.sinkDown(0);
    }
    return top;
  }

  private bubbleUp(index: number): void {
    let current = index;
    while (current > 0) {
      const parent = (current - 1) >> 1;
      if (this.heap[current]!.priority >= this.heap[parent]!.priority) {
        break;
      }
      const tmp = this.heap[current]!;
      this.heap[current] = this.heap[parent]!;
      this.heap[parent] = tmp;
      current = parent;
    }
  }

  private sinkDown(index: number): void {
    let current = index;
    const length = this.heap.length;
    while (true) {
      const left = (current << 1) + 1;
      const right = left + 1;
      let smallest = current;

      if (left < length && this.heap[left]!.priority < this.heap[smallest]!.priority) {
        smallest = left;
      }
      if (right < length && this.heap[right]!.priority < this.heap[smallest]!.priority) {
        smallest = right;
      }
      if (smallest === current) {
        break;
      }
      const tmp = this.heap[current]!;
      this.heap[current] = this.heap[smallest]!;
      this.heap[smallest] = tmp;
      current = smallest;
    }
  }
}

/**
 * Core directed multi-domain identity graph representation.
 */
export class ShadowGraph {
  public readonly metadata: IdentityGraphDocument['metadata'];
  private readonly nodesById: Map<string, GraphNode> = new Map();
  private readonly edgesById: Map<string, GraphEdge> = new Map();
  private readonly outgoingEdges: Map<string, GraphEdge[]> = new Map();
  private readonly incomingEdges: Map<string, GraphEdge[]> = new Map();

  private constructor(doc: IdentityGraphDocument) {
    this.metadata = doc.metadata;

    for (const node of doc.nodes) {
      this.nodesById.set(node.id, node);
      this.outgoingEdges.set(node.id, []);
      this.incomingEdges.set(node.id, []);
    }

    for (const rawEdge of doc.edges) {
      const profile = DEFAULT_EDGE_PROFILES[rawEdge.type];
      const normalizedEdge: GraphEdge = {
        id: rawEdge.id,
        source: rawEdge.source,
        target: rawEdge.target,
        type: rawEdge.type,
        opsecNoise: rawEdge.opsecNoise ?? profile.opsecNoise,
        exploitComplexity: rawEdge.exploitComplexity ?? profile.exploitComplexity,
        description: rawEdge.description ?? profile.description,
      };

      this.edgesById.set(normalizedEdge.id, normalizedEdge);
      this.outgoingEdges.get(normalizedEdge.source)!.push(normalizedEdge);
      this.incomingEdges.get(normalizedEdge.target)!.push(normalizedEdge);
    }
  }

  /**
   * Validates and constructs a ShadowGraph instance from an untrusted input object.
   */
  public static fromDocument(untrustedInput: unknown): ShadowGraph {
    const parsed = IdentityGraphDocumentSchema.parse(untrustedInput);
    return new ShadowGraph(parsed);
  }

  public getNode(id: string): GraphNode | undefined {
    return this.nodesById.get(id);
  }

  public getEdge(id: string): GraphEdge | undefined {
    return this.edgesById.get(id);
  }

  public getNodes(): GraphNode[] {
    return Array.from(this.nodesById.values());
  }

  public getEdges(): GraphEdge[] {
    return Array.from(this.edgesById.values());
  }

  public getOutgoingEdges(nodeId: string): readonly GraphEdge[] {
    return this.outgoingEdges.get(nodeId) ?? [];
  }

  public getIncomingEdges(nodeId: string): readonly GraphEdge[] {
    return this.incomingEdges.get(nodeId) ?? [];
  }

  public getTierZeroNodes(): GraphNode[] {
    return this.getNodes().filter((n) => n.isTierZero);
  }

  public getCompromisedNodes(): GraphNode[] {
    return this.getNodes().filter((n) => n.isCompromised);
  }
}

/**
 * Computes the positive directional step weight w(e) for a given routing mode.
 */
export function computeEdgeStepWeight(edge: GraphEdge, mode: PathRoutingMode): number {
  switch (mode) {
    case 'stealth':
      return edge.opsecNoise;
    case 'hops':
      // Prioritize minimal hop count (1000 per hop) with tie-breaking on OpSec noise and complexity
      return 1000 + edge.opsecNoise * 0.01 + edge.exploitComplexity * 0.001;
    case 'hybrid':
      // Balanced multi-objective weight: 60% OpSec noise, 30% complexity, +10 base hop penalty
      return Number((0.6 * edge.opsecNoise + 0.3 * edge.exploitComplexity + 10).toFixed(4));
  }
}

/**
 * Priority-queue Dijkstra algorithm with cycle immunity that discovers optimal multi-hop
 * escalation paths from `sourceId` to `targetTierZeroIds`.
 *
 * Returns discovered shortest paths sorted by ascending `totalWeight`.
 */
export function findShortestAttackPaths(
  graph: ShadowGraph,
  sourceId: string,
  targetTierZeroIds?: readonly string[],
  mode: PathRoutingMode = 'stealth'
): AttackPathResult[] {
  const sourceNode = graph.getNode(sourceId);
  if (!sourceNode) {
    throw new Error(`Source node "${sourceId}" does not exist in graph.`);
  }

  const resolvedTargetIds =
    targetTierZeroIds && targetTierZeroIds.length > 0
      ? targetTierZeroIds
      : graph.getTierZeroNodes().map((n) => n.id);

  const targetSet = new Set<string>(resolvedTargetIds);
  if (targetSet.size === 0) {
    return [];
  }

  const dist = new Map<string, number>();
  const prevEdge = new Map<string, GraphEdge>();
  const settled = new Set<string>();
  const pq = new MinPriorityQueue<string>();

  dist.set(sourceId, 0);
  pq.enqueue(sourceId, 0);

  while (pq.size > 0) {
    const current = pq.dequeue();
    if (!current) {
      break;
    }

    const u = current.item;
    if (settled.has(u)) {
      continue;
    }
    settled.add(u);

    const currentDist = dist.get(u)!;
    const outgoing = graph.getOutgoingEdges(u);

    for (const edge of outgoing) {
      const v = edge.target;
      // Cycle immunity: settled nodes already have a strictly optimal path due to positive weights
      if (settled.has(v)) {
        continue;
      }

      const stepWeight = computeEdgeStepWeight(edge, mode);
      const candidateDist = Number((currentDist + stepWeight).toFixed(6));
      const existingDist = dist.get(v);

      if (existingDist === undefined || candidateDist < existingDist) {
        dist.set(v, candidateDist);
        prevEdge.set(v, edge);
        pq.enqueue(v, candidateDist);
      }
    }
  }

  const results: AttackPathResult[] = [];

  for (const targetId of targetSet) {
    if (targetId === sourceId) {
      continue;
    }
    if (!prevEdge.has(targetId)) {
      continue;
    }

    const targetNode = graph.getNode(targetId);
    if (!targetNode) {
      continue;
    }

    // Reconstruct path from target back to source with cycle guard
    const reverseEdges: GraphEdge[] = [];
    const visitedReconstruction = new Set<string>();
    let cursor = targetId;

    while (cursor !== sourceId) {
      if (visitedReconstruction.has(cursor)) {
        break;
      }
      visitedReconstruction.add(cursor);
      const edge = prevEdge.get(cursor);
      if (!edge) {
        break;
      }
      reverseEdges.push(edge);
      cursor = edge.source;
    }

    if (cursor !== sourceId || reverseEdges.length === 0) {
      continue;
    }

    const forwardEdges = reverseEdges.reverse();
    const hops: AttackHop[] = [];
    const domainsSet = new Set<IdentityDomain>([sourceNode.domain]);
    let totalOpsecNoise = 0;
    let maxSingleHopNoise = 0;
    let totalExploitComplexity = 0;
    let totalWeight = 0;

    for (const edge of forwardEdges) {
      const sNode = graph.getNode(edge.source)!;
      const tNode = graph.getNode(edge.target)!;
      const stepWeight = computeEdgeStepWeight(edge, mode);
      const profile = DEFAULT_EDGE_PROFILES[edge.type];

      domainsSet.add(sNode.domain);
      domainsSet.add(tNode.domain);

      totalOpsecNoise += edge.opsecNoise;
      if (edge.opsecNoise > maxSingleHopNoise) {
        maxSingleHopNoise = edge.opsecNoise;
      }
      totalExploitComplexity += edge.exploitComplexity;
      totalWeight = Number((totalWeight + stepWeight).toFixed(4));

      hops.push({
        edgeId: edge.id,
        sourceNode: sNode,
        targetNode: tNode,
        edgeType: edge.type,
        opsecNoise: edge.opsecNoise,
        exploitComplexity: edge.exploitComplexity,
        stepWeight,
        mitreTechniqueId: profile.mitreTechniqueId,
        description: edge.description,
      });
    }

    const domainsTraversed = Array.from(domainsSet);
    results.push({
      sourceNode,
      targetNode,
      mode,
      hops,
      hopCount: hops.length,
      totalWeight,
      totalOpsecNoise,
      averageOpsecNoise: Number((totalOpsecNoise / hops.length).toFixed(2)),
      maxSingleHopNoise,
      totalExploitComplexity,
      domainsTraversed,
      isCrossDomain: domainsTraversed.length > 1,
    });
  }

  results.sort((a, b) => {
    if (a.totalWeight !== b.totalWeight) {
      return a.totalWeight - b.totalWeight;
    }
    if (a.hopCount !== b.hopCount) {
      return a.hopCount - b.hopCount;
    }
    return a.targetNode.id.localeCompare(b.targetNode.id);
  });

  return results;
}

/**
 * Reverse BFS/DFS from all Tier-0 principals (`Domain Admins`, `Enterprise Admins`,
 * `AWS Root/AdminRole`, `ClusterAdmin`) to identify non-privileged principals who hold
 * transitive control over Tier-0 without being members of any privileged Tier-0 group.
 */
export function findShadowAdmins(
  graph: ShadowGraph,
  mode: PathRoutingMode = 'stealth'
): ShadowAdminFinding[] {
  const tierZeroNodes = graph.getTierZeroNodes();
  if (tierZeroNodes.length === 0) {
    return [];
  }

  const tierZeroIds = tierZeroNodes.map((n) => n.id);
  const tierZeroSet = new Set<string>(tierZeroIds);

  // Step 1: Identify principals that are legitimately privileged solely via direct/nested MemberOf into Tier-0
  const legitimateTierZeroMembers = new Set<string>(tierZeroIds);
  const memberQueue: string[] = [...tierZeroIds];

  while (memberQueue.length > 0) {
    const currentId = memberQueue.shift()!;
    for (const incoming of graph.getIncomingEdges(currentId)) {
      if (incoming.type === 'MemberOf' && !legitimateTierZeroMembers.has(incoming.source)) {
        legitimateTierZeroMembers.add(incoming.source);
        memberQueue.push(incoming.source);
      }
    }
  }

  // Step 2: Reverse BFS over all attack edges from Tier-0 nodes to find all nodes with a path to Tier-0
  const reachableToTierZero = new Set<string>(tierZeroIds);
  const reverseQueue: string[] = [...tierZeroIds];

  while (reverseQueue.length > 0) {
    const currentId = reverseQueue.shift()!;
    for (const incoming of graph.getIncomingEdges(currentId)) {
      if (!reachableToTierZero.has(incoming.source)) {
        reachableToTierZero.add(incoming.source);
        reverseQueue.push(incoming.source);
      }
    }
  }

  // Step 3: For each non-Tier-0, non-legitimate-member principal, compute optimal escalation path
  const findings: ShadowAdminFinding[] = [];

  for (const nodeId of reachableToTierZero) {
    if (tierZeroSet.has(nodeId) || legitimateTierZeroMembers.has(nodeId)) {
      continue;
    }

    const node = graph.getNode(nodeId);
    if (!node) {
      continue;
    }

    const paths = findShortestAttackPaths(graph, nodeId, tierZeroIds, mode);
    if (paths.length === 0) {
      continue;
    }

    const bestPath = paths[0]!;
    const minHops = paths.reduce((min, p) => (p.hopCount < min ? p.hopCount : min), bestPath.hopCount);
    const reachableTargets = paths.map((p) => p.targetNode.id);

    // Stealth score [1..99]: higher when average OpSec noise is low
    const rawStealth = Math.max(1, Math.min(99, Math.round(100 - bestPath.averageOpsecNoise)));
    const chainSummary = bestPath.hops
      .map((h) => `${h.sourceNode.label} -[${h.edgeType}]-> ${h.targetNode.label}`)
      .join(' | ');

    findings.push({
      principal: node,
      shortestPathToTierZero: bestPath,
      reachableTierZeroTargets: reachableTargets,
      minHopsToTierZero: minHops,
      stealthScore: rawStealth,
      escalationVectorSummary: chainSummary,
    });
  }

  // Sort Shadow Admins by highest stealth score (quietest escalation first), then fewest hops, then ID
  findings.sort((a, b) => {
    if (a.shortestPathToTierZero.totalWeight !== b.shortestPathToTierZero.totalWeight) {
      return a.shortestPathToTierZero.totalWeight - b.shortestPathToTierZero.totalWeight;
    }
    if (a.minHopsToTierZero !== b.minHopsToTierZero) {
      return a.minHopsToTierZero - b.minHopsToTierZero;
    }
    return a.principal.id.localeCompare(b.principal.id);
  });

  return findings;
}

/**
 * Computes edge betweenness centrality across all discovered shortest attack paths from non-Tier-0
 * principals to Tier-0 assets to rank which single ACL/edge removal severs the highest percentage
 * of Tier-0 compromise paths.
 */
export function calculateRemediationChokepoints(
  graph: ShadowGraph,
  topN: number = 10,
  mode: PathRoutingMode = 'stealth'
): RemediationChokepoint[] {
  const safeTopN = Math.max(1, Math.min(500, Math.floor(topN)));
  const tierZeroNodes = graph.getTierZeroNodes();
  if (tierZeroNodes.length === 0) {
    return [];
  }

  const tierZeroIds = tierZeroNodes.map((n) => n.id);
  const nonTierZeroNodes = graph.getNodes().filter((n) => !n.isTierZero);

  const allAttackPaths: AttackPathResult[] = [];
  for (const source of nonTierZeroNodes) {
    const paths = findShortestAttackPaths(graph, source.id, tierZeroIds, mode);
    for (const p of paths) {
      // Only include paths that involve at least one non-MemberOf attack primitive
      const hasAbusablePrimitive = p.hops.some((h) => h.edgeType !== 'MemberOf');
      if (hasAbusablePrimitive) {
        allAttackPaths.push(p);
      }
    }
  }

  const totalPathsAnalyzed = allAttackPaths.length;
  if (totalPathsAnalyzed === 0) {
    return [];
  }

  const edgePathCounts = new Map<string, number>();

  for (const path of allAttackPaths) {
    const uniqueEdgesInPath = new Set<string>();
    for (const hop of path.hops) {
      uniqueEdgesInPath.add(hop.edgeId);
    }
    for (const edgeId of uniqueEdgesInPath) {
      edgePathCounts.set(edgeId, (edgePathCounts.get(edgeId) ?? 0) + 1);
    }
  }

  const candidates: Omit<RemediationChokepoint, 'rank'>[] = [];

  for (const [edgeId, pathsSevered] of edgePathCounts.entries()) {
    const edge = graph.getEdge(edgeId);
    if (!edge) {
      continue;
    }
    const sourceNode = graph.getNode(edge.source)!;
    const targetNode = graph.getNode(edge.target)!;
    const profile = DEFAULT_EDGE_PROFILES[edge.type];

    const betweennessCentrality = Number((pathsSevered / totalPathsAnalyzed).toFixed(4));
    const impactPercentage = Number(((pathsSevered / totalPathsAnalyzed) * 100).toFixed(2));
    const isStructuralGroupMembership = edge.type === 'MemberOf';

    // Actionable non-MemberOf attack primitives receive a priority multiplier over structural group memberships
    const actionabilityMultiplier = isStructuralGroupMembership ? 0.65 : 1.0;
    const stealthHazardMultiplier = Number((1 + (100 - edge.opsecNoise) / 200).toFixed(4));
    const remediationPriorityScore = Number(
      (impactPercentage * actionabilityMultiplier * stealthHazardMultiplier).toFixed(2)
    );

    candidates.push({
      edge,
      sourceNode,
      targetNode,
      pathsSevered,
      totalPathsAnalyzed,
      betweennessCentrality,
      impactPercentage,
      isStructuralGroupMembership,
      remediationPriorityScore,
      mitreTechniqueId: profile.mitreTechniqueId,
      remediationGuidance: profile.remediationGuidance,
    });
  }

  candidates.sort((a, b) => {
    if (b.remediationPriorityScore !== a.remediationPriorityScore) {
      return b.remediationPriorityScore - a.remediationPriorityScore;
    }
    if (b.pathsSevered !== a.pathsSevered) {
      return b.pathsSevered - a.pathsSevered;
    }
    return a.edge.id.localeCompare(b.edge.id);
  });

  return candidates.slice(0, safeTopN).map((item, idx) => ({
    rank: idx + 1,
    ...item,
  }));
}

/**
 * Cryptographic integrity helper: computes a SHA-256 HMAC digest over an analysis report
 * and performs constant-time signature verification using `crypto.timingSafeEqual`.
 */
export function signReportPayload(payload: string, secretKey: string): string {
  const keyBuf = Buffer.alloc(Buffer.byteLength(secretKey, 'utf8'));
  keyBuf.write(secretKey, 'utf8');
  try {
    return crypto.createHmac('sha256', keyBuf).update(payload, 'utf8').digest('hex');
  } finally {
    // Zeroize sensitive secret buffer immediately after cryptographic operation
    keyBuf.fill(0);
  }
}

export function verifyReportSignature(
  payload: string,
  providedHexSignature: string,
  secretKey: string
): boolean {
  const expectedHex = signReportPayload(payload, secretKey);
  const expectedBuf = Buffer.alloc(Buffer.byteLength(expectedHex, 'utf8'));
  expectedBuf.write(expectedHex, 'utf8');

  const providedBuf = Buffer.alloc(Buffer.byteLength(providedHexSignature, 'utf8'));
  providedBuf.write(providedHexSignature, 'utf8');

  try {
    if (expectedBuf.length !== providedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  } finally {
    expectedBuf.fill(0);
    providedBuf.fill(0);
  }
}
