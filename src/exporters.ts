import {
  DEFAULT_EDGE_PROFILES,
  type AttackPathResult,
  type RemediationChokepoint,
  type ShadowAdminFinding,
} from './schema.js';
import type { ShadowGraph } from './graph-engine.js';

/**
 * Strictly escapes untrusted strings before interpolation into HTML or SVG attributes/text.
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Sanitizes string values for Neo4j Cypher single-quoted string literals.
 */
export function escapeCypherString(input: string): string {
  return input.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r?\n/g, ' ');
}

function padRight(value: string, width: number): string {
  if (value.length >= width) {
    return value.slice(0, width - 1) + ' ';
  }
  return value + ' '.repeat(width - value.length);
}

/**
 * Generates an authoritative terminal ASCII report with attack-chain visualizations,
 * Shadow Admin tables, and remediation chokepoint rankings.
 */
export function renderAsciiReport(
  graph: ShadowGraph,
  attackPaths: readonly AttackPathResult[],
  shadowAdmins: readonly ShadowAdminFinding[],
  chokepoints: readonly RemediationChokepoint[]
): string {
  const lines: string[] = [];
  const hr = '='.repeat(96);
  const subHr = '-'.repeat(96);

  lines.push(hr);
  lines.push('SHADOW-GRAPH: MULTI-DOMAIN IDENTITY ATTACK PATH & CHOKEPOINT ANALYSIS REPORT');
  lines.push(hr);
  lines.push(`Dataset Name     : ${graph.metadata.name}`);
  lines.push(`Environment      : ${graph.metadata.environment}`);
  lines.push(`Version          : ${graph.metadata.version}`);
  lines.push(`Collected At     : ${graph.metadata.collectedAt}`);
  lines.push(
    `Graph Topology   : ${graph.getNodes().length} Nodes | ${graph.getEdges().length} Directed Edges | ${graph.getTierZeroNodes().length} Tier-0 Assets`
  );
  lines.push(`Shadow Admins    : ${shadowAdmins.length} Non-Tier-0 Principals with Transitive Tier-0 Control`);
  lines.push(hr);
  lines.push('');

  // Section 1: Attack Path Chains
  lines.push('[1] OPTIMAL MULTI-HOP ESCALATION PATHS TO TIER-0');
  lines.push(subHr);
  if (attackPaths.length === 0) {
    lines.push('No viable attack paths discovered for the selected source principal(s).');
  } else {
    for (let i = 0; i < Math.min(attackPaths.length, 5); i++) {
      const path = attackPaths[i]!;
      lines.push(
        `Path #${i + 1} [Mode: ${path.mode.toUpperCase()}] | Source: ${path.sourceNode.label} (${path.sourceNode.id}) -> Target: ${path.targetNode.label} (${path.targetNode.id})`
      );
      lines.push(
        `Metrics : Hops=${path.hopCount} | TotalWeight=${path.totalWeight} | AvgOpSecNoise=${path.averageOpsecNoise} | CrossDomain=${path.isCrossDomain ? 'YES' : 'NO'} (${path.domainsTraversed.join(' -> ')})`
      );
      for (let stepIdx = 0; stepIdx < path.hops.length; stepIdx++) {
        const hop = path.hops[stepIdx]!;
        const indent = '  '.repeat(stepIdx + 1);
        lines.push(
          `${indent}[Hop ${stepIdx + 1}] (${hop.sourceNode.domain}:${hop.sourceNode.kind}) ${hop.sourceNode.label}`
        );
        lines.push(
          `${indent}   |--[${hop.edgeType} | Noise:${hop.opsecNoise} | Complexity:${hop.exploitComplexity} | ${hop.mitreTechniqueId}]--> (${hop.targetNode.domain}:${hop.targetNode.kind}) ${hop.targetNode.label}`
        );
      }
      lines.push('');
    }
  }

  // Section 2: Shadow Admins Table
  lines.push('[2] SHADOW ADMIN ENUMERATION (NON-PRIVILEGED PRINCIPALS WITH TIER-0 REACHABILITY)');
  lines.push(subHr);
  lines.push(
    padRight('PRINCIPAL ID', 26) +
      padRight('DOMAIN', 18) +
      padRight('KIND', 16) +
      padRight('MIN HOPS', 10) +
      padRight('STEALTH', 10) +
      'PRIMARY ESCALATION VECTOR'
  );
  lines.push(subHr);
  for (const sa of shadowAdmins.slice(0, 15)) {
    lines.push(
      padRight(sa.principal.id, 26) +
        padRight(sa.principal.domain, 18) +
        padRight(sa.principal.kind, 16) +
        padRight(String(sa.minHopsToTierZero), 10) +
        padRight(`${sa.stealthScore}/100`, 10) +
        sa.escalationVectorSummary
    );
  }
  lines.push('');

  // Section 3: Remediation Chokepoints
  lines.push('[3] REMEDIATION CHOKEPOINTS (BETWEENNESS CENTRALITY RANKING)');
  lines.push(subHr);
  lines.push(
    padRight('RANK', 6) +
      padRight('EDGE ID', 16) +
      padRight('PRIMITIVE', 21) +
      padRight('SEVERED', 12) +
      padRight('IMPACT %', 11) +
      padRight('MITRE', 11) +
      'SOURCE -> TARGET'
  );
  lines.push(subHr);
  for (const cp of chokepoints) {
    lines.push(
      padRight(`#${cp.rank}`, 6) +
        padRight(cp.edge.id, 16) +
        padRight(cp.edge.type, 21) +
        padRight(`${cp.pathsSevered}/${cp.totalPathsAnalyzed}`, 12) +
        padRight(`${cp.impactPercentage.toFixed(1)}%`, 11) +
        padRight(cp.mitreTechniqueId, 11) +
        `${cp.sourceNode.label} -> ${cp.targetNode.label}`
    );
    lines.push(`      Remediation: ${cp.remediationGuidance}`);
  }
  lines.push(hr);

  return lines.join('\n');
}

/**
 * Generates a standalone, self-contained HTML5 + interactive SVG attack graph report
 * with strict HTML entity escaping and Content-Security-Policy enforcement.
 */
export function generateHtmlReport(
  graph: ShadowGraph,
  attackPaths: readonly AttackPathResult[],
  shadowAdmins: readonly ShadowAdminFinding[],
  chokepoints: readonly RemediationChokepoint[]
): string {
  const nodes = graph.getNodes();
  const edges = graph.getEdges();

  // Compute deterministic layered coordinates by domain and Tier-0 status for clean SVG rendering
  const domainColumns: Record<string, number> = {
    ActiveDirectory: 140,
    LinuxHost: 420,
    KubernetesRBAC: 700,
    CloudIAM: 980,
  };

  const domainCounts: Record<string, number> = {
    ActiveDirectory: 0,
    LinuxHost: 0,
    KubernetesRBAC: 0,
    CloudIAM: 0,
  };

  const nodeCoords = new Map<string, { x: number; y: number }>();
  for (const node of nodes) {
    const baseCol = domainColumns[node.domain] ?? 200;
    const rowIdx = domainCounts[node.domain] ?? 0;
    domainCounts[node.domain] = rowIdx + 1;
    const xOffset = node.isTierZero ? 75 : (rowIdx % 2) * 55;
    const x = baseCol + xOffset;
    const y = 70 + rowIdx * 52;
    nodeCoords.set(node.id, { x, y });
  }

  const maxRows = Math.max(...Object.values(domainCounts), 8);
  const svgHeight = Math.max(540, 100 + maxRows * 52);
  const svgWidth = 1180;

  const highlightedEdgeIds = new Set<string>();
  if (attackPaths.length > 0) {
    for (const hop of attackPaths[0]!.hops) {
      highlightedEdgeIds.add(hop.edgeId);
    }
  }

  const svgEdges = edges
    .map((e) => {
      const s = nodeCoords.get(e.source);
      const t = nodeCoords.get(e.target);
      if (!s || !t) {
        return '';
      }
      const isHighlighted = highlightedEdgeIds.has(e.id);
      const stroke = isHighlighted ? '#ef4444' : '#475569';
      const strokeWidth = isHighlighted ? '2.6' : '1.2';
      const midX = ((s.x + t.x) / 2).toFixed(1);
      const midY = ((s.y + t.y) / 2 - 6).toFixed(1);
      return `<g class="edge-group">
        <line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${stroke}" stroke-width="${strokeWidth}" marker-end="url(#arrow)" />
        <text x="${midX}" y="${midY}" fill="#94a3b8" font-size="9" text-anchor="middle">${escapeHtml(e.type)} (${e.opsecNoise})</text>
      </g>`;
    })
    .join('\n');

  const svgNodes = nodes
    .map((n) => {
      const coord = nodeCoords.get(n.id)!;
      const fill = n.isTierZero ? '#dc2626' : n.isCompromised ? '#f59e0b' : '#1e293b';
      const stroke = n.isTierZero ? '#fca5a5' : n.isCompromised ? '#fde68a' : '#38bdf8';
      return `<g class="node-group" transform="translate(${coord.x}, ${coord.y})">
        <circle r="16" fill="${fill}" stroke="${stroke}" stroke-width="2" />
        <text y="28" fill="#e2e8f0" font-size="10" font-weight="600" text-anchor="middle">${escapeHtml(n.label)}</text>
        <title>${escapeHtml(n.id)} | ${escapeHtml(n.domain)} | ${escapeHtml(n.kind)}${n.isTierZero ? ' [TIER-0]' : ''}</title>
      </g>`;
    })
    .join('\n');

  const chokepointRows = chokepoints
    .map(
      (cp) => `<tr>
        <td>#${cp.rank}</td>
        <td><code>${escapeHtml(cp.edge.id)}</code></td>
        <td><strong>${escapeHtml(cp.edge.type)}</strong></td>
        <td>${escapeHtml(cp.sourceNode.label)} &rarr; ${escapeHtml(cp.targetNode.label)}</td>
        <td>${cp.pathsSevered} / ${cp.totalPathsAnalyzed} (${cp.impactPercentage.toFixed(1)}%)</td>
        <td><code>${escapeHtml(cp.mitreTechniqueId)}</code></td>
        <td>${escapeHtml(cp.remediationGuidance)}</td>
      </tr>`
    )
    .join('\n');

  const shadowRows = shadowAdmins
    .map(
      (sa) => `<tr>
        <td><code>${escapeHtml(sa.principal.id)}</code></td>
        <td>${escapeHtml(sa.principal.label)}</td>
        <td>${escapeHtml(sa.principal.domain)}</td>
        <td>${escapeHtml(sa.principal.kind)}</td>
        <td>${sa.minHopsToTierZero}</td>
        <td>${sa.stealthScore}/100</td>
        <td>${escapeHtml(sa.escalationVectorSummary)}</td>
      </tr>`
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Shadow-Graph Security Report - ${escapeHtml(graph.metadata.name)}</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #ef4444;
    }
    body {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }
    h1, h2 {
      letter-spacing: -0.02em;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
    }
    .card-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }
    .card-value {
      font-size: 20px;
      font-weight: 700;
      margin-top: 4px;
    }
    .svg-container {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow-x: auto;
      margin-bottom: 24px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 28px;
      font-size: 13px;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: var(--panel);
      color: var(--accent);
    }
    code {
      color: #fde68a;
    }
  </style>
</head>
<body>
  <h1>SHADOW-GRAPH // MULTI-DOMAIN IDENTITY ATTACK PATH REPORT</h1>
  <div class="meta-grid">
    <div class="card">
      <div class="card-label">Dataset</div>
      <div class="card-value">${escapeHtml(graph.metadata.name)}</div>
    </div>
    <div class="card">
      <div class="card-label">Nodes / Directed Edges</div>
      <div class="card-value">${nodes.length} / ${edges.length}</div>
    </div>
    <div class="card">
      <div class="card-label">Tier-0 Assets</div>
      <div class="card-value">${graph.getTierZeroNodes().length}</div>
    </div>
    <div class="card">
      <div class="card-label">Shadow Admins Discovered</div>
      <div class="card-value">${shadowAdmins.length}</div>
    </div>
  </div>

  <h2>Interactive Multi-Domain Topology &amp; Highlighted Shortest Escalation Vector</h2>
  <div class="svg-container">
    <svg width="${svgWidth}" height="${svgHeight}" viewBox="0 0 ${svgWidth} ${svgHeight}" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
        </marker>
      </defs>
      <text x="140" y="30" fill="#38bdf8" font-size="13" font-weight="700" text-anchor="middle">ACTIVE DIRECTORY</text>
      <text x="420" y="30" fill="#38bdf8" font-size="13" font-weight="700" text-anchor="middle">LINUX SERVERS</text>
      <text x="700" y="30" fill="#38bdf8" font-size="13" font-weight="700" text-anchor="middle">KUBERNETES RBAC</text>
      <text x="980" y="30" fill="#38bdf8" font-size="13" font-weight="700" text-anchor="middle">CLOUD IAM</text>
      ${svgEdges}
      ${svgNodes}
    </svg>
  </div>

  <h2>Remediation Chokepoints (Edge Betweenness Centrality)</h2>
  <table>
    <thead>
      <tr>
        <th>Rank</th>
        <th>Edge ID</th>
        <th>Primitive</th>
        <th>Vector</th>
        <th>Paths Severed</th>
        <th>MITRE ATT&amp;CK</th>
        <th>Actionable Remediation</th>
      </tr>
    </thead>
    <tbody>
      ${chokepointRows}
    </tbody>
  </table>

  <h2>Discovered Shadow Admins (Transitive Tier-0 Control)</h2>
  <table>
    <thead>
      <tr>
        <th>Principal ID</th>
        <th>Label</th>
        <th>Domain</th>
        <th>Kind</th>
        <th>Min Hops</th>
        <th>Stealth Score</th>
        <th>Shortest Escalation Chain</th>
      </tr>
    </thead>
    <tbody>
      ${shadowRows}
    </tbody>
  </table>
</body>
</html>`;
}

/**
 * Exports the identity graph and Shadow Admin annotations as Neo4j Cypher statements.
 */
export function generateCypherExport(
  graph: ShadowGraph,
  shadowAdmins: readonly ShadowAdminFinding[],
  chokepoints: readonly RemediationChokepoint[]
): string {
  const shadowSet = new Set<string>(shadowAdmins.map((sa) => sa.principal.id));
  const chokepointRankMap = new Map<string, number>(
    chokepoints.map((cp) => [cp.edge.id, cp.rank])
  );

  const statements: string[] = [
    '// Neo4j Cypher Export generated by shadow-graph',
    `// Dataset: ${escapeCypherString(graph.metadata.name)} (${escapeCypherString(graph.metadata.version)})`,
    'CREATE CONSTRAINT identity_node_id IF NOT EXISTS FOR (n:IdentityNode) REQUIRE n.id IS UNIQUE;',
    '',
  ];

  for (const node of graph.getNodes()) {
    const isShadowAdmin = shadowSet.has(node.id);
    statements.push(
      `MERGE (n:IdentityNode:${node.kind} {id: '${escapeCypherString(node.id)}'}) ` +
        `SET n.label = '${escapeCypherString(node.label)}', ` +
        `n.domain = '${escapeCypherString(node.domain)}', ` +
        `n.isTierZero = ${node.isTierZero}, ` +
        `n.isCompromised = ${node.isCompromised}, ` +
        `n.isShadowAdmin = ${isShadowAdmin};`
    );
  }

  statements.push('');

  for (const edge of graph.getEdges()) {
    const cpRank = chokepointRankMap.get(edge.id) ?? 0;
    statements.push(
      `MATCH (s:IdentityNode {id: '${escapeCypherString(edge.source)}'}), ` +
        `(t:IdentityNode {id: '${escapeCypherString(edge.target)}'}) ` +
        `MERGE (s)-[r:${edge.type} {id: '${escapeCypherString(edge.id)}'}]->(t) ` +
        `SET r.opsecNoise = ${edge.opsecNoise}, ` +
        `r.exploitComplexity = ${edge.exploitComplexity}, ` +
        `r.chokepointRank = ${cpRank};`
    );
  }

  return statements.join('\n');
}

/**
 * Generates a static analysis SARIF v2.1.0 report representing discovered Shadow Admin paths
 * and high-impact remediation chokepoints for GitHub Code Scanning / Security tab integration.
 */
export function generateSarifReport(
  graph: ShadowGraph,
  shadowAdmins: readonly ShadowAdminFinding[],
  chokepoints: readonly RemediationChokepoint[],
  datasetArtifactUri: string = 'samples/ad-hybrid-enterprise.json'
): Record<string, unknown> {
  const rules = Object.values(DEFAULT_EDGE_PROFILES).map((profile) => ({
    id: `SG-${profile.type.toUpperCase()}`,
    name: `AttackPrimitive${profile.type}`,
    shortDescription: {
      text: `${profile.type} privilege escalation vector (${profile.mitreTechniqueId})`,
    },
    fullDescription: {
      text: profile.description,
    },
    help: {
      text: profile.remediationGuidance,
    },
    properties: {
      tags: ['security', 'identity-graph', profile.mitreTechniqueId],
      precision: 'high',
      'security-severity': profile.opsecNoise <= 30 ? '9.0' : '7.5',
    },
  }));

  const results = [
    ...chokepoints.map((cp) => ({
      ruleId: `SG-${cp.edge.type.toUpperCase()}`,
      level: cp.impactPercentage >= 25 ? 'error' : 'warning',
      message: {
        text:
          `[Chokepoint #${cp.rank}] Removing ${cp.edge.type} edge "${cp.edge.id}" ` +
          `(${cp.sourceNode.label} -> ${cp.targetNode.label}) severs ${cp.pathsSevered}/${cp.totalPathsAnalyzed} ` +
          `(${cp.impactPercentage}%) of discovered Tier-0 escalation paths. Remediation: ${cp.remediationGuidance}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: datasetArtifactUri,
            },
            region: {
              startLine: 1,
            },
          },
          logicalLocations: [
            {
              name: cp.edge.id,
              FullyQualifiedName: `${cp.sourceNode.id}->${cp.targetNode.id}`,
              kind: 'edge',
            },
          ],
        },
      ],
    })),
    ...shadowAdmins.slice(0, 20).map((sa) => {
      const firstHop = sa.shortestPathToTierZero.hops[0]!;
      return {
        ruleId: `SG-${firstHop.edgeType.toUpperCase()}`,
        level: 'error',
        message: {
          text:
            `[Shadow Admin] Non-privileged principal "${sa.principal.label}" (${sa.principal.id}) holds ` +
            `${sa.minHopsToTierZero}-hop transitive control over Tier-0 asset "${sa.shortestPathToTierZero.targetNode.label}" ` +
            `(Stealth Score: ${sa.stealthScore}/100). Vector: ${sa.escalationVectorSummary}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: datasetArtifactUri,
              },
              region: {
                startLine: 1,
              },
            },
            logicalLocations: [
              {
                name: sa.principal.id,
                FullyQualifiedName: sa.principal.label,
                kind: 'principal',
              },
            ],
          },
        ],
      };
    }),
  ];

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'shadow-graph',
            informationUri: 'https://github.com/1MEshh/Nexus',
            version: graph.metadata.version,
            rules,
          },
        },
        results,
      },
    ],
  };
}
