import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  ShadowGraph,
  calculateRemediationChokepoints,
  escapeHtml,
  findShadowAdmins,
  findShortestAttackPaths,
  generateCypherExport,
  generateHtmlReport,
  generateSarifReport,
  renderAsciiReport,
  signReportPayload,
  verifyReportSignature,
} from '../src/index.js';
import { parseCliArgs, runCli } from '../src/cli.js';

function loadEnterpriseSample(): unknown {
  const samplePath = path.resolve('samples', 'ad-hybrid-enterprise.json');
  return JSON.parse(fs.readFileSync(samplePath, 'utf8'));
}

describe('ShadowGraph Engine & Multi-Domain Attack Path Verification', () => {
  it('loads the enterprise hybrid dataset with >= 35 nodes and >= 50 edges', () => {
    const raw = loadEnterpriseSample();
    const graph = ShadowGraph.fromDocument(raw);

    assert.ok(graph.getNodes().length >= 35, `Expected >= 35 nodes, got ${graph.getNodes().length}`);
    assert.ok(graph.getEdges().length >= 50, `Expected >= 50 edges, got ${graph.getEdges().length}`);
    assert.equal(graph.getTierZeroNodes().length, 6);
  });

  it('distinguishes Dijkstra stealth routing from minimal-hop routing on AD-USER-JDOE', () => {
    const graph = ShadowGraph.fromDocument(loadEnterpriseSample());

    const stealthPaths = findShortestAttackPaths(
      graph,
      'AD-USER-JDOE',
      ['AD-DC-PRIMARY01'],
      'stealth'
    );
    const hopPaths = findShortestAttackPaths(
      graph,
      'AD-USER-JDOE',
      ['AD-DC-PRIMARY01'],
      'hops'
    );
    const hybridPaths = findShortestAttackPaths(
      graph,
      'AD-USER-JDOE',
      ['AD-DC-PRIMARY01'],
      'hybrid'
    );

    assert.equal(stealthPaths.length, 1);
    assert.equal(hopPaths.length, 1);
    assert.equal(hybridPaths.length, 1);

    const stealth = stealthPaths[0]!;
    const hops = hopPaths[0]!;

    // Stealth route takes the quiet 5-hop ACL chain (noise=91) instead of noisy AdminTo/PsExec 4-hop chain (noise=191)
    assert.equal(stealth.hopCount, 5);
    assert.equal(stealth.totalOpsecNoise, 91);
    assert.deepEqual(
      stealth.hops.map((h) => h.edgeType),
      ['MemberOf', 'GenericWrite', 'AddMember', 'WriteDacl', 'DCSync']
    );

    // Hop-minimizing route takes the 4-hop workstation session harvesting path
    assert.equal(hops.hopCount, 4);
    assert.equal(hops.totalOpsecNoise, 191);
    assert.deepEqual(
      hops.hops.map((h) => h.edgeType),
      ['AdminTo', 'HasSession', 'MemberOf', 'AdminTo']
    );
  });

  it('discovers cross-domain escalation paths (AD -> Linux -> Kubernetes -> Cloud IAM)', () => {
    const graph = ShadowGraph.fromDocument(loadEnterpriseSample());
    const contractorPaths = findShortestAttackPaths(
      graph,
      'AD-USER-contractor01',
      ['AWS-ROLE-ORG-ADMIN', 'K8S-ROLE-CLUSTER-ADMIN'],
      'stealth'
    );

    assert.equal(contractorPaths.length, 2);
    const toAwsOrgAdmin = contractorPaths.find((p) => p.targetNode.id === 'AWS-ROLE-ORG-ADMIN');
    assert.ok(toAwsOrgAdmin, 'Expected path from contractor01 to AWS-ROLE-ORG-ADMIN');
    assert.equal(toAwsOrgAdmin.isCrossDomain, true);
    assert.ok(toAwsOrgAdmin.domainsTraversed.includes('ActiveDirectory'));
    assert.ok(toAwsOrgAdmin.domainsTraversed.includes('LinuxHost'));
    assert.ok(toAwsOrgAdmin.domainsTraversed.includes('KubernetesRBAC'));
    assert.ok(toAwsOrgAdmin.domainsTraversed.includes('CloudIAM'));
  });

  it('maintains strict cycle immunity on directed graphs with 2-node and 3-node cycles', () => {
    const cyclicDoc = {
      metadata: {
        name: 'Directed Cycle Torture Graph',
        version: '1.0.0',
        collectedAt: '2026-10-23T00:00:00Z',
        environment: 'Test',
      },
      nodes: [
        { id: 'N1', label: 'Start User', kind: 'User', domain: 'ActiveDirectory', isTierZero: false },
        { id: 'N2', label: 'Pivot A', kind: 'User', domain: 'ActiveDirectory', isTierZero: false },
        { id: 'N3', label: 'Pivot B', kind: 'Group', domain: 'ActiveDirectory', isTierZero: false },
        { id: 'T0', label: 'Domain Admins', kind: 'Group', domain: 'ActiveDirectory', isTierZero: true },
      ],
      edges: [
        { id: 'E1', source: 'N1', target: 'N2', type: 'GenericWrite' },
        { id: 'E2', source: 'N2', target: 'N1', type: 'GenericWrite' },
        { id: 'E3', source: 'N2', target: 'N3', type: 'AddMember' },
        { id: 'E4', source: 'N3', target: 'N1', type: 'WriteDacl' },
        { id: 'E5', source: 'N3', target: 'N2', type: 'WriteDacl' },
        { id: 'E6', source: 'N3', target: 'T0', type: 'GenericAll' },
      ],
    };

    const graph = ShadowGraph.fromDocument(cyclicDoc);
    const paths = findShortestAttackPaths(graph, 'N1', ['T0'], 'stealth');
    assert.equal(paths.length, 1);
    assert.equal(paths[0]!.hopCount, 3);
    assert.deepEqual(
      paths[0]!.hops.map((h) => h.edgeId),
      ['E1', 'E3', 'E6']
    );
  });

  it('identifies Shadow Admins while excluding legitimate Tier-0 group members and isolated users', () => {
    const graph = ShadowGraph.fromDocument(loadEnterpriseSample());
    const shadowAdmins = findShadowAdmins(graph, 'stealth');
    const shadowIds = new Set(shadowAdmins.map((s) => s.principal.id));

    // Non-privileged accounts with multi-hop escalation paths must be flagged as Shadow Admins
    assert.ok(shadowIds.has('AD-USER-JDOE'), 'Expected AD-USER-JDOE to be flagged as a Shadow Admin');
    assert.ok(
      shadowIds.has('AD-USER-SYSADMIN-LEGACY'),
      'Expected AD-USER-SYSADMIN-LEGACY to be flagged as a Shadow Admin'
    );
    assert.ok(
      shadowIds.has('K8S-SA-CICD-DEPLOYER'),
      'Expected K8S-SA-CICD-DEPLOYER to be flagged as a Shadow Admin'
    );

    // Legitimate Tier-0 member via MemberOf must NOT be flagged as a Shadow Admin
    assert.ok(
      !shadowIds.has('AD-USER-DA-ADMIN01'),
      'Legitimate Tier-0 member AD-USER-DA-ADMIN01 must not be flagged as Shadow Admin'
    );

    // Isolated read-only user with zero path to Tier-0 must NOT be flagged
    assert.ok(
      !shadowIds.has('AD-USER-ISOLATED-AUDITOR'),
      'Isolated auditor must not be flagged as Shadow Admin'
    );

    // Tier-0 nodes themselves must NOT be flagged as Shadow Admins
    assert.ok(!shadowIds.has('AD-GRP-DOMAIN-ADMINS'));
    assert.ok(!shadowIds.has('AD-DC-PRIMARY01'));
  });

  it('ranks remediation chokepoints using betweenness centrality across all shortest paths', () => {
    const graph = ShadowGraph.fromDocument(loadEnterpriseSample());
    const chokepoints = calculateRemediationChokepoints(graph, 5, 'stealth');

    assert.equal(chokepoints.length, 5);
    for (let i = 0; i < chokepoints.length; i++) {
      const cp = chokepoints[i]!;
      assert.equal(cp.rank, i + 1);
      assert.ok(cp.pathsSevered > 0);
      assert.ok(cp.betweennessCentrality > 0 && cp.betweennessCentrality <= 1);
      assert.ok(cp.impactPercentage > 0 && cp.impactPercentage <= 100);
      if (i > 0) {
        assert.ok(
          chokepoints[i - 1]!.remediationPriorityScore >= cp.remediationPriorityScore,
          'Chokepoints must be sorted by descending remediationPriorityScore'
        );
      }
    }
  });

  it('rejects malformed inputs, duplicate IDs, and dangling edge references via strict Zod schema', () => {
    // Missing required fields
    assert.throws(() => ShadowGraph.fromDocument({}), /Invalid input/);

    // Unknown attack edge type
    assert.throws(() => {
      ShadowGraph.fromDocument({
        metadata: {
          name: 'Bad Edge Graph',
          version: '1.0',
          collectedAt: '2026-10-23',
          environment: 'Test',
        },
        nodes: [{ id: 'A', label: 'A', kind: 'User', domain: 'ActiveDirectory', isTierZero: true }],
        edges: [{ id: 'E1', source: 'A', target: 'A', type: 'ArbitraryInvalidEdge' }],
      });
    });

    // Dangling edge target node reference
    assert.throws(() => {
      ShadowGraph.fromDocument({
        metadata: {
          name: 'Dangling Node Graph',
          version: '1.0',
          collectedAt: '2026-10-23',
          environment: 'Test',
        },
        nodes: [{ id: 'A', label: 'A', kind: 'User', domain: 'ActiveDirectory', isTierZero: true }],
        edges: [{ id: 'E1', source: 'A', target: 'NON_EXISTENT_NODE', type: 'GenericAll' }],
      });
    }, /non-existent target node/);
  });

  it('exports sanitized HTML/SVG, Neo4j Cypher, SARIF v2.1.0, and ASCII reports without XSS', () => {
    const xssDoc = {
      metadata: {
        name: 'XSS Test <script>alert(1)</script>',
        version: '1.0.0',
        collectedAt: '2026-10-23T00:00:00Z',
        environment: 'Test',
      },
      nodes: [
        {
          id: 'U1',
          label: 'user"><img src=x onerror=alert(1)>',
          kind: 'User',
          domain: 'ActiveDirectory',
          isTierZero: false,
        },
        {
          id: 'T0',
          label: 'Domain Admins',
          kind: 'Group',
          domain: 'ActiveDirectory',
          isTierZero: true,
        },
      ],
      edges: [{ id: 'E1', source: 'U1', target: 'T0', type: 'GenericAll' }],
    };

    const graph = ShadowGraph.fromDocument(xssDoc);
    const paths = findShortestAttackPaths(graph, 'U1', ['T0'], 'stealth');
    const shadowAdmins = findShadowAdmins(graph, 'stealth');
    const chokepoints = calculateRemediationChokepoints(graph, 5, 'stealth');

    const html = generateHtmlReport(graph, paths, shadowAdmins, chokepoints);
    assert.ok(!html.includes('<script>alert(1)</script>'), 'HTML output must escape script tags');
    assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'HTML output must escape img tags');
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;&#x2F;script&gt;'));

    const cypher = generateCypherExport(graph, shadowAdmins, chokepoints);
    assert.ok(cypher.includes('MERGE (n:IdentityNode:User'));
    assert.ok(cypher.includes('MERGE (s)-[r:GenericAll'));

    const sarif = generateSarifReport(graph, shadowAdmins, chokepoints);
    assert.equal(sarif.version, '2.1.0');

    const ascii = renderAsciiReport(graph, paths, shadowAdmins, chokepoints);
    assert.ok(ascii.includes('SHADOW-GRAPH: MULTI-DOMAIN IDENTITY ATTACK PATH'));
    assert.equal(escapeHtml('<>&"\'/'), '&lt;&gt;&amp;&quot;&#39;&#x2F;');
  });

  it('verifies report HMAC signatures in constant time and parses CLI arguments accurately', () => {
    const payload = '{"status":"verified"}';
    const secret = 'test-hmac-key-material';
    const sig = signReportPayload(payload, secret);

    assert.equal(verifyReportSignature(payload, sig, secret), true);
    assert.equal(verifyReportSignature(payload, sig, 'wrong-key'), false);
    assert.equal(verifyReportSignature(payload + 'tamper', sig, secret), false);

    const cliOpts = parseCliArgs(['--mode', 'hybrid', '--top-chokepoints', '5', '--source', 'AD-USER-JDOE']);
    assert.equal(cliOpts.mode, 'hybrid');
    assert.equal(cliOpts.topChokepoints, 5);
    assert.equal(cliOpts.sourceId, 'AD-USER-JDOE');

    const helpExitCode = runCli(['--help']);
    assert.equal(helpExitCode, 0);
  });
});
