import { z } from 'zod';

/**
 * Supported multi-domain identity environments.
 */
export const IdentityDomainSchema = z.enum([
  'ActiveDirectory',
  'CloudIAM',
  'KubernetesRBAC',
  'LinuxHost',
]);
export type IdentityDomain = z.infer<typeof IdentityDomainSchema>;

/**
 * Supported principal and resource node classifications across AD, Cloud IAM, and Kubernetes/Linux.
 */
export const NodeKindSchema = z.enum([
  'User',
  'Group',
  'Computer',
  'DomainController',
  'IAMRole',
  'IAMUser',
  'IAMPolicy',
  'ServiceAccount',
  'Pod',
  'K8sNode',
  'ClusterRole',
]);
export type NodeKind = z.infer<typeof NodeKindSchema>;

/**
 * Directed attack edge types representing ACLs, session artifacts, role trust, and container breakouts.
 */
export const AttackEdgeTypeSchema = z.enum([
  'MemberOf',
  'GenericAll',
  'GenericWrite',
  'WriteDacl',
  'WriteOwner',
  'ForceChangePassword',
  'AddMember',
  'HasSession',
  'AdminTo',
  'CanRDP',
  'AllowedToDelegate',
  'DCSync',
  'CanAssumeRole',
  'PassRole',
  'PodExec',
  'HostPathMount',
]);
export type AttackEdgeType = z.infer<typeof AttackEdgeTypeSchema>;

/**
 * Telemetry, OpSec detection noise, exploit complexity, and remediation profiles for each attack edge primitive.
 */
export interface EdgeTelemetryProfile {
  readonly type: AttackEdgeType;
  readonly opsecNoise: number; // 1 (silent) to 100 (loud)
  readonly exploitComplexity: number; // 1 (trivial) to 100 (complex)
  readonly mitreTechniqueId: string;
  readonly mitreTechniqueName: string;
  readonly description: string;
  readonly remediationGuidance: string;
}

export const DEFAULT_EDGE_PROFILES: Readonly<Record<AttackEdgeType, EdgeTelemetryProfile>> = {
  MemberOf: {
    type: 'MemberOf',
    opsecNoise: 1,
    exploitComplexity: 1,
    mitreTechniqueId: 'T1078.002',
    mitreTechniqueName: 'Valid Accounts: Domain Accounts',
    description: 'Intrinsic security group membership inheritance; requires zero active directory modifications.',
    remediationGuidance: 'Audit and remove unnecessary nested security group memberships; enforce least-privilege RBAC.',
  },
  HasSession: {
    type: 'HasSession',
    opsecNoise: 20,
    exploitComplexity: 30,
    mitreTechniqueId: 'T1003.001',
    mitreTechniqueName: 'OS Credential Dumping: LSASS Memory',
    description: 'Active logon session or cached credential artifact resident in host memory (LSASS / SSH agent / KCM).',
    remediationGuidance: 'Enforce Credential Guard, Protected Users security group, and strict tiered workstation logon restrictions.',
  },
  CanRDP: {
    type: 'CanRDP',
    opsecNoise: 45,
    exploitComplexity: 15,
    mitreTechniqueId: 'T1021.001',
    mitreTechniqueName: 'Remote Services: Remote Desktop Protocol',
    description: 'Principal is permitted interactive Remote Desktop access to target host.',
    remediationGuidance: 'Restrict Remote Desktop Users group membership and require Network Level Authentication (NLA) with jump-host bastion controls.',
  },
  AdminTo: {
    type: 'AdminTo',
    opsecNoise: 85,
    exploitComplexity: 20,
    mitreTechniqueId: 'T1569.002',
    mitreTechniqueName: 'System Services: Service Execution (PsExec/SCM)',
    description: 'Administrative control over host enabling remote service creation, WMI execution, or memory credential harvesting.',
    remediationGuidance: 'Eliminate shared local administrator accounts via LAPS and restrict local AdminTo rights to dedicated Tier-aligned accounts.',
  },
  GenericAll: {
    type: 'GenericAll',
    opsecNoise: 30,
    exploitComplexity: 15,
    mitreTechniqueId: 'T1484.001',
    mitreTechniqueName: 'Domain Policy Modification: Group Policy / ACL Abuse',
    description: 'Full control over target object: enables group membership modification, shadow credentials, or targeted Kerberoasting.',
    remediationGuidance: 'Remove GenericAll ACEs granted to non-Tier-0 principals from the object Discretionary Access Control List (DACL).',
  },
  GenericWrite: {
    type: 'GenericWrite',
    opsecNoise: 22,
    exploitComplexity: 20,
    mitreTechniqueId: 'T1556.006',
    mitreTechniqueName: 'Modify Authentication Process: Shadow Credentials (msDS-KeyCredentialLink)',
    description: 'Write access to non-protected object attributes including SPN registration or msDS-KeyCredentialLink injection.',
    remediationGuidance: 'Revoke GenericWrite ACEs on sensitive principals and monitor LDAP Event ID 5136 for msDS-KeyCredentialLink changes.',
  },
  WriteDacl: {
    type: 'WriteDacl',
    opsecNoise: 25,
    exploitComplexity: 25,
    mitreTechniqueId: 'T1222.001',
    mitreTechniqueName: 'File and Directory Permissions Modification: Windows',
    description: 'Permission to overwrite the target object DACL and grant arbitrary privileges (e.g., GenericAll or DCSync).',
    remediationGuidance: 'Audit and remove WriteDacl permissions from non-administrative security principals; alert on Event ID 4662/5136 DACL modifications.',
  },
  WriteOwner: {
    type: 'WriteOwner',
    opsecNoise: 35,
    exploitComplexity: 30,
    mitreTechniqueId: 'T1222.001',
    mitreTechniqueName: 'File and Directory Permissions Modification: Object Ownership Takeover',
    description: 'Permission to overwrite the object owner SID, subsequently granting implicit WriteDacl privileges.',
    remediationGuidance: 'Remove WriteOwner ACEs and restrict ownership modification rights to Tier-0 directory administrators.',
  },
  ForceChangePassword: {
    type: 'ForceChangePassword',
    opsecNoise: 70,
    exploitComplexity: 10,
    mitreTechniqueId: 'T1098',
    mitreTechniqueName: 'Account Manipulation: User-Force-Change-Password',
    description: 'Extended right allowing immediate password reset of target account without knowledge of current password.',
    remediationGuidance: 'Restrict User-Force-Change-Password extended rights to scoped Helpdesk roles and ensure AdminSDHolder protection is enabled on privileged accounts.',
  },
  AddMember: {
    type: 'AddMember',
    opsecNoise: 28,
    exploitComplexity: 10,
    mitreTechniqueId: 'T1098.007',
    mitreTechniqueName: 'Account Manipulation: Additional Local or Domain Groups',
    description: 'Permission to write to the member attribute of a security group, enabling direct self-enrollment.',
    remediationGuidance: 'Remove WriteProperty(member) ACEs from privileged security groups and enforce approval workflows for group changes.',
  },
  AllowedToDelegate: {
    type: 'AllowedToDelegate',
    opsecNoise: 18,
    exploitComplexity: 35,
    mitreTechniqueId: 'T1558.003',
    mitreTechniqueName: 'Steal or Forge Kerberos Tickets: S4U2Self / S4U2Proxy Constrained Delegation',
    description: 'Kerberos Constrained Delegation (msDS-AllowedToDelegateTo) allowing impersonation of arbitrary Tier-0 principals to target services.',
    remediationGuidance: 'Enable "Account is sensitive and cannot be delegated" on all privileged accounts and replace legacy delegation with RBCD where strictly required.',
  },
  DCSync: {
    type: 'DCSync',
    opsecNoise: 15,
    exploitComplexity: 20,
    mitreTechniqueId: 'T1003.006',
    mitreTechniqueName: 'OS Credential Dumping: DCSync (DS-Replication-Get-Changes-All)',
    description: 'Directory replication rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) permitting extraction of any NTLM/Kerberos key.',
    remediationGuidance: 'Remove replication extended rights from all principals except legitimate Domain Controllers and closely monitored Entra Connect accounts.',
  },
  CanAssumeRole: {
    type: 'CanAssumeRole',
    opsecNoise: 12,
    exploitComplexity: 15,
    mitreTechniqueId: 'T1078.004',
    mitreTechniqueName: 'Valid Accounts: Cloud Accounts (sts:AssumeRole)',
    description: 'IAM Role Trust Policy permits source identity or federated workload token to assume target IAM role.',
    remediationGuidance: 'Scope IAM Trust Policies with strict sts:ExternalId, aws:PrincipalArn conditions, and OIDC subject claim constraints.',
  },
  PassRole: {
    type: 'PassRole',
    opsecNoise: 26,
    exploitComplexity: 30,
    mitreTechniqueId: 'T1098.001',
    mitreTechniqueName: 'Account Manipulation: Additional Cloud Credentials (iam:PassRole)',
    description: 'Permission to attach an IAM role to a compute instance, Lambda function, or EKS pod for privilege escalation.',
    remediationGuidance: 'Restrict iam:PassRole with explicit Resource ARNs and iam:PassedToService condition keys.',
  },
  PodExec: {
    type: 'PodExec',
    opsecNoise: 32,
    exploitComplexity: 18,
    mitreTechniqueId: 'T1609',
    mitreTechniqueName: 'Container Administration Command (pods/exec)',
    description: 'Kubernetes RBAC grants create/get on pods/exec, permitting remote command execution and service account token extraction inside the pod.',
    remediationGuidance: 'Remove pods/exec RBAC verbs from non-administrative roles and disable automountServiceAccountToken on pods where not required.',
  },
  HostPathMount: {
    type: 'HostPathMount',
    opsecNoise: 40,
    exploitComplexity: 25,
    mitreTechniqueId: 'T1611',
    mitreTechniqueName: 'Escape to Host (Privileged Pod / hostPath Mount)',
    description: 'Pod specification mounts underlying worker node filesystem (e.g., /etc/kubernetes, /var/run/containerd.sock, or /root/.aws), enabling node/cloud compromise.',
    remediationGuidance: 'Enforce Kubernetes Pod Security Admission (PSA) "restricted" profile to prohibit hostPath volumes and privileged containers.',
  },
};

/**
 * Zod schema for an identity node in the multi-domain graph.
 */
export const GraphNodeSchema = z
  .object({
    id: z.string().min(1).max(256),
    label: z.string().min(1).max(256),
    kind: NodeKindSchema,
    domain: IdentityDomainSchema,
    isTierZero: z.boolean().default(false),
    isCompromised: z.boolean().default(false),
    metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  })
  .strict();

export type GraphNode = z.infer<typeof GraphNodeSchema>;

/**
 * Zod schema for a directed attack edge in the multi-domain graph.
 */
export const GraphEdgeSchema = z
  .object({
    id: z.string().min(1).max(256),
    source: z.string().min(1).max(256),
    target: z.string().min(1).max(256),
    type: AttackEdgeTypeSchema,
    opsecNoise: z.number().min(1).max(100).optional(),
    exploitComplexity: z.number().min(1).max(100).optional(),
    description: z.string().max(1024).optional(),
  })
  .strict();

export type GraphEdgeInput = z.infer<typeof GraphEdgeSchema>;

/**
 * Normalized graph edge with resolved weights.
 */
export interface GraphEdge {
  readonly id: string;
  readonly source: string;
  readonly target: string;
  readonly type: AttackEdgeType;
  readonly opsecNoise: number;
  readonly exploitComplexity: number;
  readonly description: string;
}

/**
 * Complete multi-domain graph payload schema with cross-reference integrity checks.
 */
export const IdentityGraphDocumentSchema = z
  .object({
    metadata: z
      .object({
        name: z.string().min(1).max(256),
        version: z.string().min(1).max(64),
        collectedAt: z.string().min(1).max(64),
        environment: z.string().min(1).max(256),
      })
      .strict(),
    nodes: z.array(GraphNodeSchema).min(1).max(50000),
    edges: z.array(GraphEdgeSchema).min(1).max(200000),
  })
  .strict()
  .superRefine((doc, ctx) => {
    const nodeIds = new Set<string>();
    for (let i = 0; i < doc.nodes.length; i++) {
      const node = doc.nodes[i]!;
      if (nodeIds.has(node.id)) {
        ctx.addIssue({
          code: 'custom',
          message: `Duplicate node ID detected: "${node.id}"`,
          path: ['nodes', i, 'id'],
        });
      }
      nodeIds.add(node.id);
    }

    const edgeIds = new Set<string>();
    for (let i = 0; i < doc.edges.length; i++) {
      const edge = doc.edges[i]!;
      if (edgeIds.has(edge.id)) {
        ctx.addIssue({
          code: 'custom',
          message: `Duplicate edge ID detected: "${edge.id}"`,
          path: ['edges', i, 'id'],
        });
      }
      edgeIds.add(edge.id);

      if (!nodeIds.has(edge.source)) {
        ctx.addIssue({
          code: 'custom',
          message: `Edge "${edge.id}" references non-existent source node "${edge.source}"`,
          path: ['edges', i, 'source'],
        });
      }
      if (!nodeIds.has(edge.target)) {
        ctx.addIssue({
          code: 'custom',
          message: `Edge "${edge.id}" references non-existent target node "${edge.target}"`,
          path: ['edges', i, 'target'],
        });
      }
    }
  });

export type IdentityGraphDocument = z.infer<typeof IdentityGraphDocumentSchema>;

/**
 * Routing optimization mode for Dijkstra shortest-path calculation.
 * - 'stealth': Minimizes cumulative OpSec detection noise.
 * - 'hops': Minimizes total edge transitions (with minor tie-breaking on OpSec noise).
 * - 'hybrid': Balances OpSec detection noise (60%), exploit complexity (30%), and hop overhead (10%).
 */
export type PathRoutingMode = 'stealth' | 'hops' | 'hybrid';

export interface AttackHop {
  readonly edgeId: string;
  readonly sourceNode: GraphNode;
  readonly targetNode: GraphNode;
  readonly edgeType: AttackEdgeType;
  readonly opsecNoise: number;
  readonly exploitComplexity: number;
  readonly stepWeight: number;
  readonly mitreTechniqueId: string;
  readonly description: string;
}

export interface AttackPathResult {
  readonly sourceNode: GraphNode;
  readonly targetNode: GraphNode;
  readonly mode: PathRoutingMode;
  readonly hops: readonly AttackHop[];
  readonly hopCount: number;
  readonly totalWeight: number;
  readonly totalOpsecNoise: number;
  readonly averageOpsecNoise: number;
  readonly maxSingleHopNoise: number;
  readonly totalExploitComplexity: number;
  readonly domainsTraversed: readonly IdentityDomain[];
  readonly isCrossDomain: boolean;
}

export interface ShadowAdminFinding {
  readonly principal: GraphNode;
  readonly shortestPathToTierZero: AttackPathResult;
  readonly reachableTierZeroTargets: readonly string[];
  readonly minHopsToTierZero: number;
  readonly stealthScore: number; // 0-100 where higher means stealthier attack chain
  readonly escalationVectorSummary: string;
}

export interface RemediationChokepoint {
  readonly rank: number;
  readonly edge: GraphEdge;
  readonly sourceNode: GraphNode;
  readonly targetNode: GraphNode;
  readonly pathsSevered: number;
  readonly totalPathsAnalyzed: number;
  readonly betweennessCentrality: number; // Ratio [0, 1] of shortest paths passing through this edge
  readonly impactPercentage: number; // Percentage [0, 100]
  readonly isStructuralGroupMembership: boolean;
  readonly remediationPriorityScore: number;
  readonly mitreTechniqueId: string;
  readonly remediationGuidance: string;
}
