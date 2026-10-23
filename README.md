# SHADOW-GRAPH

**Multi-Domain Identity Attack Path Engine, Shadow Admin Enumerator, and Betweenness Centrality Chokepoint Analyzer**

`shadow-graph` is a TypeScript graph-theory and offensive/defensive identity security engine that models transitive privilege escalation across hybrid enterprise environments spanning **Active Directory (BloodHound DACL/Session primitives)**, **Linux Bastions & CI Runners**, **Kubernetes RBAC & Privileged Container Mounts**, and **Cloud IAM Role Trust & PassRole Chains**.

---

## 1. Mathematical & Graph-Theoretic Formulation

### 1.1 Multi-Weighted Directed Identity Graph
An enterprise identity topology is modeled as a directed, multi-weighted graph:

$$G = (V, E, \tau_V, \tau_E, w_{\text{noise}}, w_{\text{complex}})$$

where:
- $V$ is the finite set of security principals and compute resources partitioned across domains $\mathcal{D} = \{\text{ActiveDirectory}, \text{LinuxHost}, \text{KubernetesRBAC}, \text{CloudIAM}\}$.
- $T_0 \subset V$ denotes the subset of **Tier-0** control-plane assets (e.g., `Domain Controllers`, `Domain Admins`, `Enterprise Admins`, `PKI Subordinate CAs`, `Kubernetes cluster-admin`, `AWS OrganizationAccountAccessRole`).
- $E \subseteq V \times V$ is the set of directed privilege-escalation or lateral-movement edges.
- Each edge $e = (u, v) \in E$ is parameterized by two bounded strictly positive cost functions:
  - $w_{\text{noise}}(e) \in [1, 100]$: **OpSec Detection Cost**, quantifying telemetry volume and SOC alert probability (e.g., `MemberOf` $= 1$, `CanAssumeRole` $= 12$, `DCSync` $= 15$, `GenericWrite` $= 22$, `WriteDacl` $= 25$, `ForceChangePassword` $= 70$, `AdminTo/PsExec` $= 85$).
  - $w_{\text{complex}}(e) \in [1, 100]$: **Exploit Complexity**, quantifying prerequisite tooling, credential coercion conditions, or race windows.

### 1.2 Multi-Objective Dijkstra Routing & Cycle Immunity
Given a source principal $s \in V \setminus T_0$ and routing mode $m \in \{\text{stealth}, \text{hops}, \text{hybrid}\}$, the composite directional edge weight $W_m(e)$ is defined as:

$$W_m(e) = \begin{cases}
w_{\text{noise}}(e) & \text{if } m = \text{stealth} \\
1000 + 10^{-2} w_{\text{noise}}(e) + 10^{-3} w_{\text{complex}}(e) & \text{if } m = \text{hops} \\
0.6 \, w_{\text{noise}}(e) + 0.3 \, w_{\text{complex}}(e) + 10 & \text{if } m = \text{hybrid}
\end{cases}$$

Because $W_m(e) > 0$ for all $e \in E$, any cycle $C = (v_0, v_1, \dots, v_k = v_0)$ satisfies $\sum_{e \in C} W_m(e) > 0$. The binary min-heap Dijkstra solver in `src/graph-engine.ts` maintains a closed set $S \subseteq V$ of settled vertices and enforces cycle immunity in $\mathcal{O}((|V| + |E|) \log |V|)$ time without infinite traversal across bidirectional ACL loops or cross-cloud trust cycles.

### 1.3 Shadow Admin Set Derivation (Reverse Graph Reachability)
Let $G^{\top} = (V, E^{\top})$ be the transpose graph where $E^{\top} = \{(v, u) \mid (u, v) \in E\}$.
1. **Legitimate Tier-0 Membership Closure ($L_0$)**: Computed via reverse Breadth-First Search (BFS) from $T_0$ restricted strictly to structural `MemberOf` edges:
   $$L_0 = \{ u \in V \mid u \xrightarrow{\text{MemberOf}^*} t_0 \text{ for some } t_0 \in T_0 \}$$
2. **Transitive Escalation Closure ($R_0$)**: Computed via unrestricted reverse BFS from $T_0$ across all attack primitives $E^{\top}$:
   $$R_0 = \{ u \in V \mid \text{dist}_{G}(u, T_0) < \infty \}$$
3. **Shadow Admins ($\mathcal{S}$)**: The set of non-privileged principals holding hidden transitive control over Tier-0 is strictly:
   $$\mathcal{S} = R_0 \setminus (T_0 \cup L_0)$$

### 1.4 Edge Betweenness Centrality for Remediation Chokepoints
To identify the single ACL or trust relationship whose revocation severs the maximum fraction of attack paths into $T_0$, `calculateRemediationChokepoints` evaluates the shortest-path edge betweenness centrality $C_B(e)$ restricted to the source-target pair set $\mathcal{P} = (V \setminus T_0) \times T_0$:

$$C_B(e) = \frac{1}{|\Pi_{T_0}|} \sum_{(s, t) \in \mathcal{P}} \mathbb{I}\left(e \in \pi^*(s, t)\right)$$

where $\Pi_{T_0}$ is the set of all viable shortest attack paths from non-Tier-0 nodes to Tier-0 targets, and $\pi^*(s, t)$ is the optimal path from $s$ to $t$. Edges are further weighted by an actionability factor $\alpha(e)$ (penalizing structural `MemberOf` changes relative to anomalous ACL edges such as `GenericWrite`, `WriteDacl`, `PassRole`, or `PodExec`) and a stealth hazard factor $\eta(e) = 1 + \frac{100 - w_{\text{noise}}(e)}{200}$.

---

## 2. Supported Attack Primitives Across Domains

| Edge Primitive | Domain Scope | OpSec Noise | Complexity | MITRE ATT&CK | Technical Exploitation Mechanism |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `MemberOf` | AD / IAM / K8s | 1 | 1 | `T1078.002` | Security group membership inheritance via security token SIDs. |
| `CanAssumeRole` | Cloud IAM | 12 | 15 | `T1078.004` | `sts:AssumeRole` or `sts:AssumeRoleWithWebIdentity` via OIDC/IRSA trust policy. |
| `DCSync` | Active Directory | 15 | 20 | `T1003.006` | `DS-Replication-Get-Changes-All` via MS-DRSR (`IDL_DRSGetNCChanges`) to extract `krbtgt` keys. |
| `AllowedToDelegate` | Active Directory | 18 | 35 | `T1558.003` | Kerberos Constrained Delegation (`S4U2Self` + `S4U2Proxy`) via `msDS-AllowedToDelegateTo`. |
| `HasSession` | AD / Linux / K8s | 20 | 30 | `T1003.001` | Credential material resident in LSASS, forwarded SSH agent sockets, or projected K8s SA tokens. |
| `GenericWrite` | Active Directory | 22 | 20 | `T1556.006` | Shadow Credentials injection (`msDS-KeyCredentialLink`) for PKINIT TGT extraction or Targeted Kerberoasting. |
| `WriteDacl` | Active Directory | 25 | 25 | `T1222.001` | Modification of target object `nTSecurityDescriptor` DACL to grant `GenericAll` or `DCSync`. |
| `PassRole` | Cloud IAM | 26 | 30 | `T1098.001` | `iam:PassRole` attachment of higher-privileged IAM Role to EC2, Lambda, or EKS compute. |
| `AddMember` | Active Directory | 28 | 10 | `T1098.007` | `WriteProperty` on the `member` attribute of a security group. |
| `GenericAll` | AD / K8s | 30 | 15 | `T1484.001` | Full discretionary control over principal, group, computer, or Kubernetes `ClusterRole`. |
| `PodExec` | Kubernetes RBAC | 32 | 18 | `T1609` | `create`/`get` on `pods/exec` subresource enabling command execution inside target pod. |
| `WriteOwner` | Active Directory | 35 | 30 | `T1222.001` | Overwriting object owner SID to gain implicit `WRITE_DAC` permissions. |
| `HostPathMount` | Kubernetes / Linux | 40 | 25 | `T1611` | Privileged container or `hostPath` volume mount exposing worker node `/etc/kubernetes` or kubelet credentials. |
| `CanRDP` | AD / Linux | 45 | 15 | `T1021.001` | Interactive Remote Desktop or Bastion session establishment. |
| `ForceChangePassword` | Active Directory | 70 | 10 | `T1098` | Extended right `User-Force-Change-Password` (`00299570-246d-11d0-a768-00aa006e0529`). |
| `AdminTo` | AD / Linux | 85 | 20 | `T1569.002` | Remote Service Control Manager (`PsExec`), WMI execution, or root `sudo` privileges on host. |

---

## 3. CLI Reference

```text
Usage:
  shadow-graph [options]

Options:
  -i, --input <file>            Path to identity graph JSON (default: samples/ad-hybrid-enterprise.json)
  -s, --source <nodeId>         Evaluate shortest paths from a specific principal ID
  -m, --mode <mode>             Dijkstra routing mode: stealth | hops | hybrid (default: stealth)
  -t, --top-chokepoints <num>   Number of remediation chokepoints to rank (default: 10)
      --html-out <file>         Write standalone HTML/SVG interactive report
      --cypher-out <file>       Write Neo4j Cypher import script
      --sarif-out <file>        Write SARIF v2.1.0 static analysis report
      --json-out <file>         Write structured JSON analysis output
  -h, --help                    Display this help message
```

---

## 4. Cross-Platform Usage Examples (Linux & Windows)

### 4.1 Build and Run Test Suite
```bash
npm install
npm run build
npm test
```

### 4.2 Analyze Hybrid Enterprise Sample (Linux / macOS)
```bash
node ./dist/src/cli.js \
  --input samples/ad-hybrid-enterprise.json \
  --source AD-USER-JDOE \
  --mode stealth \
  --top-chokepoints 10 \
  --html-out report.html \
  --cypher-out export.cypher \
  --sarif-out findings.sarif
```

### 4.3 Analyze Hybrid Enterprise Sample (Windows PowerShell)
```powershell
node .\dist\src\cli.js `
  --input samples\ad-hybrid-enterprise.json `
  --source AD-USER-contractor01 `
  --mode hybrid `
  --top-chokepoints 10 `
  --html-out report.html `
  --sarif-out findings.sarif
```

---

## 5. Repository Structure

```text
shadow-graph/
├── .github/workflows/ci.yml        # Cross-platform CI matrix (ubuntu-latest & windows-latest)
├── samples/
│   └── ad-hybrid-enterprise.json   # 38-node, 52-edge multi-domain enterprise attack graph
├── scripts/
│   └── security-audit.sh           # Zero-leak and static security verification gate
├── src/
│   ├── cli.ts                      # Cross-platform CLI argument parser & runner
│   ├── exporters.ts                # ASCII, HTML/SVG (CSP + escaped), Neo4j Cypher, SARIF v2.1.0
│   ├── graph-engine.ts             # Dijkstra shortest-path, Shadow Admin BFS, Chokepoint Centrality
│   ├── index.ts                    # Public TypeScript library exports
│   └── schema.ts                   # Strict Zod perimeter validation & MITRE ATT&CK edge telemetry
└── tests/
    ├── graph-engine.test.ts        # Unit & integration test suite
    └── security/
        └── leak-scanner.test.ts    # Automated zero-leak privacy & secret scanner
```
