<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-k8s-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-k8s-audit

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Version](https://img.shields.io/badge/version-2.0-orange)
![License AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)
![VampSecure Labs](https://img.shields.io/badge/VampSecure-Labs-darkred)

**Kubernetes Security Auditor** — part of the VampSecure Labs toolkit.

Detects dangerous configurations in Kubernetes clusters through `kubectl` queries
(no SDK required). Produces structured findings with remediation guidance, JSON output,
and a professional HTML report for client delivery.

---

## Prerequisites

- **Python 3.8+**
- **kubectl** installed and reachable in `PATH`
- **Active cluster access** — the current `kubectl` context must point to the target cluster
- Sufficient RBAC permissions to read: `pods`, `services`, `secrets`, `configmaps`,
  `clusterrolebindings`, `rolebindings`, `networkpolicies`, `ingresses`, `namespaces`, `nodes`

Optional, for PDF export:
```bash
pip install fpdf2>=2.7
```

---

## Installation


```bash
pip install vamp-k8s-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-k8s-audit
```

```bash
git clone <repo-url> vamp-k8s-audit
cd vamp-k8s-audit
pip install -r requirements.txt   # optional, only needed for PDF
```

No additional dependencies beyond Python stdlib are required for JSON and HTML output.

---

## Usage

```bash
# Basic audit — current kubectl context, all namespaces
python3 vamp_k8s_audit.py

# Specific context and namespace
python3 vamp_k8s_audit.py --context prod-cluster --namespace production

# Save findings as JSON
python3 vamp_k8s_audit.py --output findings.json

# Generate professional HTML report for client delivery
python3 vamp_k8s_audit.py \
  --report-html report.html \
  --client "Acme Corp S.A." \
  --engagement "Kubernetes Security Review Q3-2026" \
  --auditor "VampSecure Labs"

# Custom kubeconfig path
python3 vamp_k8s_audit.py --kubeconfig ~/.kube/custom-config --context staging

# Skip image analysis (faster)
python3 vamp_k8s_audit.py --skip-images --output findings.json

# Verbose mode (show evidence in console)
python3 vamp_k8s_audit.py --verbose

# Full example
python3 vamp_k8s_audit.py \
  --context production \
  --namespace app-prod \
  --client "Client Name" \
  --engagement "K8S-Audit-2026" \
  --auditor "Analyst Name" \
  --output results.json \
  --report-html report.html \
  --verbose
```

---

## CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `--context CTX` | kubectl context to use | current context |
| `--namespace NS` | Limit audit to one namespace | all namespaces |
| `--kubeconfig PATH` | Path to kubeconfig file | `~/.kube/config` |
| `--output FILE` | Save findings as JSON | — |
| `--report-html FILE` | Generate professional HTML report | — |
| `--client NAME` | Client name for the report | Confidencial |
| `--engagement DESC` | Engagement description | — |
| `--auditor NAME` | Auditor name | VampSecure Labs |
| `--skip-images` | Skip image analysis (Phase 6) | false |
| `--control-plane` | Activate Phase 10: CIS control plane checks (etcd, KCM, scheduler, kubelet) | false |
| `--verbose` | Verbose mode | false |

---

## Audit Phases and Finding IDs

| Phase | Scope | Finding IDs | Key Checks |
|---|---|---|---|
| **1 — Cluster Context** | Cluster-wide | K8S-001..K8S-009 | Anonymous API access, node versions, node health |
| **2 — RBAC** | Cluster + namespaces | K8S-010..K8S-029 | `cluster-admin` SA bindings, wildcard ClusterRoles, default SA permissions, anonymous user permissions |
| **3 — Pod Security** | All pods | K8S-030..K8S-059 | Privileged containers, root execution, privilege escalation, dangerous capabilities, hostPID/IPC/Network, sensitive host mounts, missing resource limits |
| **4 — Network** | All namespaces | K8S-060..K8S-079 | LoadBalancer/NodePort exposure, missing NetworkPolicies, Ingress without TLS, Dashboard exposure, etcd TCP access |
| **5 — Secrets** | All namespaces | K8S-080..K8S-099 | Secrets in plain env vars, secrets in ConfigMaps, Opaque secrets in default namespace |
| **6 — Images & Runtime** | All pods | K8S-090..K8S-109 | `:latest` tags, public registries, missing readOnlyRootFilesystem, missing Pod Security Admission |
| **10 — Control Plane CIS** (`--control-plane`) | Node manifest files | K8S-ETCD-*/K8S-KCM-*/K8S-KSCHED-* | CIS benchmark checks for etcd (8), kube-controller-manager (8), kube-scheduler (3), kubelet anonymous auth (1) |

### Finding Severity Distribution

| Severity | Color | Meaning |
|---|---|---|
| CRITICAL | Red | Immediate exploitation risk, full cluster compromise |
| HIGH | Orange | Significant security weakness requiring urgent attention |
| MEDIUM | Yellow | Configuration issue reducing security posture |
| LOW | Blue | Best practice deviation |
| INFO | Grey | Informational observation |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one HIGH finding detected |
| `2` | At least one CRITICAL finding detected |

These codes are suitable for use in CI/CD pipelines to gate deployments.

---

## Output Formats

**Console** — Color-coded ANSI output with severity badges, affected resources, and a summary table.

**JSON** (`--output FILE`) — Structured VSL schema with metadata, summary by severity, and full finding detail.

**HTML** (`--report-html FILE`) — Standalone professional report for client delivery. Includes cover page, executive summary with risk bars, findings table, and detailed cards. No external dependencies (fully self-contained).

---

## Required RBAC Permissions

The tool requires read-only access to cluster resources. A minimal ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vamp-k8s-audit-reader
rules:
- apiGroups: [""]
  resources:
  - pods
  - services
  - secrets
  - configmaps
  - namespaces
  - nodes
  - serviceaccounts
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
  - clusterroles
  - clusterrolebindings
  - roles
  - rolebindings
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - networkpolicies
  - ingresses
  verbs: ["get", "list"]
```

---

## Sample Output

```
$ python3 vamp_k8s_audit.py --context lab-cluster --verbose

╔══════════════════════════════════════════════════════════╗
║       vamp-k8s-audit v3.1.0 — VampSecure Labs            ║
║  Context: lab-cluster   Namespace: all                   ║
╚══════════════════════════════════════════════════════════╝

[Phase 1] Cluster Context ...
  K8S-001  CRITICAL  Anonymous API access enabled — unauthenticated requests accepted
  K8S-003  HIGH      Node version skew: control-plane v1.27.4, worker v1.25.9

[Phase 2] RBAC ...
  K8S-010  CRITICAL  ServiceAccount default/api-service bound to cluster-admin
  K8S-017  HIGH      ClusterRole app-reader uses wildcard (*) on resources

[Phase 3] Pod Security ...
  K8S-031  CRITICAL  Pod monitoring/prometheus: privileged=true
  K8S-038  HIGH      Pod api/backend: allowPrivilegeEscalation not set to false
  K8S-045  MEDIUM    Pods in namespace api missing CPU/memory limits (8 pods)

[Phase 4] Network ...
  K8S-062  HIGH      Namespace frontend: no NetworkPolicy — unrestricted pod egress
  K8S-068  MEDIUM    Ingress api/public-ingress exposes HTTP without TLS redirect

[Phase 5] Secrets ...
  K8S-081  HIGH      Pod api/backend: DB_PASSWORD exposed via plain env var (not secretKeyRef)

┌──────────────────────────────────────────────────────────┐
│  CRITICAL  3   HIGH  5   MEDIUM  3   LOW  1   INFO  2    │
└──────────────────────────────────────────────────────────┘
Exit code: 2 — CRITICAL findings detected
```

---

## Why vamp-k8s-audit vs. kube-bench · Kubescape · Trivy (k8s mode)

| Feature | vamp-k8s-audit | kube-bench | Kubescape | Trivy k8s |
|---------|:---:|:---:|:---:|:---:|
| RBAC misconfiguration analysis | ✅ | ❌ | ✅ | ⚠️ partial |
| Pod Security context checks | ✅ | ✅ | ✅ | ✅ |
| Secrets in env vars / ConfigMaps | ✅ | ❌ | ⚠️ partial | ❌ |
| YAML-extensible rules engine | ✅ | ❌ | ❌ | ❌ |
| `--delta FILE` diff between two scans | ✅ | ❌ | ❌ | ❌ |
| kube-bench wrapper integration | ✅ | N/A | ❌ | ❌ |
| CI/CD exit codes (0 / 1 / 2) | ✅ | ❌ | ✅ | ✅ |
| Client-ready HTML + PDF engagement report | ✅ | ❌ | ❌ | ❌ |
| No SDK — pure `kubectl` queries | ✅ | ✅ | ❌ | ❌ |

- **kube-bench** specializes in CIS benchmark checks at the node/control-plane level (SSH/manifest-based) and excels at that scope; it does not analyze RBAC bindings, runtime pod configurations, or secret exposure in workloads.
- **Kubescape** is a broad compliance scanner with a large framework library, but requires deploying an in-cluster agent for full coverage; vamp-k8s-audit needs only `kubectl` read permissions.
- **Trivy (k8s mode)** focuses on image vulnerability scanning and misconfiguration detection, but its findings are not structured for client-delivery reporting and it has no `--delta` comparison mode.
- vamp-k8s-audit is the only tool in this comparison with an **extensible YAML rules engine** (add checks as data without modifying Python) and a built-in `--delta FILE` mode to track security posture changes between consecutive audits.

---

## Check Coverage

| Check ID | Phase | Description | Severity | Standard |
|----------|-------|-------------|----------|----------|
| K8S-001 | 1 — Cluster Context | Anonymous API access enabled | CRITICAL | CIS K8S Benchmark 1.2.1 |
| K8S-010 | 2 — RBAC | ServiceAccount bound to `cluster-admin` ClusterRole | CRITICAL | CIS K8S 5.1.1 |
| K8S-017 | 2 — RBAC | ClusterRole with wildcard (`*`) on resources | HIGH | CIS K8S 5.1.3 |
| K8S-031 | 3 — Pod Security | Privileged container (`privileged: true`) | CRITICAL | CIS K8S 5.2.1 |
| K8S-038 | 3 — Pod Security | `allowPrivilegeEscalation` not set to false | HIGH | CIS K8S 5.2.5 |
| K8S-045 | 3 — Pod Security | Missing CPU / memory resource limits | MEDIUM | CIS K8S 5.2.4 |
| K8S-062 | 4 — Network | Namespace has no NetworkPolicy defined | HIGH | CIS K8S 5.3.2 |
| K8S-068 | 4 — Network | Ingress without TLS / missing HTTPS redirect | MEDIUM | CIS K8S 5.4.1 |
| K8S-081 | 5 — Secrets | Secret value exposed as plain environment variable | HIGH | CIS K8S 5.4.1 |
| K8S-ETCD-001 | 10 — Control Plane | etcd peer TLS not enabled | CRITICAL | CIS K8S 2.1 |
| K8S-KCM-003 | 10 — Control Plane | `kube-controller-manager` profiling enabled | MEDIUM | CIS K8S 1.3.2 |
| K8S-KSCHED-001 | 10 — Control Plane | `kube-scheduler` profiling enabled | MEDIUM | CIS K8S 1.4.1 |

---

## Legal Notice

This tool is intended for **authorized security audits only**. Using it against
clusters you do not have explicit permission to test is illegal and unethical.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
All rights reserved. Authorized use only.

---

## Phase 10 — Control Plane CIS (`--control-plane`)

Inspects control plane component manifest files (`/etc/kubernetes/manifests/`) on the cluster nodes to verify CIS Kubernetes Benchmark compliance. Requires SSH access or a tool that can read node manifests.

```bash
python3 vamp_k8s_audit.py --control-plane
python3 vamp_k8s_audit.py --control-plane --report-html control-plane-report.html
```

| Component | Check IDs | Count | Key Controls |
|---|---|---|---|
| etcd | K8S-ETCD-001..008 | 8 | TLS client certs, peer TLS, auto-tls disabled, cert/key permissions |
| kube-controller-manager | K8S-KCM-001..008 | 8 | Profiling disabled, service account credentials, TLS cipher suites |
| kube-scheduler | K8S-KSCHED-001..003 | 3 | Profiling disabled, TLS configuration |
| kubelet | K8S-KUBELET-001 | 1 | Anonymous authentication disabled |

---

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v3.1.0 | **+14 checks YAML** · `cis_admission_audit.yaml`: ValidatingWebhook/MutatingWebhook `failurePolicy:Ignore` (HIGH), webhook `sideEffects:Some/Unknown` (MEDIUM), Pod seccompProfile ausente (MEDIUM CIS 5.7.2), `runAsUser:0` en containers+initContainers (HIGH CIS 5.2.6), `capabilities.add` (HIGH CIS 5.2.9), PodSecurityPolicy `privileged:true` (HIGH CIS 5.2.1), PV/SC `reclaimPolicy:Delete` (MEDIUM), SC sin `allowVolumeExpansion` (LOW), namespace sin ResourceQuota/LimitRange (MEDIUM/LOW) · **58 checks totales** · 4 ficheros YAML |
| v3.0.0 | Motor YAML extensible — 3 ficheros `rules/*.yaml`, 44 checks CIS; kube-bench wrapper (`--kube-bench`); 15 operadores `cmd_flag_*`; `--delta FILE` diff mode; paquete importable |
| v2.2.0 | Fase 11 — checks de nodos y kubelet por flags de proceso; operadores `cmd_flag_ge/le/regex`; 27 tests |
| v2.1.0 | Fase 10 delta scan (`--delta FILE`) y YAML engine beta (checks network/RBAC como datos) |
| v2.0.0 | Fase 10 control plane CIS — `--control-plane`, 20 nuevos checks etcd/KCM/scheduler/kubelet |
| v1.3 | Fases 1-6, Phase 6 imágenes, HTML report |
| v1.0 | MVP RBAC + Pod Security + Network + Secrets |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
All rights reserved. Authorized use only.
