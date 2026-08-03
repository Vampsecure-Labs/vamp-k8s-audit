# vamp-k8s-audit

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
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

## Legal Notice

This tool is intended for **authorized security audits only**. Using it against
clusters you do not have explicit permission to test is illegal and unethical.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
All rights reserved. Authorized use only.
