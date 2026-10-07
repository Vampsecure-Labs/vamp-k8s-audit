# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Motor del auditor: wrappers kubectl, logging, K8SAuditor, apply_delta_scan.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ._models import (
    ANSI_RESET, ANSI_BOLD, ANSI_RED, ANSI_YELLOW,
    ANSI_CYAN, ANSI_GREEN, ANSI_DIM,
    _sev_badge,
)
from ._report import Finding

# ---------------------------------------------------------------------------
# Estado global mutable del módulo
# ---------------------------------------------------------------------------

_KUBECTL_CMD: List[str] = []   # inicializado en _inicializar_kubectl / main
_VERBOSE = False

# ---------------------------------------------------------------------------
# Función auxiliar kubectl
# ---------------------------------------------------------------------------


def _kubectl(args: List[str]) -> Optional[Any]:
    """
    Ejecuta un subcomando de kubectl y devuelve el objeto JSON parseado.
    Retorna None si el comando falla o la salida no es JSON válido.
    """
    cmd = _KUBECTL_CMD + args
    try:
        resultado = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if resultado.returncode != 0:
            if _VERBOSE:
                _log_warn(f"kubectl {' '.join(args[:3])} falló: {resultado.stderr.strip()[:200]}")
            return None
        texto = resultado.stdout.strip()
        if not texto:
            return None
        return json.loads(texto)
    except FileNotFoundError:
        print(
            f"\n{ANSI_RED}{ANSI_BOLD}[ERROR]{ANSI_RESET} "
            f"kubectl no encontrado en el PATH.\n"
            f"  Instala kubectl: https://kubernetes.io/docs/tasks/tools/\n"
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        if _VERBOSE:
            _log_warn(f"kubectl {' '.join(args[:3])} timeout (30s)")
        return None
    except json.JSONDecodeError:
        return None


def _kubectl_raw(args: List[str]) -> str:
    """Ejecuta kubectl y devuelve stdout como texto plano. Cadena vacía si falla."""
    cmd = _KUBECTL_CMD + args
    try:
        resultado = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return resultado.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------------------
# Utilidades de logging en consola
# ---------------------------------------------------------------------------


def _log_info(msg: str) -> None:
    print(f"  {ANSI_DIM}·{ANSI_RESET} {msg}")


def _log_warn(msg: str) -> None:
    print(f"  {ANSI_YELLOW}!{ANSI_RESET} {msg}")


def _log_phase(numero: int, titulo: str) -> None:
    print(f"\n{ANSI_BOLD}{ANSI_CYAN}▶ FASE {numero} — {titulo}{ANSI_RESET}")
    print(f"  {'─' * 62}")


def _log_finding(f: Finding) -> None:
    badge = _sev_badge(f.severity)
    print(f"\n  {badge} {ANSI_BOLD}{f.id}{ANSI_RESET} — {f.title}")
    print(f"  {ANSI_DIM}Afectado:{ANSI_RESET} {f.affected}")
    if _VERBOSE and f.evidence:
        for linea in f.evidence.splitlines()[:5]:
            print(f"  {ANSI_DIM}  {linea}{ANSI_RESET}")


def _log_clean(msg: str) -> None:
    print(f"  {ANSI_GREEN}✓{ANSI_RESET} {ANSI_DIM}{msg}{ANSI_RESET}")


# ---------------------------------------------------------------------------
# Inicialización de kubectl y verificación
# ---------------------------------------------------------------------------


def _inicializar_kubectl(args: Any) -> None:
    """Construye _KUBECTL_CMD con los flags globales del CLI."""
    global _KUBECTL_CMD
    cmd = ["kubectl"]
    if args.kubeconfig:
        cmd += ["--kubeconfig", args.kubeconfig]
    if args.context:
        cmd += ["--context", args.context]
    _KUBECTL_CMD = cmd


def set_verbose(value: bool) -> None:
    """Establece el modo verbose."""
    global _VERBOSE
    _VERBOSE = value


def _verificar_kubectl_disponible() -> None:
    """Verifica que kubectl está instalado. Termina con código 1 si no."""
    try:
        resultado = subprocess.run(
            ["kubectl", "version", "--client", "--output", "json"],
            capture_output=True, text=True, timeout=10,
        )
        if resultado.returncode == 0:
            _log_info("kubectl disponible en el sistema")
        else:
            _log_warn(f"kubectl devolvió error: {resultado.stderr.strip()[:100]}")
    except FileNotFoundError:
        print(
            f"\n{ANSI_RED}{ANSI_BOLD}[ERROR]{ANSI_RESET} "
            f"kubectl no está instalado o no está en el PATH.\n"
            f"  Instala kubectl: https://kubernetes.io/docs/tasks/tools/\n"
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(
            f"\n{ANSI_RED}{ANSI_BOLD}[ERROR]{ANSI_RESET} "
            f"kubectl no responde (timeout). Verifica la instalación.\n"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Motor de reglas YAML
# ---------------------------------------------------------------------------

def _load_yaml_checks() -> list:
    try:
        import yaml as _yaml
    except ImportError:
        return []
    rules_dir = Path(__file__).parent / "rules"
    if not rules_dir.exists():
        return []
    loaded: list = []
    for yf in sorted(rules_dir.glob("*.yaml")):
        try:
            data = _yaml.safe_load(yf.read_text(encoding="utf-8")) or {}
            for r in data.get("rules", []):
                if r.get("id") and r.get("op"):
                    loaded.append(r)
        except Exception:
            pass
    return loaded


_YAML_CHECKS: list = _load_yaml_checks()

_OFFICIAL_REGISTRIES = frozenset({
    "docker.io", "gcr.io", "ghcr.io", "registry.k8s.io",
    "k8s.gcr.io", "quay.io", "mcr.microsoft.com",
})

_SECRET_ENV_RE = re.compile(
    r"(?i)(password|passwd|secret|token|key|api_key|apikey|"
    r"credential|cred|auth|private|jwt|bearer)",
)


def _get_nested(obj: Any, path: str) -> "Tuple[bool, Any]":
    """Navega un dict por ruta de puntos. Devuelve (found, value)."""
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def _eval_op_on_item(
    op: str, check_path: str, value: Any, item: Any, item_name: "Optional[str]",
    rule: "Optional[dict]" = None,
) -> "Optional[Tuple[Optional[str], str]]":
    """Evalúa op en un ítem. Devuelve (item_name, evidence) o None si no hay violación."""
    if rule is None:
        rule = {}
    if op == "eq":
        found, actual = _get_nested(item, check_path)
        if found and actual == value:
            return (item_name, f"{check_path} = {actual!r}")
    elif op == "ne":
        found, actual = _get_nested(item, check_path)
        if not found:
            return (item_name, f"{check_path} ausente")
        if actual != value:
            return (item_name, f"{check_path} = {actual!r} (esperado: {value!r})")
    elif op == "present":
        found, _ = _get_nested(item, check_path)
        if found:
            return (item_name, f"{check_path} presente")
    elif op == "absent":
        found, _ = _get_nested(item, check_path)
        if not found:
            return (item_name, f"{check_path} no definido")
    elif op == "list_contains":
        found, lst = _get_nested(item, check_path)
        if found and isinstance(lst, list) and value in lst:
            return (item_name, f"{check_path} contiene {value!r}")
    elif op == "in":
        found, actual = _get_nested(item, check_path)
        if found and isinstance(value, list) and actual in value:
            return (item_name, f"{check_path} = {actual!r}")
    elif op == "ends_with_latest":
        found, image = _get_nested(item, check_path)
        if found and isinstance(image, str):
            img_part = image.split("/")[-1]
            if image.endswith(":latest") or ":" not in img_part:
                return (item_name, f"image = {image!r}")
    elif op == "from_unofficial_registry":
        found, image = _get_nested(item, check_path)
        if found and isinstance(image, str):
            parts = image.split("/")
            if len(parts) >= 3:
                registry = parts[0]
            elif len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
                registry = parts[0]
            else:
                registry = "docker.io"
            if registry not in _OFFICIAL_REGISTRIES:
                return (item_name, f"image {image!r} (registry {registry!r})")
    elif op == "env_has_secret_value":
        found, env_list = _get_nested(item, check_path)
        if found and isinstance(env_list, list):
            for env_item in env_list:
                if isinstance(env_item, dict):
                    name = env_item.get("name", "")
                    if "value" in env_item and _SECRET_ENV_RE.search(name):
                        return (item_name, f"env var {name!r} con valor hardcodeado")
    elif op.startswith("cmd_flag"):
        found, cmd = _get_nested(item, check_path)
        if not found or not isinstance(cmd, list):
            return None
        flag      = rule.get("flag", "")
        flag_key  = flag.split("=")[0] if "=" in flag else flag
        req       = rule.get("required_value", "")
        forbidden = rule.get("forbidden_value", "")
        req_any   = rule.get("required_values", [])

        if op == "cmd_flag_absent":
            # flag (exact string, e.g. "--anonymous-auth=false") no está → hallazgo
            if flag not in cmd:
                return (item_name, f"flag {flag!r} ausente")
        elif op == "cmd_flag_key_absent":
            # la clave del flag (ej. "--audit-log-path") no aparece en ningún elemento
            if not any(c == flag_key or c.startswith(flag_key + "=") for c in cmd):
                return (item_name, f"flag {flag_key!r} no configurado")
        elif op == "cmd_flag_value_missing":
            for c in cmd:
                if c == flag_key or c.startswith(flag_key + "="):
                    val = c.split("=", 1)[1] if "=" in c else ""
                    if req not in val.split(","):
                        return (item_name, f"{flag_key}={val!r} no contiene {req!r}")
                    return None
            return (item_name, f"flag {flag_key!r} no configurado (requiere {req!r})")
        elif op == "cmd_flag_value_contains":
            for c in cmd:
                if c.startswith(flag_key + "="):
                    val = c.split("=", 1)[1]
                    if forbidden in val.split(","):
                        return (item_name, f"{flag_key}={val!r} contiene {forbidden!r}")
                    return None
        elif op == "cmd_flag_value_eq":
            for c in cmd:
                if c.startswith(flag_key + "="):
                    val = c.split("=", 1)[1]
                    if val == forbidden:
                        return (item_name, f"{flag_key}={val!r}")
                    return None
        elif op == "cmd_flag_value_missing_any":
            for c in cmd:
                if c.startswith(flag_key + "="):
                    val_parts = c.split("=", 1)[1].split(",")
                    if any(rv in val_parts for rv in req_any):
                        return None
                    return (item_name, f"{flag_key}={c.split('=',1)[1]!r} sin ninguno de {req_any}")
            return (item_name, f"flag {flag_key!r} no configurado (requiere uno de {req_any})")
    return None


def _eval_yaml_rule(rule: dict, resource: dict) -> list:
    """Evalúa una regla YAML contra un recurso. Devuelve lista de (name, evidence)."""
    op               = rule.get("op", "")
    check_path       = rule.get("check_path", "")
    value            = rule.get("value")
    foreach_path     = rule.get("foreach_path", "")
    filter_container = rule.get("filter_container", "")
    violations: list = []

    if foreach_path:
        found_list, items = _get_nested(resource, foreach_path)
        if found_list and isinstance(items, list):
            for item in items:
                item_name = item.get("name", "?") if isinstance(item, dict) else "?"
                if filter_container and item_name != filter_container:
                    continue
                viol = _eval_op_on_item(op, check_path, value, item, item_name, rule)
                if viol is not None:
                    violations.append(viol)
    else:
        viol = _eval_op_on_item(op, check_path, value, resource, None, rule)
        if viol is not None:
            violations.append(viol)
    return violations


# ---------------------------------------------------------------------------
# Clase principal del auditor
# ---------------------------------------------------------------------------

class K8SAuditor:
    """
    Auditor de seguridad para clústeres Kubernetes.
    Ejecuta 9+ fases de análisis mediante kubectl y acumula los hallazgos.
    """

    def __init__(
        self,
        context:              Optional[str],
        namespace:            Optional[str],
        skip_images:          bool = False,
        skip_cve:             bool = False,
        audit_helm:           bool = False,
        audit_control_plane:  bool = False,
    ) -> None:
        self.context              = context
        self.namespace            = namespace
        self.skip_images          = skip_images
        self.skip_cve             = skip_cve
        self.audit_helm           = audit_helm
        self.audit_control_plane  = audit_control_plane
        self.findings:            List[Finding] = []
        self._server_url:         str = ""

    # ── Helpers internos ───────────────────────────────────────────────────

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)
        _log_finding(finding)

    def _ns_filter(self) -> List[str]:
        if self.namespace:
            return ["-n", self.namespace]
        return ["--all-namespaces"]

    # ── Fase 1: Contexto del clúster ──────────────────────────────────────

    def fase1_contexto(self) -> None:
        _log_phase(1, "Contexto del clúster")

        version_data = _kubectl(["version", "--output", "json"])
        servidor_ver = "Desconocida"
        cliente_ver  = "Desconocida"
        if version_data:
            servidor_ver = (
                version_data.get("serverVersion", {}).get("gitVersion", "Desconocida")
            )
            cliente_ver = (
                version_data.get("clientVersion", {}).get("gitVersion", "Desconocida")
            )
            _log_info(f"Versión servidor: {servidor_ver}  |  Cliente kubectl: {cliente_ver}")
        else:
            _log_warn("No se pudo obtener la versión del servidor")

        nodos_data = _kubectl(["get", "nodes", "-o", "json"])
        num_nodos  = 0
        if nodos_data:
            items = nodos_data.get("items", [])
            num_nodos = len(items)
            _log_info(f"Nodos en el clúster: {num_nodos}")
            versiones_set = set()
            for nodo in items:
                kv = nodo.get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "")
                if kv:
                    versiones_set.add(kv)
            if len(versiones_set) > 1:
                self._add(Finding(
                    id          = "K8S-002",
                    title       = "Nodos con versiones de kubelet heterogéneas",
                    severity    = "MEDIUM",
                    description = (
                        "El clúster tiene nodos ejecutando diferentes versiones de kubelet. "
                        "Las diferencias de versión pueden dificultar la aplicación consistente "
                        "de parches de seguridad y generar comportamientos inesperados."
                    ),
                    evidence    = f"Versiones detectadas: {', '.join(sorted(versiones_set))}",
                    affected    = f"Clúster ({num_nodos} nodos)",
                    remediation = (
                        "Homogeneizar la versión de kubelet en todos los nodos del clúster. "
                        "Planificar actualizaciones coordinadas con ventanas de mantenimiento."
                    ),
                    tags        = ["nodos", "versiones", "actualizaciones"],
                ))
            else:
                _log_clean("Versión de kubelet homogénea en todos los nodos")

            for nodo in items:
                nombre_nodo = nodo.get("metadata", {}).get("name", "?")
                condiciones = nodo.get("status", {}).get("conditions", [])
                ready = any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in condiciones
                )
                if not ready:
                    self._add(Finding(
                        id          = "K8S-003",
                        title       = "Nodo no está en estado Ready",
                        severity    = "HIGH",
                        description = (
                            f"El nodo '{nombre_nodo}' no se encuentra en estado Ready. "
                            "Los nodos en estado degradado pueden generar pods mal programados "
                            "o con restricciones de seguridad no aplicadas."
                        ),
                        evidence    = f"Nodo: {nombre_nodo} — Ready=False/Unknown",
                        affected    = f"nodo/{nombre_nodo}",
                        remediation = (
                            "Investigar el estado del nodo con 'kubectl describe node <nombre>'. "
                            "Verificar recursos, kubelet y condiciones de red."
                        ),
                        tags        = ["nodos", "disponibilidad"],
                    ))
        else:
            _log_warn("No se pudo listar los nodos (¿permisos insuficientes?)")

        ns_data = _kubectl(["get", "namespaces", "-o", "json"])
        namespaces = []
        if ns_data:
            namespaces = [
                ns.get("metadata", {}).get("name", "")
                for ns in ns_data.get("items", [])
            ]
            _log_info(f"Namespaces encontrados: {len(namespaces)} — {', '.join(namespaces[:8])}")
        else:
            _log_warn("No se pudo listar namespaces")

        pod_count_total = 0
        if self.namespace:
            pods_data = _kubectl(["get", "pods", "-n", self.namespace, "-o", "json"])
            if pods_data:
                pod_count_total = len(pods_data.get("items", []))
                _log_info(f"Pods en namespace '{self.namespace}': {pod_count_total}")
        else:
            pods_data_all = _kubectl(["get", "pods", "--all-namespaces", "-o", "json"])
            if pods_data_all:
                pod_count_total = len(pods_data_all.get("items", []))
                _log_info(f"Pods totales en el clúster: {pod_count_total}")

        self._server_url = self._detectar_server_url()
        if self._server_url:
            _log_info(f"Verificando acceso anónimo al API server: {self._server_url}")
            if self._check_anonimo(self._server_url):
                self._add(Finding(
                    id          = "K8S-001",
                    title       = "API server accesible sin autenticación",
                    severity    = "CRITICAL",
                    description = (
                        "El API server de Kubernetes responde a peticiones sin credenciales "
                        "y devuelve datos del clúster. Esto permite a cualquier actor de red "
                        "enumerar recursos, leer secretos y potencialmente ejecutar cargas de "
                        "trabajo arbitrarias dependiendo de los permisos del usuario anónimo."
                    ),
                    evidence    = f"GET {self._server_url}/api → HTTP 200 sin Authorization",
                    affected    = self._server_url,
                    remediation = (
                        "Configurar el API server con --anonymous-auth=false. "
                        "Verificar que no existan ClusterRoleBindings para system:anonymous. "
                        "Revisar el NetworkPolicy que protege el API server."
                    ),
                    cvss        = 10.0,
                    tags        = ["api-server", "autenticación", "acceso-anónimo"],
                    references  = [
                        "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests"
                    ],
                ))
            else:
                _log_clean("API server requiere autenticación")
        else:
            _log_warn("No se pudo determinar la URL del API server")

        sensibles = ["monitoring", "logging", "metrics", "prometheus", "grafana", "istio-system"]
        for ns_sens in sensibles:
            if ns_sens in namespaces:
                _log_info(f"Namespace sensible detectado: {ns_sens} (se verificará en fases posteriores)")

        self._check_api_server_extended(pods_count_total=pod_count_total)

    def _detectar_server_url(self) -> str:
        texto = _kubectl_raw(["config", "view", "--minify", "-o",
                              "jsonpath={.clusters[0].cluster.server}"])
        return texto.strip()

    def _check_anonimo(self, server_url: str) -> bool:
        import urllib.request
        import urllib.error
        import ssl
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = f"{server_url}/api"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                cuerpo = resp.read(512).decode("utf-8", errors="replace")
                return '"apiVersion"' in cuerpo or '"versions"' in cuerpo
        except Exception:
            return False

    def _check_api_server_extended(self, pods_count_total: int = 0) -> None:
        anon_config = _kubectl_raw(
            ["get", "configmap", "kubeadm-config", "-n", "kube-system", "-o", "yaml"]
        )
        version_data = _kubectl(["version", "--output", "json"])
        version_str = ""
        if version_data:
            version_str = version_data.get("serverVersion", {}).get("gitVersion", "")
        version_vulnerable = False
        if version_str:
            try:
                partes_ver = re.findall(r"v(\d+)\.(\d+)", version_str)
                if partes_ver:
                    major_v, minor_v = int(partes_ver[0][0]), int(partes_ver[0][1])
                    if major_v == 1 and minor_v < 28:
                        version_vulnerable = True
            except (ValueError, IndexError):
                pass
        anon_false_explicito = (
            "anonymous-auth: false" in anon_config.lower() if anon_config else False
        )
        if not anon_false_explicito and version_vulnerable:
            self._add(Finding(
                id          = "K8S-API-005",
                title       = "Autenticación anónima posiblemente habilitada en API server",
                severity    = "HIGH",
                description = (
                    f"El clúster ejecuta Kubernetes {version_str} (< 1.28) y no se detecta "
                    "la opción --anonymous-auth=false de forma explícita en la configuración "
                    "de kubeadm."
                ),
                evidence    = (
                    f"Versión del servidor: {version_str}\n"
                    "anonymous-auth=false no detectado en kubeadm-config"
                ),
                affected    = "kube-apiserver",
                remediation = (
                    "Añadir --anonymous-auth=false al kube-apiserver."
                ),
                cvss        = 7.5,
                tags        = ["api-server", "autenticación", "anónimo"],
                references  = [
                    "https://kubernetes.io/docs/reference/access-authn-authz/authentication/"
                ],
            ))
        else:
            _log_clean("Autenticación anónima del API server: sin riesgo detectado")

        pods_data_all = _kubectl(["get", "pods", "--all-namespaces", "-o", "json"])
        if pods_data_all and pods_count_total > 0:
            total_pods    = pods_count_total
            items_pods    = pods_data_all.get("items", [])
            con_automount = 0
            for pod in items_pods:
                spec_p = pod.get("spec", {}) or {}
                automount_p = spec_p.get("automountServiceAccountToken")
                if automount_p is None or automount_p is True:
                    con_automount += 1
            if total_pods > 0:
                porcentaje = (con_automount / total_pods) * 100
                if porcentaje > 50:
                    self._add(Finding(
                        id          = "K8S-API-006",
                        title       = "Más del 50% de pods con automount de service account token",
                        severity    = "MEDIUM",
                        description = (
                            f"{con_automount} de {total_pods} pods ({porcentaje:.0f}%) tienen "
                            "automountServiceAccountToken habilitado (valor por defecto o explícito)."
                        ),
                        evidence    = (
                            f"Pods con automount token: {con_automount}/{total_pods} "
                            f"({porcentaje:.0f}%)"
                        ),
                        affected    = f"{con_automount} pods en el clúster",
                        remediation = (
                            "Establecer automountServiceAccountToken: false en los pods que "
                            "no necesiten acceder a la API de Kubernetes."
                        ),
                        cvss        = 5.4,
                        tags        = ["api-server", "serviceaccount", "tokens", "automount"],
                        references  = [
                            "https://kubernetes.io/docs/tasks/configure-pod-container/"
                            "configure-service-account/#opt-out-of-api-credential-automounting"
                        ],
                    ))
                else:
                    _log_clean(
                        f"Automount tokens: {porcentaje:.0f}% de pods — "
                        "dentro del umbral aceptable"
                    )
        else:
            _log_info("No se pudo verificar automount de tokens (datos insuficientes)")

    # ── Fase 2: Control de acceso RBAC ────────────────────────────────────

    def fase2_rbac(self) -> None:
        _log_phase(2, "Control de acceso RBAC")

        crb_data = _kubectl(["get", "clusterrolebindings", "-o", "json"])
        if crb_data:
            for crb in crb_data.get("items", []):
                nombre_crb  = crb.get("metadata", {}).get("name", "?")
                role_ref    = crb.get("roleRef", {})
                role_nombre = role_ref.get("name", "")
                if role_nombre != "cluster-admin":
                    continue
                subjects = crb.get("subjects", []) or []
                for subj in subjects:
                    kind    = subj.get("kind", "")
                    sname   = subj.get("name", "")
                    sns     = subj.get("namespace", "")
                    if sname in ("system:masters", "system:admin"):
                        continue
                    if kind == "ServiceAccount":
                        self._add(Finding(
                            id          = "K8S-010",
                            title       = "ServiceAccount con privilegios cluster-admin",
                            severity    = "CRITICAL",
                            description = (
                                f"La ServiceAccount '{sname}' en namespace '{sns}' tiene "
                                "el rol cluster-admin asignado directamente vía "
                                f"ClusterRoleBinding '{nombre_crb}'."
                            ),
                            evidence    = (
                                f"ClusterRoleBinding: {nombre_crb}\n"
                                f"Subject: ServiceAccount/{sname} (ns: {sns or 'cluster-level'})\n"
                                f"Role: {role_nombre}"
                            ),
                            affected    = f"SA/{sname} (ns: {sns or '-'})",
                            remediation = (
                                "Eliminar o limitar el ClusterRoleBinding. Asignar solo los "
                                "permisos mínimos necesarios (principio de mínimo privilegio)."
                            ),
                            cvss        = 9.8,
                            tags        = ["rbac", "cluster-admin", "serviceaccount"],
                            references  = [
                                "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
                            ],
                        ))
                    elif kind in ("User", "Group"):
                        self._add(Finding(
                            id          = "K8S-010",
                            title       = "Usuario/Grupo con privilegios cluster-admin",
                            severity    = "CRITICAL",
                            description = (
                                f"El {kind} '{sname}' tiene el rol cluster-admin asignado "
                                f"vía ClusterRoleBinding '{nombre_crb}'."
                            ),
                            evidence    = (
                                f"ClusterRoleBinding: {nombre_crb}\n"
                                f"Subject: {kind}/{sname}\nRole: {role_nombre}"
                            ),
                            affected    = f"{kind}/{sname}",
                            remediation = (
                                "Revisar si el acceso cluster-admin es realmente necesario. "
                                "Crear roles con permisos específicos y limitados."
                            ),
                            cvss        = 9.8,
                            tags        = ["rbac", "cluster-admin"],
                        ))
            _log_clean("Revisión de ClusterRoleBindings completada")
        else:
            _log_warn("No se pudieron obtener ClusterRoleBindings")

        cr_data = _kubectl(["get", "clusterroles", "-o", "json"])
        if cr_data:
            for cr in cr_data.get("items", []):
                nombre_cr = cr.get("metadata", {}).get("name", "?")
                if nombre_cr.startswith("system:"):
                    continue
                reglas = cr.get("rules", []) or []
                for regla in reglas:
                    verbos    = regla.get("verbs", [])
                    recursos  = regla.get("resources", [])
                    api_grups = regla.get("apiGroups", [])
                    if "*" in verbos and "*" in recursos:
                        self._add(Finding(
                            id          = "K8S-011",
                            title       = "ClusterRole con permisos wildcard totales",
                            severity    = "CRITICAL",
                            description = (
                                f"El ClusterRole '{nombre_cr}' contiene una regla con "
                                "verbos=['*'] y recursos=['*'], otorgando permisos totales "
                                "sobre todos los recursos del clúster. Equivale a cluster-admin."
                            ),
                            evidence    = (
                                f"ClusterRole: {nombre_cr}\n"
                                f"Regla: apiGroups={api_grups}, "
                                f"resources=['*'], verbs=['*']"
                            ),
                            affected    = f"ClusterRole/{nombre_cr}",
                            remediation = (
                                "Reemplazar las reglas wildcard por permisos explícitos y "
                                "limitados. Aplicar el principio de mínimo privilegio."
                            ),
                            cvss        = 9.1,
                            tags        = ["rbac", "wildcard", "clusterrole"],
                        ))
                        break
            _log_clean("Revisión de ClusterRoles completada")
        else:
            _log_warn("No se pudieron obtener ClusterRoles")

        rb_data = _kubectl(["get", "rolebindings"] + self._ns_filter() + ["-o", "json"])
        if rb_data:
            for rb in rb_data.get("items", []):
                nombre_rb  = rb.get("metadata", {}).get("name", "?")
                ns_rb      = rb.get("metadata", {}).get("namespace", "?")
                role_ref   = rb.get("roleRef", {})
                if role_ref.get("name") == "cluster-admin":
                    subjects = rb.get("subjects", []) or []
                    for subj in subjects:
                        self._add(Finding(
                            id          = "K8S-012",
                            title       = "RoleBinding asignando cluster-admin en namespace",
                            severity    = "HIGH",
                            description = (
                                f"El RoleBinding '{nombre_rb}' en namespace '{ns_rb}' "
                                "referencia el ClusterRole 'cluster-admin'."
                            ),
                            evidence    = (
                                f"RoleBinding: {nombre_rb} (ns: {ns_rb})\n"
                                f"Subject: {subj.get('kind', '?')}/{subj.get('name', '?')}\n"
                                f"RoleRef: cluster-admin"
                            ),
                            affected    = f"RoleBinding/{nombre_rb} (ns: {ns_rb})",
                            remediation = (
                                "Usar Roles específicos del namespace en lugar de referenciar "
                                "ClusterRoles con privilegios elevados."
                            ),
                            cvss        = 8.1,
                            tags        = ["rbac", "rolebinding", "cluster-admin"],
                        ))
            _log_clean("Revisión de RoleBindings completada")
        else:
            _log_warn("No se pudieron obtener RoleBindings")

        sa_data = _kubectl(["get", "serviceaccounts"] + self._ns_filter() + ["-o", "json"])
        if sa_data:
            sas_con_automount = []
            for sa in sa_data.get("items", []):
                sa_nombre  = sa.get("metadata", {}).get("name", "?")
                sa_ns      = sa.get("metadata", {}).get("namespace", "?")
                automount  = sa.get("automountServiceAccountToken")
                if automount is None or automount is True:
                    sas_con_automount.append(f"{sa_ns}/{sa_nombre}")
            if len(sas_con_automount) > 20:
                _log_info(f"ServiceAccounts con automount token habilitado: {len(sas_con_automount)}")
        else:
            _log_warn("No se pudieron obtener ServiceAccounts")

        self._check_sa_default_bindings()
        self._check_anonimo_permisos()

    def _check_sa_default_bindings(self) -> None:
        crb_data = _kubectl(["get", "clusterrolebindings", "-o", "json"])
        rb_data  = _kubectl(["get", "rolebindings"] + self._ns_filter() + ["-o", "json"])
        hallados = []
        for coleccion in [crb_data, rb_data]:
            if not coleccion:
                continue
            for binding in coleccion.get("items", []):
                subjects = binding.get("subjects", []) or []
                for subj in subjects:
                    if (subj.get("kind") == "ServiceAccount"
                            and subj.get("name") == "default"):
                        nombre = binding.get("metadata", {}).get("name", "?")
                        ns     = binding.get("metadata", {}).get("namespace", "")
                        hallados.append(f"{nombre} (ns: {ns or 'cluster'})")
        if hallados:
            self._add(Finding(
                id          = "K8S-013",
                title       = "ServiceAccount 'default' tiene permisos RBAC asignados",
                severity    = "HIGH",
                description = (
                    "La ServiceAccount 'default' tiene uno o más RoleBindings asignados. "
                    "Todos los pods que no especifiquen serviceAccountName usan 'default'."
                ),
                evidence    = "Bindings que incluyen SA/default:\n" + "\n".join(hallados[:10]),
                affected    = "ServiceAccount/default",
                remediation = (
                    "Eliminar los bindings de la SA 'default'. "
                    "Crear SAs dedicadas con permisos específicos para cada aplicación."
                ),
                cvss        = 7.5,
                tags        = ["rbac", "serviceaccount", "default"],
            ))
        else:
            _log_clean("ServiceAccount 'default' sin permisos RBAC adicionales")

    def _check_anonimo_permisos(self) -> None:
        texto = _kubectl_raw(["auth", "can-i", "--list", "--as=system:anonymous"])
        if not texto:
            _log_info("No se pudo verificar permisos de system:anonymous")
            return
        lineas_perm = [
            l for l in texto.splitlines()
            if l.strip() and not l.startswith("Resources") and not l.startswith("---")
            and "no" not in l.lower()[:6]
        ]
        if lineas_perm:
            self._add(Finding(
                id          = "K8S-014",
                title       = "Usuario anónimo (system:anonymous) tiene permisos en el clúster",
                severity    = "CRITICAL",
                description = (
                    "El usuario system:anonymous tiene permisos sobre recursos del clúster."
                ),
                evidence    = "Permisos anónimos detectados:\n" + "\n".join(lineas_perm[:15]),
                affected    = "system:anonymous",
                remediation = (
                    "Ejecutar: kubectl delete clusterrolebinding <nombre-binding-anonimo>. "
                    "Deshabilitar acceso anónimo en kube-apiserver con --anonymous-auth=false."
                ),
                cvss        = 9.8,
                tags        = ["rbac", "anónimo", "autenticación"],
                references  = [
                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-subjects"
                ],
            ))
        else:
            _log_clean("system:anonymous sin permisos detectados en el clúster")

    # ── Fase 3: Seguridad de pods y contenedores ───────────────────────────

    def fase3_pods(self) -> None:
        _log_phase(3, "Seguridad de pods y contenedores")

        pods_data = _kubectl(["get", "pods"] + self._ns_filter() + ["-o", "json"])
        if not pods_data:
            _log_warn("No se pudieron obtener pods (¿permisos insuficientes?)")
            return

        pods = pods_data.get("items", [])
        _log_info(f"Analizando {len(pods)} pods...")

        contadores: Dict[str, int] = {k: 0 for k in [
            "privileged", "root", "escalation", "caps",
            "hostpid", "hostipc", "hostnet", "mounts_sensibles",
            "sin_limits", "sin_probes",
        ]}

        CAPS_CRITICAS   = {"CAP_SYS_ADMIN", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE",
                           "NET_RAW", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
                           "SYS_PACCT", "SYS_NICE", "SYS_TTY_CONFIG", "ALL"}
        CAPS_ALTAS      = {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE",
                           "CAP_SYS_MODULE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"}
        RUTAS_SENSIBLES = {"/etc", "/proc", "/sys", "/var/run/docker.sock",
                           "/run/docker.sock", "/var/run/containerd",
                           "/run/containerd", "/", "/root", "/home",
                           "/var/lib/kubelet", "/usr/local/bin"}

        for pod in pods:
            meta_pod  = pod.get("metadata", {})
            spec_pod  = pod.get("spec", {})
            pod_ns    = meta_pod.get("namespace", "?")
            pod_name  = meta_pod.get("name", "?")
            afectado  = f"{pod_ns}/{pod_name}"
            pod_sc = spec_pod.get("securityContext", {}) or {}

            if spec_pod.get("hostPID") is True:
                contadores["hostpid"] += 1
                self._add(Finding(
                    id          = "K8S-034",
                    title       = "Pod comparte PID namespace del host",
                    severity    = "CRITICAL",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostPID=true."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostPID=true",
                    affected    = afectado,
                    remediation = "Eliminar hostPID: true de la spec del pod.",
                    cvss        = 9.0,
                    tags        = ["pod", "hostpid", "escalada"],
                ))

            if spec_pod.get("hostIPC") is True:
                contadores["hostipc"] += 1
                self._add(Finding(
                    id          = "K8S-035",
                    title       = "Pod comparte IPC namespace del host",
                    severity    = "HIGH",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostIPC=true."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostIPC=true",
                    affected    = afectado,
                    remediation = "Eliminar hostIPC: true de la spec del pod.",
                    cvss        = 7.5,
                    tags        = ["pod", "hostipc", "escalada"],
                ))

            if spec_pod.get("hostNetwork") is True:
                contadores["hostnet"] += 1
                self._add(Finding(
                    id          = "K8S-036",
                    title       = "Pod comparte red del host",
                    severity    = "HIGH",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostNetwork=true."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostNetwork=true",
                    affected    = afectado,
                    remediation = (
                        "Eliminar hostNetwork: true. Usar servicios de Kubernetes "
                        "para exponer puertos."
                    ),
                    cvss        = 8.0,
                    tags        = ["pod", "hostnetwork", "red"],
                ))

            contenedores_all = (
                spec_pod.get("initContainers", []) or []
            ) + (
                spec_pod.get("containers", []) or []
            )

            for cont in contenedores_all:
                cont_name = cont.get("name", "?")
                cont_afc  = f"{afectado}/{cont_name}"
                sc = cont.get("securityContext", {}) or {}

                if sc.get("privileged") is True:
                    contadores["privileged"] += 1
                    self._add(Finding(
                        id          = "K8S-030",
                        title       = "Contenedor ejecutándose en modo privilegiado",
                        severity    = "CRITICAL",
                        description = (
                            f"El contenedor '{cont_name}' en pod '{pod_name}' "
                            f"(namespace '{pod_ns}') tiene securityContext.privileged=true."
                        ),
                        evidence    = f"Pod/Contenedor: {cont_afc}\nsecurityContext.privileged: true",
                        affected    = cont_afc,
                        remediation = (
                            "Eliminar securityContext.privileged: true. "
                            "Sustituir por capabilities específicas si son necesarias."
                        ),
                        cvss        = 9.8,
                        tags        = ["contenedor", "privilegiado", "escalada"],
                        references  = [
                            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                        ],
                    ))

                run_as_user    = sc.get("runAsUser")
                run_as_nonroot = sc.get("runAsNonRoot")
                if run_as_user is None:
                    run_as_user = pod_sc.get("runAsUser")
                if run_as_nonroot is None:
                    run_as_nonroot = pod_sc.get("runAsNonRoot")

                es_root = (run_as_user == 0) or (run_as_nonroot is False)
                if es_root:
                    contadores["root"] += 1
                    self._add(Finding(
                        id          = "K8S-031",
                        title       = "Contenedor ejecutándose como usuario root (UID 0)",
                        severity    = "HIGH",
                        description = (
                            f"El contenedor '{cont_name}' en pod '{pod_name}' "
                            f"(namespace '{pod_ns}') está configurado para ejecutarse como root."
                        ),
                        evidence    = (
                            f"Pod/Contenedor: {cont_afc}\n"
                            f"runAsUser={run_as_user}, runAsNonRoot={run_as_nonroot}"
                        ),
                        affected    = cont_afc,
                        remediation = (
                            "Configurar runAsNonRoot: true y runAsUser con UID > 1000."
                        ),
                        cvss        = 7.2,
                        tags        = ["contenedor", "root", "escalada"],
                    ))

                allow_esc = sc.get("allowPrivilegeEscalation")
                if allow_esc is None or allow_esc is True:
                    contadores["escalation"] += 1
                    if allow_esc is True:
                        self._add(Finding(
                            id          = "K8S-032",
                            title       = "Contenedor permite escalada de privilegios",
                            severity    = "HIGH",
                            description = (
                                f"El contenedor '{cont_name}' en pod '{pod_name}' "
                                "tiene allowPrivilegeEscalation: true explícito."
                            ),
                            evidence    = (
                                f"Pod/Contenedor: {cont_afc}\n"
                                f"securityContext.allowPrivilegeEscalation: true"
                            ),
                            affected    = cont_afc,
                            remediation = "Configurar allowPrivilegeEscalation: false.",
                            cvss        = 7.0,
                            tags        = ["contenedor", "escalada-privilegios"],
                        ))

                caps_add = sc.get("capabilities", {}).get("add", []) or []
                caps_add_upper = {c.upper() for c in caps_add}
                caps_criticas_presentes = caps_add_upper & CAPS_CRITICAS
                caps_altas_presentes    = caps_add_upper & CAPS_ALTAS
                if caps_criticas_presentes:
                    contadores["caps"] += 1
                    self._add(Finding(
                        id          = "K8S-033",
                        title       = "Contenedor con capabilities Linux críticas",
                        severity    = "CRITICAL",
                        description = (
                            f"El contenedor '{cont_name}' en pod '{pod_name}' "
                            "tiene capabilities Linux críticas añadidas: "
                            f"{', '.join(sorted(caps_criticas_presentes))}."
                        ),
                        evidence    = (
                            f"Pod/Contenedor: {cont_afc}\n"
                            f"capabilities.add: {sorted(caps_add)}"
                        ),
                        affected    = cont_afc,
                        remediation = "Eliminar las capabilities críticas.",
                        cvss        = 9.0,
                        tags        = ["contenedor", "capabilities", "kernel"],
                    ))
                elif caps_altas_presentes:
                    contadores["caps"] += 1
                    self._add(Finding(
                        id          = "K8S-033",
                        title       = "Contenedor con capabilities Linux elevadas",
                        severity    = "HIGH",
                        description = (
                            f"El contenedor '{cont_name}' en pod '{pod_name}' "
                            "tiene capabilities elevadas: "
                            f"{', '.join(sorted(caps_altas_presentes))}."
                        ),
                        evidence    = (
                            f"Pod/Contenedor: {cont_afc}\n"
                            f"capabilities.add: {sorted(caps_add)}"
                        ),
                        affected    = cont_afc,
                        remediation = "Revisar si las capabilities son estrictamente necesarias.",
                        cvss        = 7.5,
                        tags        = ["contenedor", "capabilities"],
                    ))

                volume_mounts = cont.get("volumeMounts", []) or []
                volumes_pod   = {
                    v.get("name"): v
                    for v in spec_pod.get("volumes", []) or []
                }
                for vm in volume_mounts:
                    vol_name   = vm.get("name", "")
                    mount_path = vm.get("mountPath", "")
                    vol_spec   = volumes_pod.get(vol_name, {})
                    host_path  = vol_spec.get("hostPath", {}).get("path", "")
                    if host_path in RUTAS_SENSIBLES or any(
                        host_path.startswith(ruta) for ruta in RUTAS_SENSIBLES
                    ):
                        contadores["mounts_sensibles"] += 1
                        es_socket = "docker.sock" in host_path or "containerd" in host_path
                        self._add(Finding(
                            id          = "K8S-037",
                            title       = (
                                "Montaje del socket del container runtime"
                                if es_socket else
                                "Montaje de ruta sensible del host"
                            ),
                            severity    = "CRITICAL" if es_socket else "HIGH",
                            description = (
                                f"El contenedor '{cont_name}' monta la ruta del host "
                                f"'{host_path}' en '{mount_path}'."
                            ),
                            evidence    = (
                                f"Pod/Contenedor: {cont_afc}\n"
                                f"hostPath: {host_path}\nmountPath: {mount_path}"
                            ),
                            affected    = cont_afc,
                            remediation = (
                                "Eliminar el mountPath al runtime socket."
                                if es_socket else
                                f"Eliminar o restringir el montaje de '{host_path}'."
                            ),
                            cvss        = 9.8 if es_socket else 8.0,
                            tags        = ["contenedor", "hostpath", "montaje"],
                        ))

                resources   = cont.get("resources", {}) or {}
                limits      = resources.get("limits", {}) or {}
                if not limits:
                    contadores["sin_limits"] += 1

                has_ready  = bool(cont.get("readinessProbe"))
                has_live   = bool(cont.get("livenessProbe"))
                if not has_ready and not has_live:
                    contadores["sin_probes"] += 1

        if contadores["sin_limits"] > 0:
            self._add(Finding(
                id          = "K8S-038",
                title       = "Pods sin límites de recursos definidos",
                severity    = "LOW",
                description = (
                    f"{contadores['sin_limits']} contenedor(es) no tienen definidos "
                    "resource.limits (CPU y/o memoria)."
                ),
                evidence    = (
                    f"Contenedores sin limits: {contadores['sin_limits']} de "
                    f"{sum(contadores.values())} analizados"
                ),
                affected    = "Múltiples pods — ver salida verbose",
                remediation = (
                    "Definir resources.limits.cpu y resources.limits.memory en todos los "
                    "contenedores."
                ),
                tags        = ["recursos", "dos", "limits"],
                references  = [
                    "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
                ],
            ))

        if contadores["sin_probes"] > 0:
            self._add(Finding(
                id          = "K8S-039",
                title       = "Pods sin readinessProbe ni livenessProbe",
                severity    = "INFO",
                description = (
                    f"{contadores['sin_probes']} contenedor(es) no tienen definidas "
                    "readinessProbe ni livenessProbe."
                ),
                evidence    = f"Contenedores sin probes: {contadores['sin_probes']}",
                affected    = "Múltiples pods",
                remediation = (
                    "Definir livenessProbe y readinessProbe en todos los contenedores."
                ),
                tags        = ["pods", "health", "probes"],
            ))

        _log_info(
            f"Análisis de pods completado — privilegiados: {contadores['privileged']}, "
            f"root: {contadores['root']}, montajes sensibles: {contadores['mounts_sensibles']}"
        )

    # ── Fase 4: Red y exposición ───────────────────────────────────────────

    def fase4_red(self) -> None:
        _log_phase(4, "Red y exposición")

        svc_data = _kubectl(["get", "services"] + self._ns_filter() + ["-o", "json"])
        if svc_data:
            for svc in svc_data.get("items", []):
                meta_svc   = svc.get("metadata", {})
                spec_svc   = svc.get("spec", {})
                svc_tipo   = spec_svc.get("type", "ClusterIP")
                svc_nombre = meta_svc.get("name", "?")
                svc_ns     = meta_svc.get("namespace", "?")
                puertos    = spec_svc.get("ports", []) or []

                if svc_tipo in ("LoadBalancer", "NodePort"):
                    lb_ips = [
                        ing.get("ip", ing.get("hostname", ""))
                        for ing in (
                            svc.get("status", {})
                               .get("loadBalancer", {})
                               .get("ingress", []) or []
                        )
                        if ing.get("ip") or ing.get("hostname")
                    ]
                    puertos_str = ", ".join(
                        f"{p.get('port', '?')}/{p.get('protocol', 'TCP')}"
                        for p in puertos
                    )
                    is_dashboard = "dashboard" in svc_nombre.lower()
                    afectado = f"svc/{svc_ns}/{svc_nombre}"
                    self._add(Finding(
                        id          = "K8S-060",
                        title       = (
                            "Kubernetes Dashboard expuesto externamente"
                            if is_dashboard else
                            f"Servicio '{svc_tipo}' expuesto externamente"
                        ),
                        severity    = "CRITICAL" if is_dashboard else "HIGH",
                        description = (
                            f"El servicio '{svc_nombre}' en namespace '{svc_ns}' "
                            f"es de tipo {svc_tipo} y está expuesto externamente."
                        ),
                        evidence    = (
                            f"Servicio: {afectado}\nTipo: {svc_tipo}\n"
                            f"Puertos: {puertos_str}\n"
                            f"IPs externas: {', '.join(lb_ips) if lb_ips else 'pendiente/nodeport'}"
                        ),
                        affected    = afectado,
                        remediation = (
                            "Cambiar el tipo de servicio a ClusterIP y exponer a través "
                            "de un Ingress con autenticación."
                        ),
                        cvss        = 9.8 if is_dashboard else 7.5,
                        tags        = ["red", "servicio", svc_tipo.lower()],
                    ))
            _log_clean("Revisión de servicios completada")
        else:
            _log_warn("No se pudieron obtener servicios")

        np_data      = _kubectl(["get", "networkpolicies"] + self._ns_filter() + ["-o", "json"])
        pods_ns_data = _kubectl(["get", "pods"] + self._ns_filter() + ["-o", "json"])
        if np_data and pods_ns_data:
            nps_por_ns: Dict[str, int] = {}
            for np in np_data.get("items", []):
                ns = np.get("metadata", {}).get("namespace", "")
                nps_por_ns[ns] = nps_por_ns.get(ns, 0) + 1

            ns_sin_np: List[str] = []
            ns_con_pods: set = set()
            for pod in pods_ns_data.get("items", []):
                pod_ns = pod.get("metadata", {}).get("namespace", "")
                if pod_ns and not pod_ns.startswith("kube-"):
                    ns_con_pods.add(pod_ns)

            for ns in ns_con_pods:
                if nps_por_ns.get(ns, 0) == 0:
                    ns_sin_np.append(ns)

            if ns_sin_np:
                self._add(Finding(
                    id          = "K8S-061",
                    title       = "Namespaces con pods sin NetworkPolicy definida",
                    severity    = "HIGH",
                    description = (
                        f"{len(ns_sin_np)} namespace(s) con pods no tienen ninguna "
                        "NetworkPolicy."
                    ),
                    evidence    = (
                        "Namespaces sin NetworkPolicy (con pods activos):\n"
                        + "\n".join(ns_sin_np[:20])
                    ),
                    affected    = f"{len(ns_sin_np)} namespaces",
                    remediation = (
                        "Crear una NetworkPolicy de denegación por defecto en cada namespace."
                    ),
                    cvss        = 7.5,
                    tags        = ["red", "networkpolicy", "segmentación"],
                    references  = [
                        "https://kubernetes.io/docs/concepts/services-networking/network-policies/"
                    ],
                ))
            else:
                _log_clean("Todos los namespaces con pods tienen NetworkPolicy")
        else:
            _log_warn("No se pudieron verificar NetworkPolicies")

        ing_data = _kubectl(["get", "ingresses"] + self._ns_filter() + ["-o", "json"])
        if ing_data:
            for ing in ing_data.get("items", []):
                meta_ing   = ing.get("metadata", {})
                spec_ing   = ing.get("spec", {})
                ing_nombre = meta_ing.get("name", "?")
                ing_ns     = meta_ing.get("namespace", "?")
                tls        = spec_ing.get("tls", [])
                rules      = spec_ing.get("rules", [])
                hosts = [r.get("host", "?") for r in rules if r.get("host")]

                if not tls and rules:
                    self._add(Finding(
                        id          = "K8S-062",
                        title       = "Ingress sin TLS configurado",
                        severity    = "MEDIUM",
                        description = (
                            f"El Ingress '{ing_nombre}' en namespace '{ing_ns}' "
                            "no tiene TLS configurado."
                        ),
                        evidence    = (
                            f"Ingress: {ing_ns}/{ing_nombre}\n"
                            f"Hosts: {', '.join(hosts[:5])}\n"
                            f"TLS: no configurado"
                        ),
                        affected    = f"Ingress/{ing_ns}/{ing_nombre}",
                        remediation = (
                            "Añadir una sección 'tls:' al Ingress con el secreto "
                            "que contiene el certificado."
                        ),
                        cvss        = 6.5,
                        tags        = ["red", "ingress", "tls", "http"],
                    ))
            _log_clean("Revisión de Ingress completada")
        else:
            _log_info("No se encontraron recursos Ingress o no hay permisos")

        if self._server_url:
            self._check_etcd_expuesto(self._server_url)
        else:
            _log_info("URL del API server no disponible, omitiendo verificación de etcd")

    def _check_etcd_expuesto(self, server_url: str) -> None:
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(server_url)
            host = parsed.hostname or ""
            if not host or host in ("localhost", "127.0.0.1", "::1"):
                _log_info("API server en localhost, omitiendo verificación remota de etcd")
                return
        except Exception:
            return

        puertos_etcd = [2379, 2380]
        for puerto in puertos_etcd:
            try:
                with socket.create_connection((host, puerto), timeout=3):
                    self._add(Finding(
                        id          = "K8S-064",
                        title       = f"etcd accesible en puerto {puerto}",
                        severity    = "CRITICAL",
                        description = (
                            f"El puerto {puerto} de etcd está accesible en el host '{host}'."
                        ),
                        evidence    = (
                            f"Conexión TCP exitosa a {host}:{puerto}"
                        ),
                        affected    = f"{host}:{puerto}",
                        remediation = (
                            "Restringir el acceso a los puertos 2379/2380 mediante firewall."
                        ),
                        cvss        = 10.0,
                        tags        = ["etcd", "red", "base-de-datos"],
                        references  = [
                            "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
                        ],
                    ))
                    break
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        _log_clean(f"etcd no accesible externamente en {host}")

    # ── Fase 5: Gestión de secretos ────────────────────────────────────────

    def fase5_secretos(self) -> None:
        _log_phase(5, "Gestión de secretos")

        PATRON_NOMBRE_VAR = re.compile(
            r"(password|passwd|secret|token|api[_\-]?key|credential|auth[_\-]?key"
            r"|private[_\-]?key|access[_\-]?key|client[_\-]?secret|db[_\-]?pass"
            r"|database[_\-]?url|redis[_\-]?url|mongo[_\-]?url|mysql[_\-]?url"
            r"|smtp[_\-]?pass|jwt[_\-]?secret|encryption[_\-]?key|signing[_\-]?key)",
            re.IGNORECASE,
        )
        PATRON_VALOR_SECRET = re.compile(
            r"(sk_live_|sk_test_|ghp_|glpat-|xox[baprs]-|ey[A-Za-z0-9]{10,}"
            r"|-----BEGIN [A-Z ]+KEY-----|[A-Za-z0-9+/]{40,}={0,2})",
        )

        pods_data = _kubectl(["get", "pods"] + self._ns_filter() + ["-o", "json"])
        secretos_env_count = 0
        if pods_data:
            for pod in pods_data.get("items", []):
                meta_pod = pod.get("metadata", {})
                pod_ns   = meta_pod.get("namespace", "?")
                pod_name = meta_pod.get("name", "?")
                afectado = f"{pod_ns}/{pod_name}"

                conts = (
                    pod.get("spec", {}).get("containers", []) or []
                ) + (
                    pod.get("spec", {}).get("initContainers", []) or []
                )
                for cont in conts:
                    cont_name = cont.get("name", "?")
                    env_vars  = cont.get("env", []) or []
                    for env in env_vars:
                        var_nombre = env.get("name", "")
                        var_valor  = env.get("value", "")
                        if (PATRON_NOMBRE_VAR.search(var_nombre)
                                and var_valor
                                and not env.get("valueFrom")):
                            secretos_env_count += 1
                            self._add(Finding(
                                id          = "K8S-080",
                                title       = "Secreto en variable de entorno del pod (valor literal)",
                                severity    = "HIGH",
                                description = (
                                    f"El contenedor '{cont_name}' en pod '{pod_name}' "
                                    f"(namespace '{pod_ns}') tiene la variable '{var_nombre}' "
                                    "con un valor literal que parece ser una credencial."
                                ),
                                evidence    = (
                                    f"Pod/Contenedor: {afectado}/{cont_name}\n"
                                    f"Variable: {var_nombre}\n"
                                    f"Valor: {'***REDACTADO***' if var_valor else '(vacío)'}"
                                ),
                                affected    = f"{afectado}/{cont_name}",
                                remediation = (
                                    "Usar secretRef o secretKeyRef en lugar de valores literales."
                                ),
                                cvss        = 7.5,
                                tags        = ["secretos", "env", "credenciales"],
                            ))
                            if secretos_env_count >= 10:
                                break
                    if secretos_env_count >= 10:
                        break
                if secretos_env_count >= 10:
                    break
            _log_clean(f"Revisión de variables de entorno completada ({secretos_env_count} variables sensibles detectadas)")
        else:
            _log_warn("No se pudieron obtener pods para revisión de variables")

        cm_data = _kubectl(["get", "configmaps"] + self._ns_filter() + ["-o", "json"])
        cms_con_secretos = 0
        if cm_data:
            for cm in cm_data.get("items", []):
                meta_cm   = cm.get("metadata", {})
                cm_nombre = meta_cm.get("name", "?")
                cm_ns     = meta_cm.get("namespace", "?")
                datos_cm  = cm.get("data", {}) or {}
                for clave, valor in datos_cm.items():
                    valor_str = str(valor) if valor else ""
                    nombre_clave_sospechoso = bool(PATRON_NOMBRE_VAR.search(clave))
                    valor_sospechoso = (
                        len(valor_str) > 20
                        and bool(PATRON_VALOR_SECRET.search(valor_str))
                    )
                    if nombre_clave_sospechoso or valor_sospechoso:
                        cms_con_secretos += 1
                        self._add(Finding(
                            id          = "K8S-081",
                            title       = "Posible secreto almacenado en ConfigMap",
                            severity    = "MEDIUM",
                            description = (
                                f"El ConfigMap '{cm_nombre}' en namespace '{cm_ns}' "
                                f"contiene la clave '{clave}' cuyo nombre o valor "
                                "sugiere que puede ser una credencial o secreto."
                            ),
                            evidence    = (
                                f"ConfigMap: {cm_ns}/{cm_nombre}\n"
                                f"Clave: {clave}\n"
                                f"Longitud valor: {len(valor_str)} caracteres"
                            ),
                            affected    = f"ConfigMap/{cm_ns}/{cm_nombre}",
                            remediation = "Mover el valor a un Secret de Kubernetes.",
                            cvss        = 5.5,
                            tags        = ["secretos", "configmap", "credenciales"],
                        ))
                        break
            _log_clean(f"Revisión de ConfigMaps completada ({cms_con_secretos} potencialmente expuestos)")
        else:
            _log_warn("No se pudieron obtener ConfigMaps")

        sec_data = _kubectl(["get", "secrets"] + self._ns_filter() + ["-o", "json"])
        if sec_data:
            secrets_items   = sec_data.get("items", [])
            secrets_opaque  = [s for s in secrets_items if s.get("type") == "Opaque"]
            secrets_default = [
                s for s in secrets_opaque
                if s.get("metadata", {}).get("namespace") == "default"
            ]
            _log_info(
                f"Secrets totales: {len(secrets_items)} "
                f"(Opaque: {len(secrets_opaque)}, en namespace 'default': {len(secrets_default)})"
            )
            if secrets_default:
                self._add(Finding(
                    id          = "K8S-082",
                    title       = "Secrets de tipo Opaque en namespace 'default'",
                    severity    = "MEDIUM",
                    description = (
                        f"Se encontraron {len(secrets_default)} Secrets de tipo Opaque "
                        "en el namespace 'default'."
                    ),
                    evidence    = (
                        "Secrets Opaque en namespace 'default':\n"
                        + "\n".join(
                            s.get("metadata", {}).get("name", "?")
                            for s in secrets_default[:15]
                        )
                    ),
                    affected    = "namespace/default",
                    remediation = "Mover los Secrets al namespace de la aplicación que los consume.",
                    cvss        = 5.0,
                    tags        = ["secretos", "namespace", "default"],
                ))
        else:
            _log_warn("No se pudieron obtener Secrets (puede requerir permisos adicionales)")

    # ── Fase 6: Imágenes y runtime ─────────────────────────────────────────

    def fase6_imagenes(self) -> None:
        _log_phase(6, "Imágenes y runtime")

        if self.skip_images:
            _log_info("Análisis de imágenes omitido (--skip-images)")
            return

        pods_data = _kubectl(["get", "pods"] + self._ns_filter() + ["-o", "json"])
        if not pods_data:
            _log_warn("No se pudieron obtener pods para análisis de imágenes")
            return

        REGISTROS_PUBLICOS = {"docker.io", "registry-1.docker.io", "gcr.io",
                               "k8s.gcr.io", "registry.k8s.io", "quay.io",
                               "ghcr.io", "public.ecr.aws", "mcr.microsoft.com"}

        imagenes_latest: List[str]   = []
        imagenes_publicas: List[str] = []
        imagenes_noreadonly: int     = 0

        for pod in pods_data.get("items", []):
            meta_pod = pod.get("metadata", {})
            pod_ns   = meta_pod.get("namespace", "?")
            pod_name = meta_pod.get("name", "?")

            conts = (
                pod.get("spec", {}).get("containers", []) or []
            ) + (
                pod.get("spec", {}).get("initContainers", []) or []
            )

            for cont in conts:
                imagen = cont.get("image", "")
                sc     = cont.get("securityContext", {}) or {}

                tiene_tag = ":" in imagen.split("/")[-1]
                tag_es_latest = imagen.endswith(":latest")
                if not tiene_tag or tag_es_latest:
                    imagenes_latest.append(f"{pod_ns}/{pod_name}: {imagen}")

                partes = imagen.split("/")
                registro = ""
                if len(partes) >= 2 and ("." in partes[0] or ":" in partes[0]):
                    registro = partes[0].lower()
                elif len(partes) == 1:
                    registro = "docker.io"
                if registro in REGISTROS_PUBLICOS:
                    imagenes_publicas.append(f"{pod_ns}/{pod_name}: {imagen}")

                if not sc.get("readOnlyRootFilesystem"):
                    imagenes_noreadonly += 1

        if imagenes_latest:
            self._add(Finding(
                id          = "K8S-090",
                title       = "Imágenes con tag ':latest' o sin tag de versión",
                severity    = "MEDIUM",
                description = (
                    f"{len(imagenes_latest)} imagen(es) usan el tag ':latest' o no "
                    "especifican tag de versión."
                ),
                evidence    = (
                    "Imágenes con :latest o sin tag:\n"
                    + "\n".join(imagenes_latest[:20])
                ),
                affected    = f"{len(imagenes_latest)} contenedores",
                remediation = (
                    "Especificar tags de versión explícitos y fijos (p.ej. nginx:1.25.3)."
                ),
                cvss        = 5.0,
                tags        = ["imágenes", "latest", "reproducibilidad"],
            ))
        else:
            _log_clean("Todas las imágenes tienen tags de versión explícitos")

        if imagenes_publicas:
            self._add(Finding(
                id          = "K8S-092",
                title       = "Imágenes descargadas de registros públicos no verificados",
                severity    = "LOW",
                description = (
                    f"{len(imagenes_publicas)} imagen(es) se descargan de registros públicos."
                ),
                evidence    = (
                    "Imágenes de registros públicos:\n"
                    + "\n".join(imagenes_publicas[:20])
                ),
                affected    = f"{len(imagenes_publicas)} contenedores",
                remediation = (
                    "Usar un registro privado con análisis de vulnerabilidades."
                ),
                tags        = ["imágenes", "registro", "supply-chain"],
            ))
        else:
            _log_clean("No se detectaron imágenes de registros públicos")

        if imagenes_noreadonly > 0:
            self._add(Finding(
                id          = "K8S-093",
                title       = "Contenedores sin filesystem raíz de solo lectura",
                severity    = "LOW",
                description = (
                    f"{imagenes_noreadonly} contenedor(es) no tienen "
                    "readOnlyRootFilesystem: true."
                ),
                evidence    = f"Contenedores sin readOnlyRootFilesystem: {imagenes_noreadonly}",
                affected    = f"{imagenes_noreadonly} contenedores",
                remediation = "Configurar readOnlyRootFilesystem: true en securityContext.",
                tags        = ["imágenes", "filesystem", "runtime"],
            ))

        ns_data = _kubectl(["get", "namespaces", "-o", "json"])
        if ns_data:
            ns_sin_psa: List[str] = []
            for ns in ns_data.get("items", []):
                ns_nombre = ns.get("metadata", {}).get("name", "")
                if ns_nombre.startswith("kube-"):
                    continue
                labels = ns.get("metadata", {}).get("labels", {}) or {}
                tiene_psa = any(
                    k.startswith("pod-security.kubernetes.io/")
                    for k in labels
                )
                if not tiene_psa:
                    ns_sin_psa.append(ns_nombre)
            if ns_sin_psa:
                self._add(Finding(
                    id          = "K8S-094",
                    title       = "Namespaces sin Pod Security Admission configurado",
                    severity    = "MEDIUM",
                    description = (
                        f"{len(ns_sin_psa)} namespace(s) no tienen etiquetas de "
                        "Pod Security Admission (PSA)."
                    ),
                    evidence    = (
                        "Namespaces sin label pod-security.kubernetes.io/enforce:\n"
                        + "\n".join(ns_sin_psa[:20])
                    ),
                    affected    = f"{len(ns_sin_psa)} namespaces",
                    remediation = (
                        "Añadir la etiqueta 'pod-security.kubernetes.io/enforce: restricted' "
                        "a los namespaces de aplicación."
                    ),
                    cvss        = 5.5,
                    tags        = ["psa", "pod-security", "admisión"],
                    references  = [
                        "https://kubernetes.io/docs/concepts/security/pod-security-admission/"
                    ],
                ))
            else:
                _log_clean("Todos los namespaces tienen Pod Security Admission configurado")
        else:
            _log_warn("No se pudieron verificar las etiquetas de PSA en namespaces")

    # ── Fase 7: OPA/Gatekeeper ─────────────────────────────────────────────

    def fase7_opa(self) -> None:
        _log_phase(7, "OPA/Gatekeeper")

        crds_raw = _kubectl_raw(["get", "crd", "--no-headers"])
        gatekeeper_crds = [
            l for l in crds_raw.splitlines()
            if "gatekeeper.sh" in l.lower() or "constraints.gatekeeper" in l.lower()
        ]

        if not gatekeeper_crds:
            self._add(Finding(
                id          = "K8S-OPA-001",
                title       = "OPA/Gatekeeper no está instalado en el clúster",
                severity    = "INFO",
                description = (
                    "No se detectaron CRDs de OPA/Gatekeeper en el clúster."
                ),
                evidence    = "kubectl get crd | grep gatekeeper — sin resultados",
                affected    = "Clúster completo",
                remediation = (
                    "Considerar la instalación de OPA/Gatekeeper."
                ),
                tags        = ["opa", "gatekeeper", "admission-control", "policy"],
            ))
            _log_clean("OPA/Gatekeeper no instalado (recomendación INFO emitida)")
            return

        _log_info(f"OPA/Gatekeeper detectado ({len(gatekeeper_crds)} CRDs encontrados)")

        constraints_data = _kubectl(["get", "constraints", "--all-namespaces", "-o", "json"])
        if not constraints_data or not constraints_data.get("items"):
            self._add(Finding(
                id          = "K8S-OPA-002",
                title       = "OPA/Gatekeeper instalado pero sin constraints definidas",
                severity    = "MEDIUM",
                description = (
                    "OPA/Gatekeeper está instalado pero no hay constraints definidas."
                ),
                evidence    = "kubectl get constraints --all-namespaces — sin resultados",
                affected    = "OPA/Gatekeeper",
                remediation = "Definir constraints de seguridad adecuadas.",
                tags        = ["opa", "gatekeeper", "constraints", "policy"],
            ))
            return

        items = constraints_data.get("items", [])
        _log_info(f"Constraints encontradas: {len(items)}")

        for constraint in items:
            nombre       = constraint.get("metadata", {}).get("name", "desconocida")
            kind         = constraint.get("kind", "Constraint")
            violations   = constraint.get("status", {}).get("violations", [])
            n_violations = len(violations)

            if n_violations > 0:
                partes_evidencia = [f"Constraint: {kind}/{nombre}"]
                for v in violations[:5]:
                    partes_evidencia.append(
                        f"  - {v.get('kind', '?')}/{v.get('name', '?')} "
                        f"en {v.get('namespace', 'cluster')}: "
                        f"{v.get('message', '')[:120]}"
                    )
                if n_violations > 5:
                    partes_evidencia.append(f"  ... y {n_violations - 5} violation(s) adicional(es)")

                self._add(Finding(
                    id          = "K8S-OPA-003",
                    title       = f"Violations activas en constraint OPA: {kind}/{nombre}",
                    severity    = "HIGH",
                    description = (
                        f"La constraint OPA/Gatekeeper '{kind}/{nombre}' tiene "
                        f"{n_violations} violation(s) activa(s)."
                    ),
                    evidence    = "\n".join(partes_evidencia),
                    affected    = f"OPA Constraint: {kind}/{nombre}",
                    remediation = (
                        f"Corregir los recursos que violan la constraint '{nombre}'."
                    ),
                    tags        = ["opa", "gatekeeper", "constraints", "violations", "policy"],
                ))
            else:
                _log_clean(f"Constraint {kind}/{nombre}: sin violations")

    # ── Fase 8: Admission Webhooks ─────────────────────────────────────────

    def fase8_webhooks(self) -> None:
        _log_phase(8, "Admission Webhooks")

        for wh_tipo, wh_recurso in [
            ("Validating", "validatingwebhookconfigurations"),
            ("Mutating",   "mutatingwebhookconfigurations"),
        ]:
            data = _kubectl(["get", wh_recurso, "-o", "json"])
            if not data:
                _log_clean(
                    f"No se encontraron {wh_tipo}WebhookConfigurations "
                    "(o sin acceso para listarlos)"
                )
                continue

            configs = data.get("items", [])
            _log_info(f"{wh_tipo}WebhookConfigurations: {len(configs)} encontrada(s)")

            for config in configs:
                cfg_name = config.get("metadata", {}).get("name", "?")
                webhooks = config.get("webhooks", [])

                for wh in webhooks:
                    wh_name  = wh.get("name", "?")
                    affected = (
                        f"{wh_tipo}WebhookConfiguration/{cfg_name} → {wh_name}"
                    )

                    failure_policy = wh.get("failurePolicy", "Fail")
                    if failure_policy == "Ignore":
                        self._add(Finding(
                            id          = "K8S-WHK-001",
                            title       = f"Webhook con failurePolicy=Ignore: {wh_name}",
                            severity    = "MEDIUM",
                            description = (
                                f"El {wh_tipo.lower()} webhook '{wh_name}' en "
                                f"'{cfg_name}' tiene failurePolicy=Ignore."
                            ),
                            evidence    = f"{affected}\nfailurePolicy: Ignore",
                            affected    = affected,
                            remediation = "Cambiar failurePolicy a 'Fail'.",
                            tags        = ["webhooks", "admission-control", "failure-policy"],
                        ))

                    ns_selector = wh.get("namespaceSelector") or {}
                    sin_selector = (
                        not ns_selector
                        or (
                            not ns_selector.get("matchLabels")
                            and not ns_selector.get("matchExpressions")
                        )
                    )
                    if sin_selector:
                        self._add(Finding(
                            id          = "K8S-WHK-002",
                            title       = (
                                f"Webhook sin namespaceSelector (cubre kube-system): {wh_name}"
                            ),
                            severity    = "HIGH",
                            description = (
                                f"El webhook '{wh_name}' no tiene namespaceSelector definido."
                            ),
                            evidence    = f"{affected}\nnamespaceSelector: {{}}",
                            affected    = affected,
                            remediation = "Añadir un namespaceSelector para excluir kube-system.",
                            tags        = ["webhooks", "admission-control", "namespace-selector"],
                        ))

                    timeout_secs = wh.get("timeoutSeconds", 10)
                    if isinstance(timeout_secs, int) and timeout_secs > 10:
                        self._add(Finding(
                            id          = "K8S-WHK-003",
                            title       = (
                                f"Webhook con timeout elevado ({timeout_secs}s): {wh_name}"
                            ),
                            severity    = "LOW",
                            description = (
                                f"El webhook '{wh_name}' tiene timeoutSeconds={timeout_secs}."
                            ),
                            evidence    = f"{affected}\ntimeoutSeconds: {timeout_secs}",
                            affected    = affected,
                            remediation = "Reducir timeoutSeconds a un máximo de 5-10 segundos.",
                            tags        = ["webhooks", "admission-control", "timeout"],
                        ))

    # ── Fase 9: CVEs activos ───────────────────────────────────────────────

    @staticmethod
    def _parse_runc_version(version_str: str) -> Optional[Tuple[int, int, int, str]]:
        patron = re.search(r"(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9._-]+)?", version_str)
        if not patron:
            return None
        try:
            major   = int(patron.group(1))
            minor   = int(patron.group(2))
            patch   = int(patron.group(3))
            pre     = patron.group(4) or ""
            return (major, minor, patch, pre)
        except (ValueError, IndexError):
            return None

    def _check_cve_runc(self) -> None:
        _log_info("Verificando CVE-2025-52881 (runc container escape)...")

        runtime_versions_raw = _kubectl_raw(
            ["get", "nodes", "-o",
             "jsonpath={.items[*].status.nodeInfo.containerRuntimeVersion}"]
        )

        versiones_candidatas: List[str] = []
        if runtime_versions_raw:
            for token in runtime_versions_raw.split():
                token = token.strip()
                if token:
                    versiones_candidatas.append(token)

        for cmd_local in [["runc", "--version"], ["crictl", "version"]]:
            try:
                resultado = subprocess.run(
                    cmd_local, capture_output=True, text=True, timeout=5,
                )
                if resultado.returncode == 0 and resultado.stdout.strip():
                    versiones_candidatas.append(resultado.stdout.strip())
            except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
                pass

        if not versiones_candidatas:
            self._add(Finding(
                id          = "K8S-RUNC-002",
                title       = "Versión de runc no verificable (CVE-2025-52881)",
                severity    = "HIGH",
                description = (
                    "No se pudo determinar la versión del runtime runc en los nodos."
                ),
                evidence    = "No hay datos de versión disponibles",
                affected    = "Nodos del clúster (versión runc indeterminada)",
                remediation = (
                    "Verificar manualmente la versión de runc en cada nodo."
                ),
                cvss        = 7.8,
                tags        = ["cve", "runc", "container-escape", "CVE-2025-52881"],
                references  = [
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-XXXX"
                ],
            ))
            return

        versiones_vulnerables: List[str] = []
        for ver_raw in versiones_candidatas:
            parsed = self._parse_runc_version(ver_raw)
            if parsed is None:
                continue
            major, minor, patch, pre = parsed
            vulnerable = False
            if major == 1:
                if minor <= 1:
                    vulnerable = True
                elif minor == 2 and patch < 8:
                    vulnerable = True
                elif minor == 3 and patch < 3:
                    vulnerable = True
                elif minor == 4:
                    if patch == 0 and pre and "rc" in pre:
                        rc_match = re.search(r"rc\.?(\d+)", pre)
                        if rc_match and int(rc_match.group(1)) < 3:
                            vulnerable = True
                        elif not rc_match:
                            vulnerable = True
                    elif patch == 0 and pre:
                        vulnerable = True
            if vulnerable:
                versiones_vulnerables.append(ver_raw)

        if versiones_vulnerables:
            self._add(Finding(
                id          = "K8S-RUNC-001",
                title       = "CVE-2025-52881: runc vulnerable a escape de contenedor (CRÍTICO)",
                severity    = "CRITICAL",
                description = (
                    "Se detectaron versiones de runc vulnerables a CVE-2025-52881."
                ),
                evidence    = (
                    "Versiones de runtime detectadas en los nodos:\n"
                    + "\n".join(versiones_candidatas[:10]) + "\n"
                    "Versiones identificadas como vulnerables:\n"
                    + "\n".join(versiones_vulnerables[:10])
                ),
                affected    = f"Nodos del clúster ({len(versiones_vulnerables)} versiones vulnerables)",
                remediation = (
                    "Actualizar runc inmediatamente a versión parcheada."
                ),
                cvss        = 9.8,
                tags        = ["cve", "runc", "container-escape", "CVE-2025-52881", "crítico"],
                references  = [
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-XXXX",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-52881",
                ],
            ))
        else:
            _log_clean("CVE-2025-52881 (runc): versiones detectadas no son vulnerables")

    def _check_cve_acm(self) -> None:
        _log_info("Verificando presencia de Red Hat ACM (CVE-2026-66786)...")

        acm_hub_raw = _kubectl_raw(
            ["get", "pods", "-n", "open-cluster-management",
             "--no-headers", "-o", "wide"]
        )
        tiene_acm = False
        if acm_hub_raw and "multicluster" in acm_hub_raw.lower():
            tiene_acm = True

        if not tiene_acm:
            addon_raw = _kubectl_raw(["get", "ClusterManagementAddon", "--no-headers"])
            if addon_raw and addon_raw.strip():
                tiene_acm = True

        if not tiene_acm:
            if _VERBOSE:
                _log_info("ACM no detectado en el clúster — omitiendo CVE-2026-66786")
            return

        _log_info("Red Hat ACM detectado — verificando acceso no autenticado (CVE-2026-66786)...")

        acm_accesible_sin_auth = False
        if self._server_url:
            import urllib.request
            import urllib.error
            import ssl
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                url = f"{self._server_url}/multicloud/api/v1/"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    if resp.status == 200:
                        acm_accesible_sin_auth = True
            except Exception:
                pass

        if acm_accesible_sin_auth:
            self._add(Finding(
                id          = "K8S-ACM-001",
                title       = "CVE-2026-66786: Red Hat ACM permite escalada de privs sin autenticación",
                severity    = "CRITICAL",
                description = (
                    "El endpoint /multicloud/api/v1/ de Red Hat ACM "
                    "responde con HTTP 200 sin credenciales."
                ),
                evidence    = (
                    f"GET {self._server_url}/multicloud/api/v1/ → HTTP 200 sin Authorization"
                ),
                affected    = f"Red Hat ACM en {self._server_url}",
                remediation = "Aplicar el parche de Red Hat para CVE-2026-66786 inmediatamente.",
                cvss        = 10.0,
                tags        = ["cve", "acm", "red-hat", "escalada-privilegios",
                               "sin-autenticación", "CVE-2026-66786"],
                references  = [
                    "https://access.redhat.com/security/cve/CVE-2026-66786",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-66786",
                ],
            ))
        else:
            _log_clean(
                "CVE-2026-66786 (ACM): endpoint no accesible sin autenticación"
            )

    def fase9_cve(self) -> None:
        _log_phase(9, "CVEs activos")

        if self.skip_cve:
            _log_info("Verificación de CVEs omitida (--skip-cve)")
            return

        self._check_cve_runc()
        self._check_cve_acm()

    # ── Auditoría de Helm charts ───────────────────────────────────────────

    def _audit_helm_charts(self, findings: List[Finding]) -> None:
        _log_phase(10, "Helm charts")

        try:
            res_ver = subprocess.run(
                ["helm", "version", "--short"],
                capture_output=True, text=True, timeout=10,
            )
            if res_ver.returncode != 0:
                _log_info("helm no disponible o devolvió error — checks Helm omitidos")
                return
        except FileNotFoundError:
            _log_info("Helm no disponible o sin releases")
            return
        except subprocess.TimeoutExpired:
            _log_info("helm no responde (timeout) — checks Helm omitidos")
            return

        try:
            res_list = subprocess.run(
                ["helm", "list", "-A", "-o", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if res_list.returncode != 0 or not res_list.stdout.strip():
                _log_info("Helm no disponible o sin releases")
                return
            releases = json.loads(res_list.stdout)
            if not releases:
                _log_info("No se encontraron releases de Helm en el clúster")
                return
        except (json.JSONDecodeError, subprocess.TimeoutExpired):
            _log_info("No se pudo parsear la salida de helm list")
            return

        _log_info(f"Encontrados {len(releases)} release(s) de Helm — auditando valores")

        for release in releases:
            nombre    = release.get("name", "?")
            namespace = release.get("namespace", "default")
            chart     = release.get("chart", "?")
            prefijo   = f"{namespace}/{nombre}"

            try:
                res_vals = subprocess.run(
                    ["helm", "get", "values", nombre, "-n", namespace, "-o", "json"],
                    capture_output=True, text=True, timeout=20,
                )
                if res_vals.returncode != 0 or not res_vals.stdout.strip():
                    continue
                raw = res_vals.stdout.strip()
                valores: dict = {} if raw == "null" else json.loads(raw)
            except (json.JSONDecodeError, subprocess.TimeoutExpired):
                continue

            pull_policy = (valores.get("image") or {}).get("pullPolicy", "")
            if pull_policy and pull_policy != "Always":
                findings.append(Finding(
                    id="K8S-HELM-001",
                    severity="LOW",
                    category="Helm",
                    title=f"Helm release '{prefijo}': pullPolicy no es Always",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) tiene "
                        f"image.pullPolicy='{pull_policy}'."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        f"image.pullPolicy={pull_policy}"
                    ),
                    remediation=(
                        f"helm upgrade {nombre} <chart> -n {namespace} "
                        "--set image.pullPolicy=Always"
                    ),
                ))

            if "securityContext" not in valores and "podSecurityContext" not in valores:
                findings.append(Finding(
                    id="K8S-HELM-002",
                    severity="MEDIUM",
                    category="Helm",
                    title=f"Helm release '{prefijo}': securityContext no configurado",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) no define securityContext."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "securityContext ausente"
                    ),
                    remediation="Añadir securityContext con runAsNonRoot: true.",
                ))

            resources = valores.get("resources") or {}
            if not resources.get("limits"):
                findings.append(Finding(
                    id="K8S-HELM-003",
                    severity="LOW",
                    category="Helm",
                    title=f"Helm release '{prefijo}': resources.limits no definido",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) no define limits."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "resources.limits ausente"
                    ),
                    remediation="Definir limits de CPU/memoria.",
                ))

            ingress = valores.get("ingress") or {}
            if ingress.get("enabled") and not ingress.get("tls"):
                findings.append(Finding(
                    id="K8S-HELM-004",
                    severity="MEDIUM",
                    category="Helm",
                    title=f"Helm release '{prefijo}': Ingress habilitado sin TLS",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) tiene "
                        "ingress.enabled=true pero ingress.tls está vacío."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "ingress.enabled=true, ingress.tls ausente"
                    ),
                    remediation="Configurar TLS en el Ingress.",
                ))

    # ── Fase 10: Control plane CIS ──────────────────────────────────────────

    def _args_control_plane_pod(self, nombre_pod_prefix: str) -> Dict[str, str]:
        data = _kubectl(
            ["get", "pods", "-n", "kube-system",
             "--field-selector", "status.phase=Running",
             "-o", "json"],
        )
        if not data:
            return {}
        args_dict: Dict[str, str] = {}
        for item in data.get("items", []):
            name = item.get("metadata", {}).get("name", "")
            if not name.startswith(nombre_pod_prefix):
                continue
            for container in item.get("spec", {}).get("containers", []):
                for arg in container.get("command", []) + container.get("args", []):
                    if arg.startswith("--"):
                        arg = arg[2:]
                        if "=" in arg:
                            k, v = arg.split("=", 1)
                        else:
                            k, v = arg, "true"
                        args_dict[k.lower()] = v.lower()
        return args_dict

    def fase10_control_plane_cis(self) -> None:
        _log_phase(10, "CONTROL PLANE CIS — etcd / controller-manager / scheduler")

        _log_info("etcd: leyendo argumentos del pod estático …")
        etcd_args = self._args_control_plane_pod("etcd-")

        if not etcd_args:
            _log_info("etcd: pod estático no encontrado — checks omitidos (clúster gestionado?)")
        else:
            if not etcd_args.get("cert-file") or not etcd_args.get("key-file"):
                self._add(Finding(
                    id="K8S-ETCD-001", title="CIS 2.1: etcd sin TLS de servidor configurado",
                    severity="CRITICAL",
                    description="etcd no tiene --cert-file o --key-file configurados.",
                    evidence=f"Args etcd: {etcd_args}", affected="etcd",
                    remediation="Configurar --cert-file y --key-file en etcd.",
                    cvss=9.8, tags=["etcd", "tls", "cis-2.1"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if etcd_args.get("client-cert-auth", "false") not in ("true", "1"):
                self._add(Finding(
                    id="K8S-ETCD-002", title="CIS 2.2: etcd sin autenticación de cliente por certificado",
                    severity="CRITICAL",
                    description="--client-cert-auth no está habilitado en etcd.",
                    evidence=f"client-cert-auth={etcd_args.get('client-cert-auth', 'no configurado')}",
                    affected="etcd",
                    remediation="Añadir --client-cert-auth=true al manifiesto estático de etcd.",
                    cvss=9.8, tags=["etcd", "autenticación", "cis-2.2"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if etcd_args.get("auto-tls", "false") == "true":
                self._add(Finding(
                    id="K8S-ETCD-003", title="CIS 2.3: etcd con --auto-tls habilitado",
                    severity="HIGH",
                    description="--auto-tls=true genera certificados auto-firmados sin validación PKI.",
                    evidence="auto-tls=true en argumentos de etcd", affected="etcd",
                    remediation="Usar certificados firmados por una CA de confianza.",
                    cvss=7.5, tags=["etcd", "tls", "cis-2.3"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if not etcd_args.get("peer-cert-file") or not etcd_args.get("peer-key-file"):
                self._add(Finding(
                    id="K8S-ETCD-004", title="CIS 2.4: etcd sin TLS en comunicación entre peers",
                    severity="HIGH",
                    description="--peer-cert-file o --peer-key-file no configurados.",
                    evidence=f"peer-cert-file={etcd_args.get('peer-cert-file', 'no configurado')}",
                    affected="etcd",
                    remediation="Configurar --peer-cert-file y --peer-key-file.",
                    cvss=7.5, tags=["etcd", "peer-tls", "cis-2.4"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if etcd_args.get("peer-client-cert-auth", "false") not in ("true", "1"):
                self._add(Finding(
                    id="K8S-ETCD-005", title="CIS 2.5: etcd sin autenticación mutua entre peers",
                    severity="HIGH",
                    description="--peer-client-cert-auth no está habilitado.",
                    evidence=f"peer-client-cert-auth={etcd_args.get('peer-client-cert-auth', 'no configurado')}",
                    affected="etcd",
                    remediation="Añadir --peer-client-cert-auth=true.",
                    cvss=7.0, tags=["etcd", "peer-auth", "cis-2.5"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if etcd_args.get("peer-auto-tls", "false") == "true":
                self._add(Finding(
                    id="K8S-ETCD-006", title="CIS 2.6: etcd con --peer-auto-tls habilitado",
                    severity="MEDIUM",
                    description="--peer-auto-tls=true genera certificados peer auto-firmados.",
                    evidence="peer-auto-tls=true", affected="etcd",
                    remediation="Usar certificados peer firmados por CA.",
                    cvss=5.9, tags=["etcd", "peer-tls", "cis-2.6"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if not etcd_args.get("trusted-ca-file"):
                self._add(Finding(
                    id="K8S-ETCD-007", title="CIS 2.7: etcd sin --trusted-ca-file configurado",
                    severity="HIGH",
                    description="--trusted-ca-file no está configurado en etcd.",
                    evidence="trusted-ca-file no presente en argumentos etcd", affected="etcd",
                    remediation="Configurar --trusted-ca-file=/path/to/ca.crt en etcd.",
                    cvss=6.5, tags=["etcd", "ca", "cis-2.7"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            api_args = self._args_control_plane_pod("kube-apiserver-")
            if api_args and not api_args.get("encryption-provider-config"):
                self._add(Finding(
                    id="K8S-ETCD-008", title="Cifrado at-rest de Secrets no configurado en el API server",
                    severity="HIGH",
                    description="--encryption-provider-config no está configurado en kube-apiserver.",
                    evidence="encryption-provider-config no encontrado en args de kube-apiserver",
                    affected="kube-apiserver",
                    remediation="Crear un EncryptionConfiguration y configurar --encryption-provider-config.",
                    cvss=7.5, tags=["etcd", "cifrado", "secretos"],
                    references=["https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"],
                ))

        _log_info("kube-controller-manager: leyendo argumentos del pod estático …")
        kcm_args = self._args_control_plane_pod("kube-controller-manager-")

        if not kcm_args:
            _log_info("kube-controller-manager: pod no encontrado — omitido")
        else:
            if not kcm_args.get("terminated-pod-gc-threshold"):
                self._add(Finding(
                    id="K8S-KCM-001", title="CIS 1.3.1: --terminated-pod-gc-threshold no configurado",
                    severity="LOW",
                    description="Sin --terminated-pod-gc-threshold, los pods terminados se acumulan.",
                    evidence="terminated-pod-gc-threshold no encontrado",
                    affected="kube-controller-manager",
                    remediation="Añadir --terminated-pod-gc-threshold=10.",
                    cvss=3.1, tags=["kcm", "gc", "cis-1.3.1"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            kcm_profiling = kcm_args.get("profiling", "true")
            if kcm_profiling != "false":
                self._add(Finding(
                    id="K8S-KCM-002", title="CIS 1.3.2: profiling habilitado en kube-controller-manager",
                    severity="LOW",
                    description="--profiling no está seteado a false.",
                    evidence=f"profiling={kcm_profiling}", affected="kube-controller-manager",
                    remediation="Añadir --profiling=false al kube-controller-manager.",
                    cvss=3.1, tags=["kcm", "profiling", "cis-1.3.2"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if kcm_args.get("use-service-account-credentials", "false") not in ("true", "1"):
                self._add(Finding(
                    id="K8S-KCM-003", title="CIS 1.3.3: --use-service-account-credentials no habilitado",
                    severity="HIGH",
                    description="El kube-controller-manager no usa credenciales individuales por SA.",
                    evidence=f"use-service-account-credentials={kcm_args.get('use-service-account-credentials', 'no configurado')}",
                    affected="kube-controller-manager",
                    remediation="Añadir --use-service-account-credentials=true.",
                    cvss=6.5, tags=["kcm", "rbac", "cis-1.3.3"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if not kcm_args.get("service-account-private-key-file"):
                self._add(Finding(
                    id="K8S-KCM-004", title="CIS 1.3.4: --service-account-private-key-file no configurado",
                    severity="MEDIUM",
                    description="No se ha configurado una clave privada explícita para tokens de SA.",
                    evidence="service-account-private-key-file no encontrado",
                    affected="kube-controller-manager",
                    remediation="Configurar --service-account-private-key-file=/path/to/sa.key.",
                    cvss=5.3, tags=["kcm", "service-account", "cis-1.3.4"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if not kcm_args.get("root-ca-file"):
                self._add(Finding(
                    id="K8S-KCM-005", title="CIS 1.3.5: --root-ca-file no configurado en controller-manager",
                    severity="MEDIUM",
                    description="Sin --root-ca-file, el controller-manager no puede inyectar la CA.",
                    evidence="root-ca-file no encontrado", affected="kube-controller-manager",
                    remediation="Configurar --root-ca-file=/path/to/ca.crt.",
                    cvss=4.3, tags=["kcm", "ca", "cis-1.3.5"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            feature_gates = kcm_args.get("feature-gates", "")
            if "rotatekubeletservercertificate=true" not in feature_gates.lower():
                self._add(Finding(
                    id="K8S-KCM-006", title="CIS 1.3.6: RotateKubeletServerCertificate no habilitado",
                    severity="MEDIUM",
                    description="El feature gate RotateKubeletServerCertificate no está habilitado.",
                    evidence=f"feature-gates={feature_gates or 'no configurado'}",
                    affected="kube-controller-manager",
                    remediation="Añadir --feature-gates=RotateKubeletServerCertificate=true.",
                    cvss=4.9, tags=["kcm", "certificados", "rotación", "cis-1.3.6"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            bind_addr = kcm_args.get("bind-address", "0.0.0.0")
            if bind_addr not in ("127.0.0.1", "::1"):
                self._add(Finding(
                    id="K8S-KCM-007", title="CIS 1.3.7: kube-controller-manager expone métricas en all-interfaces",
                    severity="LOW",
                    description=f"--bind-address={bind_addr} en kube-controller-manager.",
                    evidence=f"bind-address={bind_addr}", affected="kube-controller-manager",
                    remediation="Añadir --bind-address=127.0.0.1 al kube-controller-manager.",
                    cvss=3.7, tags=["kcm", "red", "cis-1.3.7"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if kcm_args.get("secure-port", "10257") == "0":
                self._add(Finding(
                    id="K8S-KCM-008", title="kube-controller-manager con --secure-port=0 (HTTPS deshabilitado)",
                    severity="MEDIUM",
                    description="--secure-port=0 deshabilita el endpoint HTTPS del controller-manager.",
                    evidence="secure-port=0", affected="kube-controller-manager",
                    remediation="Usar el puerto seguro por defecto 10257.",
                    cvss=5.3, tags=["kcm", "tls", "seguridad"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

        _log_info("kube-scheduler: leyendo argumentos del pod estático …")
        sched_args = self._args_control_plane_pod("kube-scheduler-")

        if not sched_args:
            _log_info("kube-scheduler: pod no encontrado — omitido")
        else:
            sched_profiling = sched_args.get("profiling", "true")
            if sched_profiling != "false":
                self._add(Finding(
                    id="K8S-KSCHED-001", title="CIS 1.4.1: profiling habilitado en kube-scheduler",
                    severity="LOW",
                    description="--profiling no está seteado a false en kube-scheduler.",
                    evidence=f"profiling={sched_profiling}", affected="kube-scheduler",
                    remediation="Añadir --profiling=false al kube-scheduler.",
                    cvss=3.1, tags=["scheduler", "profiling", "cis-1.4.1"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            sched_bind = sched_args.get("bind-address", "0.0.0.0")
            if sched_bind not in ("127.0.0.1", "::1"):
                self._add(Finding(
                    id="K8S-KSCHED-002", title="CIS 1.4.2: kube-scheduler expone métricas en all-interfaces",
                    severity="LOW",
                    description=f"--bind-address={sched_bind} en kube-scheduler.",
                    evidence=f"bind-address={sched_bind}", affected="kube-scheduler",
                    remediation="Añadir --bind-address=127.0.0.1 al kube-scheduler.",
                    cvss=3.7, tags=["scheduler", "red", "cis-1.4.2"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            if sched_args.get("secure-port", "10259") == "0":
                self._add(Finding(
                    id="K8S-KSCHED-003", title="kube-scheduler con --secure-port=0 (HTTPS deshabilitado)",
                    severity="MEDIUM",
                    description="--secure-port=0 deshabilita el endpoint HTTPS del scheduler.",
                    evidence="secure-port=0 en kube-scheduler", affected="kube-scheduler",
                    remediation="No usar --secure-port=0.",
                    cvss=5.3, tags=["scheduler", "tls"],
                    references=["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

        _log_info("kubelet: verificando configuración CIS en nodos …")
        nodos_data = _kubectl(["get", "nodes", "-o", "json"])
        if nodos_data:
            for nodo in nodos_data.get("items", [])[:5]:
                nombre_nodo = nodo.get("metadata", {}).get("name", "desconocido")
                kubelet_cfg = _kubectl(
                    ["get", "--raw", f"/api/v1/nodes/{nombre_nodo}/proxy/configz"],
                ) or {}
                anon_auth = (
                    kubelet_cfg.get("kubeletconfig", {})
                    .get("authentication", {})
                    .get("anonymous", {})
                    .get("enabled", True)
                )
                if anon_auth:
                    self._add(Finding(
                        id          = "K8S-KUBELET-001",
                        title       = f"CIS 4.2.1: kubelet anon-auth habilitado en nodo {nombre_nodo}",
                        severity    = "CRITICAL",
                        description = (
                            f"El kubelet del nodo '{nombre_nodo}' tiene --anonymous-auth=true."
                        ),
                        evidence    = f"anonymous.enabled={anon_auth} en /configz de {nombre_nodo}",
                        affected    = f"kubelet/{nombre_nodo}",
                        remediation = "Añadir --anonymous-auth=false en el kubelet.",
                        cvss        = 9.8,
                        tags        = ["kubelet", "autenticación", "cis-4.2.1"],
                        references  = ["https://www.cisecurity.org/benchmark/kubernetes"],
                    ))
                    break

    # ── Fase 11: Reglas YAML CIS ──────────────────────────────────────────

    def fase_yaml_rules(self) -> None:
        """Evalúa reglas YAML CIS contra todos los recursos del clúster."""
        if not _YAML_CHECKS:
            _log_warn("No hay reglas YAML disponibles (¿falta pyyaml?)")
            return
        _log_phase(11, f"Reglas YAML CIS ({len(_YAML_CHECKS)} checks)")

        resource_cache: dict = {}

        def fetch(kind: str, ns_scope: str) -> list:
            key = (kind, ns_scope)
            if key not in resource_cache:
                if ns_scope == "cluster":
                    data = _kubectl(["get", kind, "-o", "json"])
                else:
                    data = _kubectl(["get", kind, "--all-namespaces", "-o", "json"])
                resource_cache[key] = data.get("items", []) if data else []
            return resource_cache[key]

        rule_count = 0
        finding_count = 0

        for rule in _YAML_CHECKS:
            rule_id      = rule["id"]
            kind         = rule.get("resource_kind", "Pod")
            ns_scope     = rule.get("namespace", "all")
            op           = rule.get("op", "")
            title        = rule.get("title", rule_id)
            severity     = rule.get("severity", "MEDIUM")
            category     = rule.get("category", "")
            description  = rule.get("description", "")
            remediation  = rule.get("remediation", "")
            filter_name  = rule.get("filter_name")
            cis          = rule.get("cis", "")
            rule_count  += 1
            resources    = fetch(kind, ns_scope)

            # namespace_empty: comprueba si hay algún recurso de este tipo en cada ns
            if op == "namespace_empty":
                ns_data = _kubectl(["get", "namespaces", "-o", "json"])
                all_ns: set = set()
                if ns_data:
                    for ns_item in ns_data.get("items", []):
                        all_ns.add(ns_item.get("metadata", {}).get("name", ""))
                ns_with_res: set = set()
                for res in resources:
                    ns = res.get("metadata", {}).get("namespace", "")
                    if ns:
                        ns_with_res.add(ns)
                skip = {"kube-system", "kube-public", "kube-node-lease"}
                empty_ns = all_ns - ns_with_res - skip
                if empty_ns:
                    for ns in sorted(empty_ns):
                        safe_id = re.sub(r"[^a-zA-Z0-9]", "", ns)
                        self._add(Finding(
                            id          = f"{rule_id}-{safe_id}",
                            title       = title,
                            severity    = severity,
                            description = description,
                            evidence    = f"Namespace {ns!r} sin {kind}",
                            affected    = f"namespace/{ns}",
                            remediation = remediation,
                            tags        = ["yaml-cis", category],
                            references  = [f"CIS K8s {cis}"] if cis else [],
                        ))
                        finding_count += 1
                else:
                    _log_clean(f"{rule_id}: OK")
                continue

            flagged = False
            for resource in resources:
                res_name = resource.get("metadata", {}).get("name", "?")
                res_ns   = resource.get("metadata", {}).get("namespace", "")
                if filter_name and res_name != filter_name:
                    continue
                violations = _eval_yaml_rule(rule, resource)
                if not violations:
                    continue
                flagged = True
                affected = f"{res_ns}/{kind}/{res_name}" if res_ns else f"{kind}/{res_name}"
                evidence_lines = []
                for item_name, ev_str in violations[:5]:
                    evidence_lines.append(f"  · {item_name + ': ' if item_name else ''}{ev_str}")
                if len(violations) > 5:
                    evidence_lines.append(f"  · ... y {len(violations) - 5} más")
                safe_id = re.sub(r"[^a-zA-Z0-9]", "", res_name)[:20]
                self._add(Finding(
                    id          = f"{rule_id}-{safe_id}",
                    title       = title,
                    severity    = severity,
                    description = description,
                    evidence    = "\n".join(evidence_lines),
                    affected    = affected,
                    remediation = remediation,
                    tags        = ["yaml-cis", category],
                    references  = [f"CIS K8s {cis}"] if cis else [],
                ))
                finding_count += 1

            if not flagged:
                _log_clean(f"{rule_id}: OK")

        _log_info(
            f"Reglas YAML: {rule_count} evaluadas → {finding_count} hallazgo(s)"
        )

    # ── Fase 12: kube-bench externo ───────────────────────────────────────

    def run_kubebench(self) -> None:
        """Ejecuta kube-bench si está disponible e importa sus hallazgos."""
        _log_phase(12, "kube-bench (CIS Kubernetes Benchmark externo)")
        try:
            result = subprocess.run(
                ["kube-bench", "--json"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode not in (0, 1):
                _log_warn(f"kube-bench terminó con código {result.returncode}")
                return
            data = json.loads(result.stdout)
        except FileNotFoundError:
            _log_warn("kube-bench no encontrado en PATH — saltando fase 12")
            return
        except subprocess.TimeoutExpired:
            _log_warn("kube-bench timeout (120s) — saltando")
            return
        except json.JSONDecodeError:
            _log_warn("kube-bench: salida JSON no parseable")
            return

        kb_count = 0
        sections = data if isinstance(data, list) else [data]
        for section in sections:
            node_type = section.get("node_type", "cluster")
            for test_group in section.get("tests", []):
                for test in test_group.get("results", []):
                    if test.get("status", "") != "FAIL":
                        continue
                    test_num  = test.get("test_number", "?")
                    test_desc = test.get("test_desc", "")
                    remed     = test.get("remediation", "")
                    scored    = test.get("scored", True)
                    severity  = "HIGH" if scored else "MEDIUM"
                    safe_id   = re.sub(r"[^a-zA-Z0-9]", "", test_num)
                    self._add(Finding(
                        id          = f"KB-{safe_id}",
                        title       = f"[kube-bench] {test_desc}",
                        severity    = severity,
                        description = f"CIS K8s Benchmark check {test_num} fallido.",
                        evidence    = test.get("actual_value", ""),
                        affected    = node_type,
                        remediation = remed,
                        tags        = ["kube-bench", "cis"],
                        references  = [f"CIS K8s {test_num}"],
                    ))
                    kb_count += 1

        _log_info(f"kube-bench: {kb_count} hallazgo(s) importados")

    # ── Ejecución completa ─────────────────────────────────────────────────

    def run(self) -> int:
        """Ejecuta todas las fases y devuelve exit code (0/1/2)."""
        from ._models import BANNER
        print(BANNER)

        ts_inicio = datetime.now(timezone.utc)
        _log_info(f"Inicio de auditoría: {ts_inicio.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if self.context:
            _log_info(f"Contexto kubectl: {self.context}")
        if self.namespace:
            _log_info(f"Namespace objetivo: {self.namespace}")

        self.fase1_contexto()
        self.fase2_rbac()
        self.fase3_pods()
        self.fase4_red()
        self.fase5_secretos()
        self.fase6_imagenes()
        self.fase7_opa()
        self.fase8_webhooks()
        self.fase9_cve()

        if self.audit_helm:
            self._audit_helm_charts(self.findings)

        if getattr(self, "audit_control_plane", False):
            self.fase10_control_plane_cis()

        self.fase_yaml_rules()
        self.run_kubebench()

        return self._calcular_exit_code()

    def _calcular_exit_code(self) -> int:
        tiene_critical = any(f.severity == "CRITICAL" for f in self.findings)
        tiene_high     = any(f.severity == "HIGH"     for f in self.findings)
        if tiene_critical:
            return 2
        if tiene_high:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Delta scan
# ---------------------------------------------------------------------------

def apply_delta_scan(
    findings: "List[Finding]", delta_path: str
) -> "tuple[List[Finding], List[str], List[str], List[str]]":
    """
    Compara hallazgos actuales con un informe JSON previo (--delta FILE).
    Devuelve (findings, new_ids, recurring_ids, resolved_ids).
    """
    try:
        baseline_data = json.loads(Path(delta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se puede leer el delta baseline '{delta_path}': {exc}") from exc
    baseline_ids  = {f["id"] for f in baseline_data.get("findings", []) if "id" in f}
    current_ids   = {f.id for f in findings}
    new_ids       = sorted(current_ids - baseline_ids)
    recurring_ids = sorted(current_ids & baseline_ids)
    resolved_ids  = sorted(baseline_ids - current_ids)
    return findings, new_ids, recurring_ids, resolved_ids
