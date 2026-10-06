#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VampSecure Labs — Kubernetes Security Auditor
==============================================
Auditor de seguridad para clústeres Kubernetes.

Detecta configuraciones inseguras mediante consultas a la API de Kubernetes
a través de kubectl: RBAC sobredimensionado, pods privilegiados, exposición
de red, gestión deficiente de secretos, imágenes sin verificar y ausencia
de controles de seguridad en el runtime del clúster.

© VampSecure Studios — VampSecure Labs Security Research Division

Uso autorizado exclusivamente en entornos con permiso explícito.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from vampsec_report import (
    Finding,
    VampSecReport,
    meta_from_args,
)

# ---------------------------------------------------------------------------
# Metadatos
# ---------------------------------------------------------------------------

VERSION   = "2.1"
TOOL_NAME = "vamp-k8s-audit"

# ---------------------------------------------------------------------------
# Colores ANSI (sin dependencias externas)
# ---------------------------------------------------------------------------

ANSI_RESET   = "\033[0m"
ANSI_BOLD    = "\033[1m"
ANSI_RED     = "\033[91m"
ANSI_ORANGE  = "\033[33m"
ANSI_YELLOW  = "\033[93m"
ANSI_BLUE    = "\033[94m"
ANSI_CYAN    = "\033[96m"
ANSI_GREEN   = "\033[92m"
ANSI_GREY    = "\033[37m"
ANSI_DIM     = "\033[2m"
ANSI_WHITE   = "\033[97m"

_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": ANSI_RED,
    "HIGH":     ANSI_ORANGE,
    "MEDIUM":   ANSI_YELLOW,
    "LOW":      ANSI_BLUE,
    "INFO":     ANSI_GREY,
}

def _color(text: str, code: str) -> str:
    """Aplica un código de color ANSI al texto dado."""
    return f"{code}{text}{ANSI_RESET}"

def _sev_badge(severity: str) -> str:
    """Devuelve el badge de severidad con color ANSI."""
    color = _SEV_COLOR.get(severity.upper(), ANSI_GREY)
    return _color(f"[{severity.upper():8}]", color + ANSI_BOLD)

# ---------------------------------------------------------------------------
# Banner ASCII
# ---------------------------------------------------------------------------

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ 
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-k8s-audit v1.3 · Kubernetes Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Función auxiliar kubectl
# ---------------------------------------------------------------------------

_KUBECTL_CMD: List[str] = []   # inicializado en main


def _kubectl(args: List[str]) -> Optional[Any]:
    """
    Ejecuta un subcomando de kubectl y devuelve el objeto JSON parseado.

    Parámetros
    ----------
    args : lista de argumentos a pasar a kubectl (sin el comando 'kubectl')

    Retorna
    -------
    El objeto Python correspondiente al JSON de salida de kubectl, o None
    si el comando falla o la salida no es JSON válido.

    Notas
    -----
    - Si kubectl no está disponible en el PATH, imprime un mensaje claro y
      termina el proceso con código 1.
    - Si el contexto o el cluster no son accesibles, devuelve None y muestra
      el error en modo verbose.
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
    """
    Ejecuta kubectl y devuelve stdout como texto plano (no JSON).

    Retorna cadena vacía si falla.
    """
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

_VERBOSE = False


def _log_info(msg: str) -> None:
    """Imprime mensaje informativo en consola."""
    print(f"  {ANSI_DIM}·{ANSI_RESET} {msg}")


def _log_warn(msg: str) -> None:
    """Imprime aviso en consola."""
    print(f"  {ANSI_YELLOW}!{ANSI_RESET} {msg}")


def _log_phase(numero: int, titulo: str) -> None:
    """Imprime cabecera de fase con formato VSL."""
    print(f"\n{ANSI_BOLD}{ANSI_CYAN}▶ FASE {numero} — {titulo}{ANSI_RESET}")
    print(f"  {'─' * 62}")


def _log_finding(f: Finding) -> None:
    """Imprime un hallazgo individual en consola con colores de severidad."""
    badge = _sev_badge(f.severity)
    print(f"\n  {badge} {ANSI_BOLD}{f.id}{ANSI_RESET} — {f.title}")
    print(f"  {ANSI_DIM}Afectado:{ANSI_RESET} {f.affected}")
    if _VERBOSE and f.evidence:
        for linea in f.evidence.splitlines()[:5]:
            print(f"  {ANSI_DIM}  {linea}{ANSI_RESET}")


def _log_clean(msg: str) -> None:
    """Imprime mensaje de comprobación superada."""
    print(f"  {ANSI_GREEN}✓{ANSI_RESET} {ANSI_DIM}{msg}{ANSI_RESET}")


# ---------------------------------------------------------------------------
# Clase principal del auditor
# ---------------------------------------------------------------------------

class K8SAuditor:
    """
    Auditor de seguridad para clústeres Kubernetes.

    Ejecuta 6 fases de análisis mediante kubectl y acumula los hallazgos
    en formato Finding normalizado VSL para su posterior exportación.

    Atributos
    ---------
    context   : contexto kubectl a usar (None = contexto activo)
    namespace : namespace a auditar (None = todos)
    findings  : lista de hallazgos acumulados
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
        """Añade un hallazgo a la lista acumulada y lo imprime en consola."""
        self.findings.append(finding)
        _log_finding(finding)

    def _ns_filter(self) -> List[str]:
        """Devuelve los flags de namespace para kubectl."""
        if self.namespace:
            return ["-n", self.namespace]
        return ["--all-namespaces"]

    # ── Fase 1: Contexto del clúster ──────────────────────────────────────

    def fase1_contexto(self) -> None:
        """
        Fase 1 — Contexto del clúster (K8S-001..K8S-009).

        Recopila información básica del clúster: versión del servidor,
        nodos, namespaces y pods. Verifica acceso anónimo al API server.
        """
        _log_phase(1, "Contexto del clúster")

        # ── Versión del servidor
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

        # ── Nodos
        nodos_data = _kubectl(["get", "nodes", "-o", "json"])
        num_nodos  = 0
        if nodos_data:
            items = nodos_data.get("items", [])
            num_nodos = len(items)
            _log_info(f"Nodos en el clúster: {num_nodos}")
            # Versiones de kubelet por nodo
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

            # Nodos sin estado Ready
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

        # ── Namespaces
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

        # ── Pods totales por namespace
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

        # ── Acceso anónimo al API server
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

        # ── Namespaces con nombres sensibles sin protección
        sensibles = ["monitoring", "logging", "metrics", "prometheus", "grafana", "istio-system"]
        for ns_sens in sensibles:
            if ns_sens in namespaces:
                _log_info(f"Namespace sensible detectado: {ns_sens} (se verificará en fases posteriores)")

        # ── Checks extendidos del API server (K8S-API-005, K8S-API-006)
        self._check_api_server_extended(pods_count_total=pod_count_total)

    def _detectar_server_url(self) -> str:
        """Obtiene la URL del API server del contexto actual de kubectl."""
        texto = _kubectl_raw(["config", "view", "--minify", "-o",
                              "jsonpath={.clusters[0].cluster.server}"])
        return texto.strip()

    def _check_anonimo(self, server_url: str) -> bool:
        """
        Intenta acceder al endpoint /api sin credenciales.

        Retorna True si la respuesta contiene datos del API (acceso anónimo activo).
        """
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
        """
        Checks adicionales del API server: autenticación anónima y automount tokens.

        K8S-API-005 (HIGH): --anonymous-auth habilitado en versiones < 1.28
        K8S-API-006 (MEDIUM): automount de service account tokens sin restricción
        """

        # ── K8S-API-005: Autenticación anónima
        anon_config = _kubectl_raw(
            ["get", "configmap", "kubeadm-config", "-n", "kube-system",
             "-o", "yaml"]
        )
        if anon_config:
            if "anonymous-auth: true" in anon_config.lower() or "anonymous-auth=true" in anon_config:
                pass
        # También verificar versión del servidor para la condición < 1.28
        version_data = _kubectl(["version", "--output", "json"])
        version_str = ""
        if version_data:
            version_str = version_data.get("serverVersion", {}).get("gitVersion", "")
        version_vulnerable = False
        if version_str:
            try:
                # Extraer major.minor de cadenas tipo "v1.27.3"
                partes_ver = re.findall(r"v(\d+)\.(\d+)", version_str)
                if partes_ver:
                    major_v, minor_v = int(partes_ver[0][0]), int(partes_ver[0][1])
                    if major_v == 1 and minor_v < 28:
                        version_vulnerable = True
            except (ValueError, IndexError):
                pass
        # Si no hay config explícita de anonymous-auth=false Y versión vulnerable → HIGH
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
                    "de kubeadm. En versiones anteriores a 1.28, el valor por defecto puede "
                    "permitir acceso anónimo al API server, lo que expone información del clúster "
                    "a actores no autenticados."
                ),
                evidence    = (
                    f"Versión del servidor: {version_str}\n"
                    f"anonymous-auth=false no detectado en kubeadm-config\n"
                    "Fuente: kubectl get configmap kubeadm-config -n kube-system"
                ),
                affected    = "kube-apiserver",
                remediation = (
                    "Añadir --anonymous-auth=false al kube-apiserver. "
                    "En clusters kubeadm, editar el ConfigMap kubeadm-config "
                    "y actualizar los argumentos del API server:\n"
                    "  extraArgs:\n"
                    "    anonymous-auth: 'false'\n"
                    "Verificar que no existan ClusterRoleBindings para system:anonymous."
                ),
                cvss        = 7.5,
                tags        = ["api-server", "autenticación", "anónimo"],
                references  = [
                    "https://kubernetes.io/docs/reference/access-authn-authz/authentication/"
                ],
            ))
        else:
            _log_clean("Autenticación anónima del API server: sin riesgo detectado")

        # ── K8S-API-006: Automount service account tokens sin restricción
        pods_data_all = _kubectl(["get", "pods", "--all-namespaces", "-o", "json"])
        if pods_data_all and pods_count_total > 0:
            total_pods   = pods_count_total
            items_pods   = pods_data_all.get("items", [])
            con_automount = 0
            for pod in items_pods:
                spec_p = pod.get("spec", {}) or {}
                automount_p = spec_p.get("automountServiceAccountToken")
                # El default en Kubernetes es True cuando no se especifica
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
                            "automountServiceAccountToken habilitado (valor por defecto o explícito). "
                            "Los tokens montados automáticamente amplían la superficie de ataque: "
                            "cualquier contenedor comprometido puede usar el token para acceder "
                            "a la API de Kubernetes con los permisos de su ServiceAccount."
                        ),
                        evidence    = (
                            f"Pods con automount token: {con_automount}/{total_pods} "
                            f"({porcentaje:.0f}%)"
                        ),
                        affected    = f"{con_automount} pods en el clúster",
                        remediation = (
                            "Establecer automountServiceAccountToken: false en los pods que "
                            "no necesiten acceder a la API de Kubernetes:\n"
                            "  spec:\n"
                            "    automountServiceAccountToken: false\n"
                            "También se puede deshabilitar a nivel de ServiceAccount. "
                            "Habilitar solo en los pods que realmente lo requieran."
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
        """
        Fase 2 — Control de acceso RBAC (K8S-010..K8S-029).

        Analiza ClusterRoleBindings, ClusterRoles, RoleBindings y
        ServiceAccounts en busca de privilegios excesivos o peligrosos.
        """
        _log_phase(2, "Control de acceso RBAC")

        # ── ClusterRoleBindings con cluster-admin a SA o usuarios no esperados
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
                    # system:masters es esperado; system:admin también
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
                                f"ClusterRoleBinding '{nombre_crb}'. Cualquier pod que use "
                                "esta SA obtiene control total sobre el clúster."
                            ),
                            evidence    = (
                                f"ClusterRoleBinding: {nombre_crb}\n"
                                f"Subject: ServiceAccount/{sname} (ns: {sns or 'cluster-level'})\n"
                                f"Role: {role_nombre}"
                            ),
                            affected    = f"SA/{sname} (ns: {sns or '-'})",
                            remediation = (
                                "Eliminar o limitar el ClusterRoleBinding. Asignar solo los "
                                "permisos mínimos necesarios (principio de mínimo privilegio). "
                                "Revisar qué pods usan esta ServiceAccount."
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
                                f"vía ClusterRoleBinding '{nombre_crb}'. Esto otorga control "
                                "total sobre todos los recursos del clúster."
                            ),
                            evidence    = (
                                f"ClusterRoleBinding: {nombre_crb}\n"
                                f"Subject: {kind}/{sname}\nRole: {role_nombre}"
                            ),
                            affected    = f"{kind}/{sname}",
                            remediation = (
                                "Revisar si el acceso cluster-admin es realmente necesario. "
                                "Crear roles con permisos específicos y limitados. "
                                "Auditar regularmente los ClusterRoleBindings."
                            ),
                            cvss        = 9.8,
                            tags        = ["rbac", "cluster-admin"],
                        ))
            _log_clean("Revisión de ClusterRoleBindings completada")
        else:
            _log_warn("No se pudieron obtener ClusterRoleBindings")

        # ── ClusterRoles con permisos wildcard (verbos y recursos = *)
        cr_data = _kubectl(["get", "clusterroles", "-o", "json"])
        if cr_data:
            for cr in cr_data.get("items", []):
                nombre_cr = cr.get("metadata", {}).get("name", "?")
                # Ignorar roles del sistema
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
                        break  # un hallazgo por ClusterRole es suficiente
            _log_clean("Revisión de ClusterRoles completada")
        else:
            _log_warn("No se pudieron obtener ClusterRoles")

        # ── RoleBindings que dan cluster-admin a nivel namespace
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
                                "referencia el ClusterRole 'cluster-admin'. Aunque la "
                                "cobertura es a nivel namespace, es una práctica de riesgo "
                                "que puede indicar mala comprensión del modelo RBAC."
                            ),
                            evidence    = (
                                f"RoleBinding: {nombre_rb} (ns: {ns_rb})\n"
                                f"Subject: {subj.get('kind', '?')}/{subj.get('name', '?')}\n"
                                f"RoleRef: cluster-admin"
                            ),
                            affected    = f"RoleBinding/{nombre_rb} (ns: {ns_rb})",
                            remediation = (
                                "Usar Roles específicos del namespace en lugar de referenciar "
                                "ClusterRoles con privilegios elevados. Revisar la intención "
                                "real del RoleBinding."
                            ),
                            cvss        = 8.1,
                            tags        = ["rbac", "rolebinding", "cluster-admin"],
                        ))
            _log_clean("Revisión de RoleBindings completada")
        else:
            _log_warn("No se pudieron obtener RoleBindings")

        # ── ServiceAccount 'default' con bindings de roles
        sa_data = _kubectl(["get", "serviceaccounts"] + self._ns_filter() + ["-o", "json"])
        if sa_data:
            sas_con_automount = []
            for sa in sa_data.get("items", []):
                sa_nombre  = sa.get("metadata", {}).get("name", "?")
                sa_ns      = sa.get("metadata", {}).get("namespace", "?")
                automount  = sa.get("automountServiceAccountToken")
                # Por defecto es True si no se especifica
                if automount is None or automount is True:
                    sas_con_automount.append(f"{sa_ns}/{sa_nombre}")
            if len(sas_con_automount) > 20:
                _log_info(f"ServiceAccounts con automount token habilitado: {len(sas_con_automount)}")
        else:
            _log_warn("No se pudieron obtener ServiceAccounts")

        # ── SA 'default' con bindings
        self._check_sa_default_bindings()

        # ── Permisos del usuario anónimo
        self._check_anonimo_permisos()

    def _check_sa_default_bindings(self) -> None:
        """Verifica si la SA 'default' tiene RoleBindings asignados."""
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
                    "Todos los pods que no especifiquen serviceAccountName usan 'default', "
                    "por lo que heredan estos permisos de forma implícita."
                ),
                evidence    = "Bindings que incluyen SA/default:\n" + "\n".join(hallados[:10]),
                affected    = "ServiceAccount/default",
                remediation = (
                    "Eliminar los bindings de la SA 'default'. "
                    "Crear SAs dedicadas con permisos específicos para cada aplicación. "
                    "Deshabilitar automountServiceAccountToken en la SA default "
                    "(patch serviceaccount default --patch ...automountServiceAccountToken: false)."
                ),
                cvss        = 7.5,
                tags        = ["rbac", "serviceaccount", "default"],
            ))
        else:
            _log_clean("ServiceAccount 'default' sin permisos RBAC adicionales")

    def _check_anonimo_permisos(self) -> None:
        """Verifica si system:anonymous tiene permisos en el clúster."""
        texto = _kubectl_raw(
            ["auth", "can-i", "--list", "--as=system:anonymous"]
        )
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
                    "El usuario system:anonymous tiene permisos sobre recursos del clúster. "
                    "Esto permite a cualquier actor sin credenciales interactuar con la API "
                    "de Kubernetes, pudiendo leer configuraciones, secretos o ejecutar pods."
                ),
                evidence    = "Permisos anónimos detectados:\n" + "\n".join(lineas_perm[:15]),
                affected    = "system:anonymous",
                remediation = (
                    "Ejecutar: kubectl delete clusterrolebinding <nombre-binding-anonimo>. "
                    "Deshabilitar acceso anónimo en kube-apiserver con --anonymous-auth=false. "
                    "Revisar todos los ClusterRoleBindings que referencien system:anonymous."
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
        """
        Fase 3 — Seguridad de pods y contenedores (K8S-030..K8S-059).

        Inspecciona cada pod y contenedor en busca de configuraciones
        inseguras del securityContext, capacidades peligrosas, acceso al
        host y ausencia de limits de recursos.
        """
        _log_phase(3, "Seguridad de pods y contenedores")

        pods_data = _kubectl(["get", "pods"] + self._ns_filter() + ["-o", "json"])
        if not pods_data:
            _log_warn("No se pudieron obtener pods (¿permisos insuficientes?)")
            return

        pods = pods_data.get("items", [])
        _log_info(f"Analizando {len(pods)} pods...")

        # Contadores para resumen
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

            # SecurityContext a nivel de pod
            pod_sc = spec_pod.get("securityContext", {}) or {}

            # hostPID
            if spec_pod.get("hostPID") is True:
                contadores["hostpid"] += 1
                self._add(Finding(
                    id          = "K8S-034",
                    title       = "Pod comparte PID namespace del host",
                    severity    = "CRITICAL",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostPID=true. "
                        "Esto permite al contenedor ver y señalizar todos los procesos del nodo, "
                        "facilitando la extracción de credenciales de la memoria de otros procesos."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostPID=true",
                    affected    = afectado,
                    remediation = (
                        "Eliminar hostPID: true de la spec del pod. "
                        "Si es necesario para una aplicación específica, "
                        "aislarla en un namespace dedicado con NetworkPolicy estricta."
                    ),
                    cvss        = 9.0,
                    tags        = ["pod", "hostpid", "escalada"],
                ))

            # hostIPC
            if spec_pod.get("hostIPC") is True:
                contadores["hostipc"] += 1
                self._add(Finding(
                    id          = "K8S-035",
                    title       = "Pod comparte IPC namespace del host",
                    severity    = "HIGH",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostIPC=true. "
                        "Permite al contenedor acceder a la memoria compartida IPC del nodo, "
                        "facilitando ataques de comunicación entre procesos del host."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostIPC=true",
                    affected    = afectado,
                    remediation = (
                        "Eliminar hostIPC: true de la spec del pod. "
                        "Usar mecanismos de IPC dentro del pod si la comunicación "
                        "entre contenedores es necesaria."
                    ),
                    cvss        = 7.5,
                    tags        = ["pod", "hostipc", "escalada"],
                ))

            # hostNetwork
            if spec_pod.get("hostNetwork") is True:
                contadores["hostnet"] += 1
                self._add(Finding(
                    id          = "K8S-036",
                    title       = "Pod comparte red del host",
                    severity    = "HIGH",
                    description = (
                        f"El pod '{pod_name}' en namespace '{pod_ns}' tiene hostNetwork=true. "
                        "El contenedor puede acceder a toda la red del nodo, incluyendo "
                        "servicios internos no expuestos, metadatos de cloud y el API server."
                    ),
                    evidence    = f"Pod: {afectado}\nSpec: hostNetwork=true",
                    affected    = afectado,
                    remediation = (
                        "Eliminar hostNetwork: true. Usar servicios de Kubernetes "
                        "para exponer puertos. Reservar hostNetwork para DaemonSets "
                        "de red del sistema (CNI plugins) con revisión explícita."
                    ),
                    cvss        = 8.0,
                    tags        = ["pod", "hostnetwork", "red"],
                ))

            # Analizar contenedores (init + regulares)
            contenedores_all = (
                spec_pod.get("initContainers", []) or []
            ) + (
                spec_pod.get("containers", []) or []
            )

            for cont in contenedores_all:
                cont_name = cont.get("name", "?")
                cont_afc  = f"{afectado}/{cont_name}"
                sc = cont.get("securityContext", {}) or {}

                # Modo privilegiado
                if sc.get("privileged") is True:
                    contadores["privileged"] += 1
                    self._add(Finding(
                        id          = "K8S-030",
                        title       = "Contenedor ejecutándose en modo privilegiado",
                        severity    = "CRITICAL",
                        description = (
                            f"El contenedor '{cont_name}' en pod '{pod_name}' "
                            f"(namespace '{pod_ns}') tiene securityContext.privileged=true. "
                            "Un contenedor privilegiado tiene acceso casi total al nodo "
                            "subyacente, pudiendo modificar el kernel, el filesystem del host "
                            "y escapar del aislamiento del contenedor."
                        ),
                        evidence    = f"Pod/Contenedor: {cont_afc}\nsecurityContext.privileged: true",
                        affected    = cont_afc,
                        remediation = (
                            "Eliminar securityContext.privileged: true. "
                            "Sustituir por capabilities específicas si son necesarias. "
                            "Usar PSA (Pod Security Admission) en modo 'restricted' para "
                            "bloquear pods privilegiados en el namespace."
                        ),
                        cvss        = 9.8,
                        tags        = ["contenedor", "privilegiado", "escalada"],
                        references  = [
                            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                        ],
                    ))

                # Ejecución como root
                run_as_user    = sc.get("runAsUser")
                run_as_nonroot = sc.get("runAsNonRoot")
                # Herencia del pod-level SC
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
                            f"(namespace '{pod_ns}') está configurado para ejecutarse "
                            "como root (runAsUser=0 o runAsNonRoot=false). "
                            "Si el contenedor es comprometido, el atacante tiene "
                            "privilegios de root dentro del mismo."
                        ),
                        evidence    = (
                            f"Pod/Contenedor: {cont_afc}\n"
                            f"runAsUser={run_as_user}, runAsNonRoot={run_as_nonroot}"
                        ),
                        affected    = cont_afc,
                        remediation = (
                            "Configurar runAsNonRoot: true y runAsUser con UID > 1000. "
                            "Reconstruir la imagen del contenedor con un usuario no-root. "
                            "Usar USER en el Dockerfile para evitar la ejecución como root."
                        ),
                        cvss        = 7.2,
                        tags        = ["contenedor", "root", "escalada"],
                    ))

                # Escalada de privilegios
                allow_esc = sc.get("allowPrivilegeEscalation")
                if allow_esc is None or allow_esc is True:
                    contadores["escalation"] += 1
                    if allow_esc is True:  # solo reportar los explícitamente True
                        self._add(Finding(
                            id          = "K8S-032",
                            title       = "Contenedor permite escalada de privilegios",
                            severity    = "HIGH",
                            description = (
                                f"El contenedor '{cont_name}' en pod '{pod_name}' "
                                "tiene allowPrivilegeEscalation: true explícito. "
                                "Esto permite que procesos dentro del contenedor obtengan "
                                "más privilegios que su proceso padre mediante setuid/setgid."
                            ),
                            evidence    = (
                                f"Pod/Contenedor: {cont_afc}\n"
                                f"securityContext.allowPrivilegeEscalation: true"
                            ),
                            affected    = cont_afc,
                            remediation = (
                                "Configurar allowPrivilegeEscalation: false en todos los "
                                "contenedores. Esto es requerido por los perfiles PSA "
                                "'baseline' y 'restricted'."
                            ),
                            cvss        = 7.0,
                            tags        = ["contenedor", "escalada-privilegios"],
                        ))

                # Capabilities peligrosas
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
                            f"{', '.join(sorted(caps_criticas_presentes))}. "
                            "Estas capabilities permiten operaciones privilegiadas en el "
                            "kernel del nodo y pueden usarse para escapar del contenedor."
                        ),
                        evidence    = (
                            f"Pod/Contenedor: {cont_afc}\n"
                            f"capabilities.add: {sorted(caps_add)}"
                        ),
                        affected    = cont_afc,
                        remediation = (
                            "Eliminar las capabilities críticas. Aplicar el principio de "
                            "mínimo privilegio: añadir solo la capability mínima necesaria. "
                            "Considerar usar seccomp profiles para restringir syscalls."
                        ),
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
                        remediation = (
                            "Revisar si las capabilities son estrictamente necesarias. "
                            "Preferir capabilities específicas de red solo si el contenedor "
                            "es un componente de red del sistema."
                        ),
                        cvss        = 7.5,
                        tags        = ["contenedor", "capabilities"],
                    ))

                # Montajes de rutas sensibles del host
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
                    vol_spec.get("hostPath", {}).get("path", "")
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
                                f"'{host_path}' en '{mount_path}'. "
                                + (
                                    "El socket del runtime (Docker/containerd) da control "
                                    "total sobre todos los contenedores del nodo."
                                    if es_socket else
                                    "El acceso a rutas sensibles del host puede permitir "
                                    "la lectura de credenciales o la modificación del sistema."
                                )
                            ),
                            evidence    = (
                                f"Pod/Contenedor: {cont_afc}\n"
                                f"hostPath: {host_path}\nmountPath: {mount_path}"
                            ),
                            affected    = cont_afc,
                            remediation = (
                                "Eliminar el mountPath al runtime socket. "
                                "Si se requiere gestión de contenedores, "
                                "usar la API de Kubernetes en lugar del socket directo."
                                if es_socket else
                                f"Eliminar o restringir el montaje de '{host_path}'. "
                                "Usar ConfigMaps o Secrets para pasar configuración "
                                "en lugar de montar rutas del host."
                            ),
                            cvss        = 9.8 if es_socket else 8.0,
                            tags        = ["contenedor", "hostpath", "montaje"],
                        ))

                # Sin límites de recursos
                resources   = cont.get("resources", {}) or {}
                limits      = resources.get("limits", {}) or {}
                if not limits:
                    contadores["sin_limits"] += 1

                # Sin probes de health
                has_ready  = bool(cont.get("readinessProbe"))
                has_live   = bool(cont.get("livenessProbe"))
                if not has_ready and not has_live:
                    contadores["sin_probes"] += 1

        # Hallazgos de resumen para sin_limits y sin_probes (agrupados)
        if contadores["sin_limits"] > 0:
            self._add(Finding(
                id          = "K8S-038",
                title       = "Pods sin límites de recursos definidos",
                severity    = "LOW",
                description = (
                    f"{contadores['sin_limits']} contenedor(es) no tienen definidos "
                    "resource.limits (CPU y/o memoria). La ausencia de límites permite "
                    "que un pod consuma todos los recursos del nodo (DoS por starving), "
                    "afectando a otros pods y a la estabilidad del clúster."
                ),
                evidence    = (
                    f"Contenedores sin limits: {contadores['sin_limits']} de "
                    f"{sum(contadores.values())} analizados"
                ),
                affected    = "Múltiples pods — ver salida verbose",
                remediation = (
                    "Definir resources.limits.cpu y resources.limits.memory en todos los "
                    "contenedores. Usar LimitRange en los namespaces para imponer límites "
                    "por defecto. Configurar ResourceQuota a nivel de namespace."
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
                    "readinessProbe ni livenessProbe. Sin estas sondas, Kubernetes no "
                    "puede detectar automáticamente pods en estado degradado ni "
                    "reiniciarlos de forma autónoma."
                ),
                evidence    = f"Contenedores sin probes: {contadores['sin_probes']}",
                affected    = "Múltiples pods",
                remediation = (
                    "Definir livenessProbe y readinessProbe en todos los contenedores. "
                    "Usar httpGet, tcpSocket o exec según el tipo de servicio."
                ),
                tags        = ["pods", "health", "probes"],
            ))

        _log_info(
            f"Análisis de pods completado — privilegiados: {contadores['privileged']}, "
            f"root: {contadores['root']}, montajes sensibles: {contadores['mounts_sensibles']}"
        )

    # ── Fase 4: Red y exposición ───────────────────────────────────────────

    def fase4_red(self) -> None:
        """
        Fase 4 — Red y exposición (K8S-060..K8S-079).

        Analiza servicios expuestos externamente, ausencia de NetworkPolicies,
        Ingress sin TLS, el Kubernetes Dashboard y la exposición de etcd.
        """
        _log_phase(4, "Red y exposición")

        # ── Servicios LoadBalancer / NodePort
        svc_data = _kubectl(["get", "services"] + self._ns_filter() + ["-o", "json"])
        if svc_data:
            for svc in svc_data.get("items", []):
                meta_svc = svc.get("metadata", {})
                spec_svc = svc.get("spec", {})
                svc_tipo = spec_svc.get("type", "ClusterIP")
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
                            f"es de tipo {svc_tipo} y está expuesto externamente. "
                            + (
                                "El Kubernetes Dashboard accesible públicamente es "
                                "una superficie de ataque crítica."
                                if is_dashboard else
                                "Los servicios expuestos directamente amplían la "
                                "superficie de ataque del clúster."
                            )
                        ),
                        evidence    = (
                            f"Servicio: {afectado}\nTipo: {svc_tipo}\n"
                            f"Puertos: {puertos_str}\n"
                            f"IPs externas: {', '.join(lb_ips) if lb_ips else 'pendiente/nodeport'}"
                        ),
                        affected    = afectado,
                        remediation = (
                            "Cambiar el tipo de servicio a ClusterIP y exponer a través "
                            "de un Ingress con autenticación. Para el Dashboard, usar "
                            "kubectl proxy o VPN para acceso administrativo."
                            if is_dashboard else
                            "Revisar si la exposición externa es necesaria. "
                            "Preferir Ingress con TLS y autenticación. "
                            "Configurar NetworkPolicy para limitar el origen de las conexiones."
                        ),
                        cvss        = 9.8 if is_dashboard else 7.5,
                        tags        = ["red", "servicio", svc_tipo.lower()],
                    ))
            _log_clean("Revisión de servicios completada")
        else:
            _log_warn("No se pudieron obtener servicios")

        # ── NetworkPolicies por namespace
        np_data    = _kubectl(["get", "networkpolicies"] + self._ns_filter() + ["-o", "json"])
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
                        "NetworkPolicy. Sin NetworkPolicy, todo el tráfico entre pods "
                        "está permitido por defecto, incluyendo movimiento lateral entre "
                        "namespaces y servicios que no deberían comunicarse entre sí."
                    ),
                    evidence    = (
                        "Namespaces sin NetworkPolicy (con pods activos):\n"
                        + "\n".join(ns_sin_np[:20])
                    ),
                    affected    = f"{len(ns_sin_np)} namespaces",
                    remediation = (
                        "Crear una NetworkPolicy de denegación por defecto en cada namespace: "
                        "'deny-all-ingress' + 'deny-all-egress'. "
                        "Luego añadir políticas explícitas para el tráfico permitido. "
                        "Usar Calico, Cilium o similar como plugin CNI."
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

        # ── Ingress sin TLS
        ing_data = _kubectl(["get", "ingresses"] + self._ns_filter() + ["-o", "json"])
        if ing_data:
            for ing in ing_data.get("items", []):
                meta_ing = ing.get("metadata", {})
                spec_ing = ing.get("spec", {})
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
                            "no tiene TLS configurado. El tráfico entre el cliente "
                            "y el Ingress controller se transmite en texto plano "
                            "(HTTP), exponiendo credenciales y datos de sesión."
                        ),
                        evidence    = (
                            f"Ingress: {ing_ns}/{ing_nombre}\n"
                            f"Hosts: {', '.join(hosts[:5])}\n"
                            f"TLS: no configurado"
                        ),
                        affected    = f"Ingress/{ing_ns}/{ing_nombre}",
                        remediation = (
                            "Añadir una sección 'tls:' al Ingress con el secreto "
                            "que contiene el certificado. Usar cert-manager para "
                            "gestión automática de certificados Let's Encrypt. "
                            "Forzar redirección HTTP→HTTPS."
                        ),
                        cvss        = 6.5,
                        tags        = ["red", "ingress", "tls", "http"],
                    ))
            _log_clean("Revisión de Ingress completada")
        else:
            _log_info("No se encontraron recursos Ingress o no hay permisos")

        # ── Kubernetes Dashboard expuesto (búsqueda específica)
        svc_dash = _kubectl(
            ["get", "services", "--all-namespaces",
             "-l", "k8s-app=kubernetes-dashboard", "-o", "json"]
        )
        if svc_dash:
            for svc in svc_dash.get("items", []):
                tipo = svc.get("spec", {}).get("type", "ClusterIP")
                if tipo in ("LoadBalancer", "NodePort"):
                    _log_info("Dashboard ya reportado como servicio externo")

        # ── etcd expuesto
        if self._server_url:
            self._check_etcd_expuesto(self._server_url)
        else:
            _log_info("URL del API server no disponible, omitiendo verificación de etcd")

    def _check_etcd_expuesto(self, server_url: str) -> None:
        """Intenta conexión TCP a los puertos de etcd en el host del API server."""
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
                            f"El puerto {puerto} de etcd está accesible en el host "
                            f"'{host}'. etcd almacena TODOS los secretos, "
                            "configuraciones y estado del clúster en texto plano "
                            "(o con una clave de cifrado). El acceso directo a etcd "
                            "permite leer todos los Secrets, modificar el estado del "
                            "clúster y comprometer completamente la instalación de Kubernetes."
                        ),
                        evidence    = (
                            f"Conexión TCP exitosa a {host}:{puerto}\n"
                            f"Este es el puerto de {'cliente' if puerto == 2379 else 'peers'} de etcd."
                        ),
                        affected    = f"{host}:{puerto}",
                        remediation = (
                            "Restringir el acceso a los puertos 2379/2380 mediante firewall "
                            "a solo los nodos del clúster. Habilitar autenticación TLS en etcd. "
                            "Habilitar cifrado at-rest de secretos en el API server "
                            "(--encryption-provider-config). Auditar quién tiene acceso a etcd."
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
        """
        Fase 5 — Gestión de secretos (K8S-080..K8S-099).

        Detecta secretos expuestos como variables de entorno en pods,
        posibles secretos en ConfigMaps e inventario de Secrets de Kubernetes.
        """
        _log_phase(5, "Gestión de secretos")

        # Patrones de nombre de variable que sugieren credenciales
        PATRON_NOMBRE_VAR = re.compile(
            r"(password|passwd|secret|token|api[_\-]?key|credential|auth[_\-]?key"
            r"|private[_\-]?key|access[_\-]?key|client[_\-]?secret|db[_\-]?pass"
            r"|database[_\-]?url|redis[_\-]?url|mongo[_\-]?url|mysql[_\-]?url"
            r"|smtp[_\-]?pass|jwt[_\-]?secret|encryption[_\-]?key|signing[_\-]?key)",
            re.IGNORECASE,
        )
        # Patrones de valor que sugieren secretos reales
        PATRON_VALOR_SECRET = re.compile(
            r"(sk_live_|sk_test_|ghp_|glpat-|xox[baprs]-|ey[A-Za-z0-9]{10,}"
            r"|-----BEGIN [A-Z ]+KEY-----|[A-Za-z0-9+/]{40,}={0,2})",
        )

        # ── Variables de entorno en pods
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
                        # Verificar si tiene un secreto referenciado directamente (como valor literal)
                        # vs secretRef (que es la forma correcta)
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
                                    "con un valor literal que parece ser una credencial. "
                                    "Las variables de entorno se almacenan en etcd sin cifrar "
                                    "y son visibles en 'kubectl describe pod'."
                                ),
                                evidence    = (
                                    f"Pod/Contenedor: {afectado}/{cont_name}\n"
                                    f"Variable: {var_nombre}\n"
                                    f"Valor: {'***REDACTADO***' if var_valor else '(vacío)'}"
                                ),
                                affected    = f"{afectado}/{cont_name}",
                                remediation = (
                                    "Usar secretRef o secretKeyRef en lugar de valores literales. "
                                    "Crear un Secret de Kubernetes y referenciar su clave. "
                                    "Considerar soluciones de gestión de secretos como "
                                    "HashiCorp Vault o Sealed Secrets."
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

        # ── Posibles secretos en ConfigMaps
        cm_data = _kubectl(["get", "configmaps"] + self._ns_filter() + ["-o", "json"])
        cms_con_secretos = 0
        if cm_data:
            for cm in cm_data.get("items", []):
                meta_cm = cm.get("metadata", {})
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
                                "sugiere que puede ser una credencial o secreto. "
                                "Los ConfigMaps no están cifrados en etcd y son "
                                "accesibles con permisos de lectura básicos."
                            ),
                            evidence    = (
                                f"ConfigMap: {cm_ns}/{cm_nombre}\n"
                                f"Clave: {clave}\n"
                                f"Longitud valor: {len(valor_str)} caracteres"
                            ),
                            affected    = f"ConfigMap/{cm_ns}/{cm_nombre}",
                            remediation = (
                                "Mover el valor a un Secret de Kubernetes. "
                                "Los ConfigMaps son para configuración no sensible. "
                                "Revisar si la clave debe cifrarse con Sealed Secrets "
                                "o gestionarse con un vault externo."
                            ),
                            cvss        = 5.5,
                            tags        = ["secretos", "configmap", "credenciales"],
                        ))
                        break  # un hallazgo por ConfigMap es suficiente
            _log_clean(f"Revisión de ConfigMaps completada ({cms_con_secretos} potencialmente expuestos)")
        else:
            _log_warn("No se pudieron obtener ConfigMaps")

        # ── Inventario de Secrets
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
                        "en el namespace 'default'. Los secretos en el namespace default "
                        "son accesibles por cualquier pod en ese namespace si tienen "
                        "permisos RBAC básicos, y el namespace default suele ser más "
                        "permisivo que los namespaces de aplicación."
                    ),
                    evidence    = (
                        "Secrets Opaque en namespace 'default':\n"
                        + "\n".join(
                            s.get("metadata", {}).get("name", "?")
                            for s in secrets_default[:15]
                        )
                    ),
                    affected    = "namespace/default",
                    remediation = (
                        "Mover los Secrets al namespace de la aplicación que los consume. "
                        "Eliminar Secrets obsoletos del namespace default. "
                        "Revisar los RBAC que permiten acceso a Secrets en 'default'."
                    ),
                    cvss        = 5.0,
                    tags        = ["secretos", "namespace", "default"],
                ))
        else:
            _log_warn("No se pudieron obtener Secrets (puede requerir permisos adicionales)")

    # ── Fase 6: Imágenes y runtime ─────────────────────────────────────────

    def fase6_imagenes(self) -> None:
        """
        Fase 6 — Imágenes y runtime (K8S-090..K8S-109).

        Analiza las imágenes de los pods en busca de tags :latest, registros
        no corporativos y ausencia de filesystem de solo lectura. Verifica
        la configuración de Pod Security Admission por namespace.
        """
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

                # Tag :latest o sin tag
                tiene_tag = ":" in imagen.split("/")[-1]
                tag_es_latest = imagen.endswith(":latest")
                if not tiene_tag or tag_es_latest:
                    imagenes_latest.append(f"{pod_ns}/{pod_name}: {imagen}")

                # Registro público
                partes = imagen.split("/")
                registro = ""
                if len(partes) >= 2 and ("." in partes[0] or ":" in partes[0]):
                    registro = partes[0].lower()
                elif len(partes) == 1:
                    registro = "docker.io"  # imagen oficial de Docker Hub
                if registro in REGISTROS_PUBLICOS:
                    imagenes_publicas.append(f"{pod_ns}/{pod_name}: {imagen}")

                # Filesystem de solo lectura
                if not sc.get("readOnlyRootFilesystem"):
                    imagenes_noreadonly += 1

        if imagenes_latest:
            self._add(Finding(
                id          = "K8S-090",
                title       = "Imágenes con tag ':latest' o sin tag de versión",
                severity    = "MEDIUM",
                description = (
                    f"{len(imagenes_latest)} imagen(es) usan el tag ':latest' o no "
                    "especifican tag de versión. El tag ':latest' apunta a la última "
                    "versión publicada, que puede cambiar sin control, introducir "
                    "regresiones de seguridad o comportamientos inesperados."
                ),
                evidence    = (
                    "Imágenes con :latest o sin tag:\n"
                    + "\n".join(imagenes_latest[:20])
                ),
                affected    = f"{len(imagenes_latest)} contenedores",
                remediation = (
                    "Especificar tags de versión explícitos y fijos (p.ej. nginx:1.25.3). "
                    "Usar digests SHA256 para máxima reproducibilidad. "
                    "Configurar admission webhooks que rechacen imágenes con :latest."
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
                    f"{len(imagenes_publicas)} imagen(es) se descargan de registros "
                    "públicos (Docker Hub, GCR, Quay.io, etc.) sin pasar por un "
                    "registro interno con análisis de vulnerabilidades. "
                    "Las imágenes de registros públicos pueden contener malware, "
                    "backdoors o vulnerabilidades conocidas no parcheadas."
                ),
                evidence    = (
                    "Imágenes de registros públicos:\n"
                    + "\n".join(imagenes_publicas[:20])
                ),
                affected    = f"{len(imagenes_publicas)} contenedores",
                remediation = (
                    "Usar un registro privado (Harbor, ECR privado, GitLab Registry) "
                    "que realice análisis de vulnerabilidades (Trivy, Clair) antes de "
                    "aprobar las imágenes. Implementar políticas de imagen firmada "
                    "(Cosign, Notary)."
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
                    "readOnlyRootFilesystem: true. Un filesystem de escritura permite "
                    "a un atacante con acceso al contenedor instalar herramientas, "
                    "modificar binarios o persistir tras un reinicio."
                ),
                evidence    = (
                    f"Contenedores sin readOnlyRootFilesystem: {imagenes_noreadonly}"
                ),
                affected    = f"{imagenes_noreadonly} contenedores",
                remediation = (
                    "Configurar readOnlyRootFilesystem: true en securityContext. "
                    "Montar volúmenes emptyDir para directorios que necesiten escritura "
                    "(p.ej. /tmp, /var/cache). Reconstruir la imagen para no necesitar "
                    "escritura en el filesystem raíz."
                ),
                tags        = ["imágenes", "filesystem", "runtime"],
            ))

        # ── Pod Security Admission por namespace
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
                        "Pod Security Admission (PSA). Sin PSA, no hay restricciones "
                        "automáticas sobre las capacidades de seguridad de los pods "
                        "que se desplieguen en esos namespaces."
                    ),
                    evidence    = (
                        "Namespaces sin label pod-security.kubernetes.io/enforce:\n"
                        + "\n".join(ns_sin_psa[:20])
                    ),
                    affected    = f"{len(ns_sin_psa)} namespaces",
                    remediation = (
                        "Añadir la etiqueta 'pod-security.kubernetes.io/enforce: restricted' "
                        "a los namespaces de aplicación. Usar 'baseline' para namespaces "
                        "de sistema. Probar primero con el modo 'warn' para identificar "
                        "incompatibilidades."
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

    # ── Fase 7: OPA/Gatekeeper (v1.1) ─────────────────────────────────────

    def fase7_opa(self) -> None:
        """
        Fase 7 — Auditoría de OPA/Gatekeeper (K8S-OPA-NNN).

        Detecta si OPA/Gatekeeper está instalado comprobando la presencia de
        sus CRDs, verifica si hay constraints definidas y reporta constraints
        con violations activas como hallazgos de severidad HIGH.

        Hallazgos:
          K8S-OPA-001 — OPA no instalado → INFO (recomendación)
          K8S-OPA-002 — OPA instalado sin constraints → MEDIUM
          K8S-OPA-003 — Constraint con violations > 0 → HIGH por constraint
        """
        _log_phase(7, "OPA/Gatekeeper")

        # Comprobar si OPA/Gatekeeper está instalado buscando sus CRDs
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
                    "No se detectaron CRDs de OPA/Gatekeeper en el clúster. "
                    "OPA Gatekeeper implementa admission control basado en políticas, "
                    "impidiendo el despliegue de recursos que violen las normas de "
                    "seguridad definidas por el equipo."
                ),
                evidence    = "kubectl get crd | grep gatekeeper — sin resultados",
                affected    = "Clúster completo",
                remediation = (
                    "Considerar la instalación de OPA/Gatekeeper:\n"
                    "  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/"
                    "gatekeeper/v3.14.0/deploy/gatekeeper.yaml\n"
                    "Ref: https://open-policy-agent.github.io/gatekeeper/"
                ),
                tags        = ["opa", "gatekeeper", "admission-control", "policy"],
            ))
            _log_clean("OPA/Gatekeeper no instalado (recomendación INFO emitida)")
            return

        _log_info(f"OPA/Gatekeeper detectado ({len(gatekeeper_crds)} CRDs encontrados)")

        # Comprobar si hay constraints definidas
        constraints_data = _kubectl(["get", "constraints", "--all-namespaces", "-o", "json"])
        if not constraints_data or not constraints_data.get("items"):
            self._add(Finding(
                id          = "K8S-OPA-002",
                title       = "OPA/Gatekeeper instalado pero sin constraints definidas",
                severity    = "MEDIUM",
                description = (
                    "OPA/Gatekeeper está instalado pero no hay constraints definidas. "
                    "Sin constraints activas, el admission controller no aplica ninguna "
                    "política de seguridad — la instalación es ineficaz."
                ),
                evidence    = "kubectl get constraints --all-namespaces — sin resultados",
                affected    = "OPA/Gatekeeper",
                remediation = (
                    "Definir constraints de seguridad adecuadas:\n"
                    "  - Prohibir contenedores privilegiados (K8sPSPPrivilegedContainer)\n"
                    "  - Requerir usuarios no root (K8sPSPAllowedUsers)\n"
                    "  - Restringir imágenes a registros autorizados\n"
                    "Ref: https://open-policy-agent.github.io/gatekeeper/website/"
                    "docs/constrainttemplates"
                ),
                tags        = ["opa", "gatekeeper", "constraints", "policy"],
            ))
            return

        items = constraints_data.get("items", [])
        _log_info(f"Constraints encontradas: {len(items)}")

        # Analizar violations activas en cada constraint
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
                        f"{n_violations} violation(s) activa(s). Existen recursos en el "
                        "clúster que violan las políticas de seguridad definidas."
                    ),
                    evidence    = "\n".join(partes_evidencia),
                    affected    = f"OPA Constraint: {kind}/{nombre}",
                    remediation = (
                        f"Corregir los recursos que violan la constraint '{nombre}':\n"
                        "  kubectl get constraints -o jsonpath='{.items[*].status.violations}'\n"
                        "Durante la remediación se puede usar modo 'warn' para no bloquear:\n"
                        "  spec.enforcementAction: warn"
                    ),
                    tags        = ["opa", "gatekeeper", "constraints", "violations", "policy"],
                ))
            else:
                _log_clean(f"Constraint {kind}/{nombre}: sin violations")

    # ── Fase 8: Admission Webhooks (v1.1) ─────────────────────────────────

    def fase8_webhooks(self) -> None:
        """
        Fase 8 — Auditoría de Admission Webhooks (K8S-WHK-NNN).

        Audita ValidatingWebhookConfigurations y MutatingWebhookConfigurations
        en busca de configuraciones inseguras que puedan eludir controles.

        Hallazgos:
          K8S-WHK-001 — failurePolicy: Ignore → MEDIUM (bypass en fallo)
          K8S-WHK-002 — namespaceSelector vacío → HIGH (aplica a kube-system)
          K8S-WHK-003 — timeoutSeconds > 10 → LOW (latencia del API server)
        """
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

                    # 1. failurePolicy: Ignore — fallo del webhook permite la operación
                    failure_policy = wh.get("failurePolicy", "Fail")
                    if failure_policy == "Ignore":
                        self._add(Finding(
                            id          = "K8S-WHK-001",
                            title       = (
                                f"Webhook con failurePolicy=Ignore: {wh_name}"
                            ),
                            severity    = "MEDIUM",
                            description = (
                                f"El {wh_tipo.lower()} webhook '{wh_name}' en "
                                f"'{cfg_name}' tiene failurePolicy=Ignore. Si el "
                                "webhook falla o es inalcanzable, la operación se "
                                "permite de todas formas, eludiendo los controles "
                                "de seguridad que implementa."
                            ),
                            evidence    = f"{affected}\nfailurePolicy: Ignore",
                            affected    = affected,
                            remediation = (
                                "Cambiar failurePolicy a 'Fail' para que un fallo del "
                                "webhook bloquee la operación en lugar de permitirla:\n"
                                "  failurePolicy: Fail\n"
                                "Asegurarse de que el webhook tiene alta disponibilidad "
                                "antes de activar este modo en producción."
                            ),
                            tags        = ["webhooks", "admission-control", "failure-policy"],
                        ))

                    # 2. namespaceSelector vacío — aplica a kube-system y a todos
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
                                f"Webhook sin namespaceSelector (cubre kube-system): "
                                f"{wh_name}"
                            ),
                            severity    = "HIGH",
                            description = (
                                f"El webhook '{wh_name}' no tiene namespaceSelector "
                                "definido, lo que lo aplica a TODOS los namespaces "
                                "incluyendo kube-system. Un fallo del webhook puede "
                                "interrumpir componentes críticos del control plane."
                            ),
                            evidence    = f"{affected}\nnamespaceSelector: {{}}",
                            affected    = affected,
                            remediation = (
                                "Añadir un namespaceSelector para excluir kube-system:\n"
                                "  namespaceSelector:\n"
                                "    matchExpressions:\n"
                                "    - key: kubernetes.io/metadata.name\n"
                                "      operator: NotIn\n"
                                "      values: [kube-system, kube-public]"
                            ),
                            tags        = [
                                "webhooks", "admission-control", "namespace-selector",
                            ],
                        ))

                    # 3. timeoutSeconds > 10 — timeout elevado
                    timeout_secs = wh.get("timeoutSeconds", 10)
                    if isinstance(timeout_secs, int) and timeout_secs > 10:
                        self._add(Finding(
                            id          = "K8S-WHK-003",
                            title       = (
                                f"Webhook con timeout elevado "
                                f"({timeout_secs}s): {wh_name}"
                            ),
                            severity    = "LOW",
                            description = (
                                f"El webhook '{wh_name}' tiene "
                                f"timeoutSeconds={timeout_secs}. Un timeout elevado "
                                "puede ralentizar el API server si el webhook es lento "
                                "o inalcanzable, afectando la disponibilidad del clúster."
                            ),
                            evidence    = (
                                f"{affected}\ntimeoutSeconds: {timeout_secs}"
                            ),
                            affected    = affected,
                            remediation = (
                                "Reducir timeoutSeconds a un máximo de 5-10 segundos:\n"
                                "  timeoutSeconds: 5\n"
                                "Optimizar el webhook para responder rápidamente."
                            ),
                            tags        = ["webhooks", "admission-control", "timeout"],
                        ))

    # ── Fase 9: CVEs activos (v1.2) ───────────────────────────────────────

    @staticmethod
    def _parse_runc_version(version_str: str) -> Optional[Tuple[int, int, int, str]]:
        """
        Extrae la versión semver de una cadena de versión de runc.

        Retorna una tupla (major, minor, patch, pre) o None si no se puede parsear.
        Ejemplos de entrada: 'runc version 1.1.12', '1.2.3', '1.4.0-rc.3'
        """
        # Buscar patrón semver con opcional pre-release
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
        """
        K8S-RUNC-001 (CRITICAL): CVE-2025-52881 — escape de contenedor runc vía race condition
        en shared mounts. Afecta a runc < 1.2.8, < 1.3.3, < 1.4.0-rc.3.

        K8S-RUNC-002 (HIGH): versión de runc no verificable.
        """
        _log_info("Verificando CVE-2025-52881 (runc container escape)...")

        # Obtener versiones del runtime desde los nodos
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

        # Intentar también runc/crictl locales como fuente secundaria
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
            # No se pudo determinar la versión
            self._add(Finding(
                id          = "K8S-RUNC-002",
                title       = "Versión de runc no verificable (CVE-2025-52881)",
                severity    = "HIGH",
                description = (
                    "No se pudo determinar la versión del runtime runc en los nodos del "
                    "clúster. CVE-2025-52881 es una vulnerabilidad crítica de escape de "
                    "contenedor por race condition en shared mounts. La incapacidad de "
                    "verificar la versión impide confirmar si el clúster está parcheado."
                ),
                evidence    = (
                    "kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo."
                    "containerRuntimeVersion}' — sin resultados\n"
                    "runc --version / crictl version — no disponibles localmente"
                ),
                affected    = "Nodos del clúster (versión runc indeterminada)",
                remediation = (
                    "Verificar manualmente la versión de runc en cada nodo:\n"
                    "  kubectl debug node/<nombre> -it --image=busybox -- runc --version\n"
                    "Actualizar runc a >= 1.2.8 (rama 1.x), >= 1.3.3 (rama 1.3.x) "
                    "o >= 1.4.0 (rama 1.4.x)."
                ),
                cvss        = 7.8,
                tags        = ["cve", "runc", "container-escape", "CVE-2025-52881"],
                references  = [
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-XXXX"
                ],
            ))
            return

        # Analizar si alguna versión detectada es vulnerable
        versiones_vulnerables: List[str] = []
        for ver_raw in versiones_candidatas:
            parsed = self._parse_runc_version(ver_raw)
            if parsed is None:
                continue
            major, minor, patch, pre = parsed
            # Solo analizar runc (el runtime puede ser containerd, cri-o, etc.)
            # Si la cadena no menciona runc explícitamente, intentar igual si tiene semver
            vulnerable = False
            if major == 1:
                if minor <= 1:
                    # Rama 1.x (1.0.x, 1.1.x): vulnerable si < 1.2.8
                    vulnerable = True
                elif minor == 2 and patch < 8:
                    vulnerable = True
                elif minor == 3 and patch < 3:
                    # Rama 1.3.x: vulnerable si < 1.3.3
                    vulnerable = True
                elif minor == 4:
                    # Rama 1.4.x: vulnerable si < 1.4.0 (rc.3 considerado pre-release vulnerable)
                    if patch == 0 and pre and "rc" in pre:
                        # Extraer número de rc
                        rc_match = re.search(r"rc\.?(\d+)", pre)
                        if rc_match and int(rc_match.group(1)) < 3:
                            vulnerable = True
                        elif not rc_match:
                            vulnerable = True  # rc sin número → asumir vulnerable
                    elif patch == 0 and pre:
                        vulnerable = True  # cualquier pre-release de 1.4.0 anterior
            if vulnerable:
                versiones_vulnerables.append(ver_raw)

        if versiones_vulnerables:
            self._add(Finding(
                id          = "K8S-RUNC-001",
                title       = "CVE-2025-52881: runc vulnerable a escape de contenedor (CRÍTICO)",
                severity    = "CRITICAL",
                description = (
                    "Se detectaron versiones de runc vulnerables a CVE-2025-52881, una "
                    "race condition en el manejo de shared mounts que permite a un proceso "
                    "dentro de un contenedor escapar al namespace del host y obtener "
                    "acceso root al nodo subyacente. Afecta a runc < 1.2.8 (rama 1.x), "
                    "< 1.3.3 (rama 1.3.x) y < 1.4.0-rc.3 (rama 1.4.x pre-release)."
                ),
                evidence    = (
                    "Versiones de runtime detectadas en los nodos:\n"
                    + "\n".join(versiones_candidatas[:10]) + "\n"
                    "Versiones identificadas como vulnerables:\n"
                    + "\n".join(versiones_vulnerables[:10])
                ),
                affected    = f"Nodos del clúster ({len(versiones_vulnerables)} versiones vulnerables)",
                remediation = (
                    "Actualizar runc inmediatamente:\n"
                    "  - Rama 1.x → runc >= 1.2.8\n"
                    "  - Rama 1.3.x → runc >= 1.3.3\n"
                    "  - Rama 1.4.x → runc >= 1.4.0 (release estable)\n"
                    "En distribuciones gestionadas (EKS, GKE, AKS), actualizar el node pool "
                    "a la última versión de la imagen base del nodo.\n"
                    "Verificar la versión tras el parche:\n"
                    "  kubectl debug node/<nombre> -it --image=busybox -- runc --version"
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
        """
        K8S-ACM-001 (CRITICAL): CVE-2026-66786 — escalada de privilegios sin autenticación
        en Red Hat Advanced Cluster Management (ACM).

        Verifica si ACM está instalado y si el endpoint de la API responde sin credenciales.
        Si ACM no está presente, se omite el check silenciosamente.
        """
        _log_info("Verificando presencia de Red Hat ACM (CVE-2026-66786)...")

        # Detectar ACM: buscar el hub de multicluster en open-cluster-management
        acm_hub_raw = _kubectl_raw(
            ["get", "pods", "-n", "open-cluster-management",
             "--no-headers", "-o", "wide"]
        )
        tiene_acm = False
        if acm_hub_raw and "multicluster" in acm_hub_raw.lower():
            tiene_acm = True

        # Segunda comprobación: ClusterManagementAddon (recurso CRD de ACM)
        if not tiene_acm:
            addon_raw = _kubectl_raw(
                ["get", "ClusterManagementAddon", "--no-headers"]
            )
            if addon_raw and addon_raw.strip():
                tiene_acm = True

        if not tiene_acm:
            if _VERBOSE:
                _log_info("ACM no detectado en el clúster — omitiendo CVE-2026-66786")
            return

        _log_info("Red Hat ACM detectado — verificando acceso no autenticado (CVE-2026-66786)...")

        # Intentar acceso sin credenciales al endpoint de ACM
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

        # Verificar también si el addon manager permite acceso anónimo
        if not acm_accesible_sin_auth:
            addon_list = _kubectl_raw(
                ["get", "ClusterManagementAddon", "-o",
                 "jsonpath={.items[*].metadata.name}"]
            )
            if addon_list and addon_list.strip():
                # La presencia de addons sin verificación de auth es riesgo confirmado
                # solo si el endpoint responde, de lo contrario registramos como potencial
                if _VERBOSE:
                    _log_info(
                        f"ClusterManagementAddons encontrados: {addon_list.strip()[:100]}"
                    )

        if acm_accesible_sin_auth:
            self._add(Finding(
                id          = "K8S-ACM-001",
                title       = "CVE-2026-66786: Red Hat ACM permite escalada de privs sin autenticación",
                severity    = "CRITICAL",
                description = (
                    "El endpoint /multicloud/api/v1/ de Red Hat Advanced Cluster Management "
                    "(ACM) responde con HTTP 200 sin credenciales de autenticación. "
                    "CVE-2026-66786 describe una vulnerabilidad de escalada de privilegios "
                    "sin autenticación que permite a un atacante tomar control del hub de "
                    "gestión y, transitivamente, de todos los clústeres gestionados por ACM."
                ),
                evidence    = (
                    f"GET {self._server_url}/multicloud/api/v1/ → HTTP 200 sin Authorization\n"
                    "Red Hat ACM detectado en namespace open-cluster-management"
                ),
                affected    = f"Red Hat ACM en {self._server_url}",
                remediation = (
                    "Aplicar el parche de Red Hat para CVE-2026-66786 inmediatamente:\n"
                    "  oc adm upgrade --to-latest (OpenShift) o actualizar el operador ACM.\n"
                    "Como mitigación temporal:\n"
                    "  - Restringir el acceso al endpoint /multicloud/ mediante NetworkPolicy\n"
                    "  - Verificar los ClusterRoleBindings de system:anonymous en ACM\n"
                    "  - Auditar los logs del hub ACM por accesos no autorizados recientes\n"
                    "Referencia: https://access.redhat.com/security/cve/CVE-2026-66786"
                ),
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
                "CVE-2026-66786 (ACM): endpoint no accesible sin autenticación "
                "(o ACM no expone el endpoint de forma accesible)"
            )

    def fase9_cve(self) -> None:
        """
        Fase 9 — CVEs activos (K8S-RUNC-NNN, K8S-ACM-NNN).

        Verifica CVEs críticos publicados recientemente que afectan al runtime
        del clúster y a componentes opcionales de gestión multi-clúster.

        Hallazgos:
          K8S-RUNC-001 (CRITICAL) — CVE-2025-52881: runc container escape
          K8S-RUNC-002 (HIGH)     — versión runc no verificable
          K8S-ACM-001  (CRITICAL) — CVE-2026-66786: ACM priv esc sin auth
        """
        _log_phase(9, "CVEs activos")

        if self.skip_cve:
            _log_info("Verificación de CVEs omitida (--skip-cve)")
            return

        self._check_cve_runc()
        self._check_cve_acm()

    # ── Auditoría de Helm charts (v1.3) ───────────────────────────────────

    def _audit_helm_charts(self, findings: List[Finding]) -> None:
        """
        Fase 10 — Helm charts desplegados (v1.3).

        Ejecuta 'helm list -A -o json' para enumerar los releases activos y
        comprueba malas configuraciones de seguridad comunes en sus valores.

        Hallazgos:
          K8S-HELM-001 (LOW)    — image.pullPolicy no es Always
          K8S-HELM-002 (MEDIUM) — securityContext ausente
          K8S-HELM-003 (LOW)    — resources.limits ausente
          K8S-HELM-004 (MEDIUM) — Ingress habilitado sin TLS
        """
        _log_phase(10, "Helm charts")

        # Verificar disponibilidad de helm
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

        # Listar releases de todos los namespaces
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

            # Obtener valores del release
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

            # K8S-HELM-001: image.pullPolicy debe ser Always
            pull_policy = (valores.get("image") or {}).get("pullPolicy", "")
            if pull_policy and pull_policy != "Always":
                findings.append(Finding(
                    id="K8S-HELM-001",
                    severity="LOW",
                    category="Helm",
                    title=f"Helm release '{prefijo}': pullPolicy no es Always",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) tiene "
                        f"image.pullPolicy='{pull_policy}'. Con pullPolicy "
                        "distinto de 'Always', el clúster puede arrancar "
                        "imágenes cacheadas que no incluyan los últimos parches."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        f"image.pullPolicy={pull_policy}"
                    ),
                    remediation=(
                        "Establecer image.pullPolicy=Always en los valores:\n"
                        f"  helm upgrade {nombre} <chart> -n {namespace} "
                        "--set image.pullPolicy=Always"
                    ),
                ))

            # K8S-HELM-002: securityContext ausente
            if "securityContext" not in valores and "podSecurityContext" not in valores:
                findings.append(Finding(
                    id="K8S-HELM-002",
                    severity="MEDIUM",
                    category="Helm",
                    title=f"Helm release '{prefijo}': securityContext no configurado",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) no define "
                        "securityContext ni podSecurityContext en sus valores. "
                        "Sin este control, los pods pueden ejecutarse con "
                        "privilegios innecesarios."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "securityContext ausente"
                    ),
                    remediation=(
                        "Añadir securityContext con al menos:\n"
                        "  runAsNonRoot: true\n"
                        "  runAsUser: 1000\n"
                        "  readOnlyRootFilesystem: true"
                    ),
                ))

            # K8S-HELM-003: resources.limits ausente
            resources = valores.get("resources") or {}
            if not resources.get("limits"):
                findings.append(Finding(
                    id="K8S-HELM-003",
                    severity="LOW",
                    category="Helm",
                    title=f"Helm release '{prefijo}': resources.limits no definido",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) no define "
                        "limits de CPU/memoria. Sin límites, un contenedor puede "
                        "consumir todos los recursos del nodo (DoS interno)."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "resources.limits ausente"
                    ),
                    remediation=(
                        "Definir limits en los valores del chart:\n"
                        "  resources:\n"
                        "    limits:\n"
                        "      cpu: '500m'\n"
                        "      memory: '512Mi'"
                    ),
                ))

            # K8S-HELM-004: Ingress habilitado sin TLS
            ingress = valores.get("ingress") or {}
            if ingress.get("enabled") and not ingress.get("tls"):
                findings.append(Finding(
                    id="K8S-HELM-004",
                    severity="MEDIUM",
                    category="Helm",
                    title=f"Helm release '{prefijo}': Ingress habilitado sin TLS",
                    description=(
                        f"El release '{nombre}' (chart: {chart}) tiene "
                        "ingress.enabled=true pero ingress.tls está vacío o ausente. "
                        "El tráfico HTTP sin cifrar expone datos y credenciales."
                    ),
                    evidence=(
                        f"helm get values {nombre} -n {namespace}: "
                        "ingress.enabled=true, ingress.tls ausente"
                    ),
                    remediation=(
                        "Configurar TLS en el Ingress:\n"
                        "  ingress:\n"
                        "    tls:\n"
                        "      - hosts: ['<dominio>']\n"
                        "        secretName: '<tls-secret>'"
                    ),
                ))

    # ── Ejecución completa ─────────────────────────────────────────────────

    # ── Fase 10: Componentes del control plane CIS (v2.0) ──────────────────

    def _args_control_plane_pod(self, nombre_pod_prefix: str) -> Dict[str, str]:
        """
        Lee los argumentos de un pod estático del control plane en kube-system.
        Devuelve un dict {flag_sin_doble_guion: valor}.
        El pod se identifica por prefijo de nombre (p.ej. 'etcd', 'kube-controller-manager').
        """
        data = _kubectl(
            ["get", "pods", "-n", "kube-system",
             "--field-selector", "status.phase=Running",
             "-o", "json"],
            context=self.context,
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
        """
        Fase 10 — Checks CIS para etcd, kube-controller-manager y kube-scheduler.

        Implementa controles CIS Kubernetes Benchmark v1.9:
          · Sección 2: etcd (K8S-ETCD-001..K8S-ETCD-016)
          · Sección 1.3: kube-controller-manager (K8S-KCM-001..K8S-KCM-012)
          · Sección 1.4: kube-scheduler (K8S-KSCHED-001..K8S-KSCHED-006)
        """
        _log_phase(10, "CONTROL PLANE CIS — etcd / controller-manager / scheduler")

        # ── 2.x etcd ──────────────────────────────────────────────────────
        _log_info("etcd: leyendo argumentos del pod estático …")
        etcd_args = self._args_control_plane_pod("etcd-")

        if not etcd_args:
            _log_info("etcd: pod estático no encontrado — checks omitidos (clúster gestionado?)")
        else:
            # CIS 2.1 — --cert-file y --key-file presentes
            if not etcd_args.get("cert-file") or not etcd_args.get("key-file"):
                self._add(Finding(
                    id          = "K8S-ETCD-001",
                    title       = "CIS 2.1: etcd sin TLS de servidor configurado",
                    severity    = "CRITICAL",
                    description = (
                        "etcd no tiene --cert-file o --key-file configurados. "
                        "Sin TLS, todas las comunicaciones etcd viajan en texto claro "
                        "y cualquier proceso en la red del clúster puede interceptar "
                        "secretos, tokens y estado completo del clúster."
                    ),
                    evidence    = f"Args etcd: {etcd_args}",
                    affected    = "etcd",
                    remediation = (
                        "Configurar --cert-file=/path/to/etcd.crt y "
                        "--key-file=/path/to/etcd.key en el manifiesto estático de etcd. "
                        "Consultar: https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/"
                    ),
                    cvss       = 9.8,
                    tags       = ["etcd", "tls", "cis-2.1"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.2 — --client-cert-auth=true
            if etcd_args.get("client-cert-auth", "false") not in ("true", "1"):
                self._add(Finding(
                    id          = "K8S-ETCD-002",
                    title       = "CIS 2.2: etcd sin autenticación de cliente por certificado",
                    severity    = "CRITICAL",
                    description = (
                        "--client-cert-auth no está habilitado en etcd. "
                        "Cualquier cliente con acceso de red a etcd puede leer y escribir "
                        "el estado completo del clúster sin autenticación."
                    ),
                    evidence    = f"client-cert-auth={etcd_args.get('client-cert-auth', 'no configurado')}",
                    affected    = "etcd",
                    remediation = "Añadir --client-cert-auth=true al manifiesto estático de etcd.",
                    cvss       = 9.8,
                    tags       = ["etcd", "autenticación", "cis-2.2"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.3 — --auto-tls=false (no auto-TLS)
            if etcd_args.get("auto-tls", "false") == "true":
                self._add(Finding(
                    id          = "K8S-ETCD-003",
                    title       = "CIS 2.3: etcd con --auto-tls habilitado",
                    severity    = "HIGH",
                    description = (
                        "--auto-tls=true genera certificados auto-firmados sin validación PKI. "
                        "Los certificados auto-TLS no verifican la identidad del par; "
                        "un atacante MitM puede hacerse pasar por el servidor etcd."
                    ),
                    evidence    = "auto-tls=true en argumentos de etcd",
                    affected    = "etcd",
                    remediation = "Usar certificados firmados por una CA de confianza. Eliminar --auto-tls o setearlo a false.",
                    cvss       = 7.5,
                    tags       = ["etcd", "tls", "cis-2.3"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.4 — --peer-cert-file y --peer-key-file
            if not etcd_args.get("peer-cert-file") or not etcd_args.get("peer-key-file"):
                self._add(Finding(
                    id          = "K8S-ETCD-004",
                    title       = "CIS 2.4: etcd sin TLS en comunicación entre peers",
                    severity    = "HIGH",
                    description = (
                        "--peer-cert-file o --peer-key-file no configurados. "
                        "La comunicación entre nodos de etcd no está cifrada, "
                        "permitiendo intercepción del tráfico intra-clúster."
                    ),
                    evidence    = f"peer-cert-file={etcd_args.get('peer-cert-file', 'no configurado')}",
                    affected    = "etcd",
                    remediation = "Configurar --peer-cert-file y --peer-key-file con certificados de peer válidos.",
                    cvss       = 7.5,
                    tags       = ["etcd", "peer-tls", "cis-2.4"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.5 — --peer-client-cert-auth=true
            if etcd_args.get("peer-client-cert-auth", "false") not in ("true", "1"):
                self._add(Finding(
                    id          = "K8S-ETCD-005",
                    title       = "CIS 2.5: etcd sin autenticación mutua entre peers",
                    severity    = "HIGH",
                    description = (
                        "--peer-client-cert-auth no está habilitado. "
                        "Los peers etcd no verifican mutuamente sus certificados, "
                        "permitiendo que un nodo comprometido se una al clúster etcd."
                    ),
                    evidence    = f"peer-client-cert-auth={etcd_args.get('peer-client-cert-auth', 'no configurado')}",
                    affected    = "etcd",
                    remediation = "Añadir --peer-client-cert-auth=true al manifiesto estático de etcd.",
                    cvss       = 7.0,
                    tags       = ["etcd", "peer-auth", "cis-2.5"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.6 — --peer-auto-tls=false
            if etcd_args.get("peer-auto-tls", "false") == "true":
                self._add(Finding(
                    id          = "K8S-ETCD-006",
                    title       = "CIS 2.6: etcd con --peer-auto-tls habilitado",
                    severity    = "MEDIUM",
                    description = (
                        "--peer-auto-tls=true genera certificados peer auto-firmados. "
                        "Los peers no pueden verificar la identidad de otros miembros del clúster etcd."
                    ),
                    evidence    = "peer-auto-tls=true",
                    affected    = "etcd",
                    remediation = "Usar certificados peer firmados por CA. Eliminar --peer-auto-tls.",
                    cvss       = 5.9,
                    tags       = ["etcd", "peer-tls", "cis-2.6"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 2.7 — --trusted-ca-file presente
            if not etcd_args.get("trusted-ca-file"):
                self._add(Finding(
                    id          = "K8S-ETCD-007",
                    title       = "CIS 2.7: etcd sin --trusted-ca-file configurado",
                    severity    = "HIGH",
                    description = (
                        "--trusted-ca-file no está configurado en etcd. "
                        "Sin una CA de confianza explícita, etcd no puede verificar "
                        "los certificados de cliente de forma correcta."
                    ),
                    evidence    = "trusted-ca-file no presente en argumentos etcd",
                    affected    = "etcd",
                    remediation = "Configurar --trusted-ca-file=/path/to/ca.crt en etcd.",
                    cvss       = 6.5,
                    tags       = ["etcd", "ca", "cis-2.7"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # Extra: cifrado at-rest — busca --encryption-provider-config en API server
            api_args = self._args_control_plane_pod("kube-apiserver-")
            if api_args and not api_args.get("encryption-provider-config"):
                self._add(Finding(
                    id          = "K8S-ETCD-008",
                    title       = "Cifrado at-rest de Secrets no configurado en el API server",
                    severity    = "HIGH",
                    description = (
                        "--encryption-provider-config no está configurado en kube-apiserver. "
                        "Los Secrets de Kubernetes se almacenan en etcd en Base64 (sin cifrar). "
                        "Si etcd es comprometido, todos los Secrets quedan expuestos."
                    ),
                    evidence    = "encryption-provider-config no encontrado en args de kube-apiserver",
                    affected    = "kube-apiserver",
                    remediation = (
                        "Crear un EncryptionConfiguration y configurar "
                        "--encryption-provider-config en kube-apiserver. "
                        "Ver: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
                    ),
                    cvss       = 7.5,
                    tags       = ["etcd", "cifrado", "secretos"],
                    references = ["https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"],
                ))

        # ── 1.3.x kube-controller-manager ──────────────────────────────────
        _log_info("kube-controller-manager: leyendo argumentos del pod estático …")
        kcm_args = self._args_control_plane_pod("kube-controller-manager-")

        if not kcm_args:
            _log_info("kube-controller-manager: pod no encontrado — omitido")
        else:
            # CIS 1.3.1 — --terminated-pod-gc-threshold configurado
            if not kcm_args.get("terminated-pod-gc-threshold"):
                self._add(Finding(
                    id          = "K8S-KCM-001",
                    title       = "CIS 1.3.1: --terminated-pod-gc-threshold no configurado",
                    severity    = "LOW",
                    description = (
                        "Sin --terminated-pod-gc-threshold, los pods terminados se acumulan "
                        "indefinidamente. Esto consume recursos y puede dificultar la auditoría "
                        "forense al contaminar el historial de pods."
                    ),
                    evidence    = "terminated-pod-gc-threshold no encontrado",
                    affected    = "kube-controller-manager",
                    remediation = "Añadir --terminated-pod-gc-threshold=10 (o valor apropiado).",
                    cvss       = 3.1,
                    tags       = ["kcm", "gc", "cis-1.3.1"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.3.2 — --profiling=false
            if etcd_args.get("profiling", "true") != "false":
                kcm_profiling = kcm_args.get("profiling", "true")
                if kcm_profiling != "false":
                    self._add(Finding(
                        id          = "K8S-KCM-002",
                        title       = "CIS 1.3.2: profiling habilitado en kube-controller-manager",
                        severity    = "LOW",
                        description = (
                            "--profiling no está seteado a false. El endpoint de profiling "
                            "expone información de rendimiento e interno del proceso que "
                            "podría usarse para análisis de vulnerabilidades."
                        ),
                        evidence    = f"profiling={kcm_profiling}",
                        affected    = "kube-controller-manager",
                        remediation = "Añadir --profiling=false al kube-controller-manager.",
                        cvss       = 3.1,
                        tags       = ["kcm", "profiling", "cis-1.3.2"],
                        references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                    ))

            # CIS 1.3.3 — --use-service-account-credentials=true
            if kcm_args.get("use-service-account-credentials", "false") not in ("true", "1"):
                self._add(Finding(
                    id          = "K8S-KCM-003",
                    title       = "CIS 1.3.3: --use-service-account-credentials no habilitado",
                    severity    = "HIGH",
                    description = (
                        "El kube-controller-manager no usa credenciales individuales por "
                        "service account. Sin esta opción, todos los controllers comparten "
                        "el mismo token de alta privilegiación del controller-manager, "
                        "violando el principio de mínimo privilegio."
                    ),
                    evidence    = f"use-service-account-credentials={kcm_args.get('use-service-account-credentials', 'no configurado')}",
                    affected    = "kube-controller-manager",
                    remediation = "Añadir --use-service-account-credentials=true.",
                    cvss       = 6.5,
                    tags       = ["kcm", "rbac", "cis-1.3.3"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.3.4 — --service-account-private-key-file presente
            if not kcm_args.get("service-account-private-key-file"):
                self._add(Finding(
                    id          = "K8S-KCM-004",
                    title       = "CIS 1.3.4: --service-account-private-key-file no configurado",
                    severity    = "MEDIUM",
                    description = (
                        "No se ha configurado una clave privada explícita para firmar tokens "
                        "de service account. Sin esto, los tokens se firman con la clave "
                        "del API server, que puede no estar aislada correctamente."
                    ),
                    evidence    = "service-account-private-key-file no encontrado",
                    affected    = "kube-controller-manager",
                    remediation = "Configurar --service-account-private-key-file=/path/to/sa.key.",
                    cvss       = 5.3,
                    tags       = ["kcm", "service-account", "cis-1.3.4"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.3.5 — --root-ca-file presente
            if not kcm_args.get("root-ca-file"):
                self._add(Finding(
                    id          = "K8S-KCM-005",
                    title       = "CIS 1.3.5: --root-ca-file no configurado en controller-manager",
                    severity    = "MEDIUM",
                    description = (
                        "Sin --root-ca-file, el controller-manager no puede inyectar "
                        "la CA del clúster en los pods. Los pods no podrán verificar "
                        "el certificado del API server de forma independiente."
                    ),
                    evidence    = "root-ca-file no encontrado",
                    affected    = "kube-controller-manager",
                    remediation = "Configurar --root-ca-file=/path/to/ca.crt.",
                    cvss       = 4.3,
                    tags       = ["kcm", "ca", "cis-1.3.5"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.3.6 — RotateKubeletServerCertificate feature gate
            feature_gates = kcm_args.get("feature-gates", "")
            if "rotatekubeletservercertificate=true" not in feature_gates.lower():
                self._add(Finding(
                    id          = "K8S-KCM-006",
                    title       = "CIS 1.3.6: RotateKubeletServerCertificate no habilitado",
                    severity    = "MEDIUM",
                    description = (
                        "El feature gate RotateKubeletServerCertificate no está habilitado "
                        "en kube-controller-manager. Sin rotación automática de certificados "
                        "kubelet, los certs pueden expirar y los nodos quedar sin comunicación "
                        "con el API server, o continuar usando certs expirados si hay tolerancia."
                    ),
                    evidence    = f"feature-gates={feature_gates or 'no configurado'}",
                    affected    = "kube-controller-manager",
                    remediation = "Añadir --feature-gates=RotateKubeletServerCertificate=true.",
                    cvss       = 4.9,
                    tags       = ["kcm", "certificados", "rotación", "cis-1.3.6"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.3.7 — --bind-address=127.0.0.1
            bind_addr = kcm_args.get("bind-address", "0.0.0.0")
            if bind_addr not in ("127.0.0.1", "::1"):
                self._add(Finding(
                    id          = "K8S-KCM-007",
                    title       = "CIS 1.3.7: kube-controller-manager expone métricas en all-interfaces",
                    severity    = "LOW",
                    description = (
                        f"--bind-address={bind_addr} en kube-controller-manager. "
                        "El endpoint de métricas y healthz queda accesible en todas las "
                        "interfaces de red del nodo master, no solo en loopback."
                    ),
                    evidence    = f"bind-address={bind_addr}",
                    affected    = "kube-controller-manager",
                    remediation = "Añadir --bind-address=127.0.0.1 al kube-controller-manager.",
                    cvss       = 3.7,
                    tags       = ["kcm", "red", "cis-1.3.7"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # Extra: --secure-port > 0 (metricas en puerto seguro)
            if kcm_args.get("secure-port", "10257") == "0":
                self._add(Finding(
                    id          = "K8S-KCM-008",
                    title       = "kube-controller-manager con --secure-port=0 (HTTPS deshabilitado)",
                    severity    = "MEDIUM",
                    description = (
                        "--secure-port=0 deshabilita el endpoint HTTPS del controller-manager. "
                        "Prometheus, readiness probes y Kubernetes dashboard acceden sin TLS."
                    ),
                    evidence    = "secure-port=0",
                    affected    = "kube-controller-manager",
                    remediation = "Usar el puerto seguro por defecto 10257 (no poner --secure-port=0).",
                    cvss       = 5.3,
                    tags       = ["kcm", "tls", "seguridad"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

        # ── 1.4.x kube-scheduler ───────────────────────────────────────────
        _log_info("kube-scheduler: leyendo argumentos del pod estático …")
        sched_args = self._args_control_plane_pod("kube-scheduler-")

        if not sched_args:
            _log_info("kube-scheduler: pod no encontrado — omitido")
        else:
            # CIS 1.4.1 — --profiling=false
            sched_profiling = sched_args.get("profiling", "true")
            if sched_profiling != "false":
                self._add(Finding(
                    id          = "K8S-KSCHED-001",
                    title       = "CIS 1.4.1: profiling habilitado en kube-scheduler",
                    severity    = "LOW",
                    description = (
                        "--profiling no está seteado a false en kube-scheduler. "
                        "El endpoint de profiling expone datos de ejecución internos."
                    ),
                    evidence    = f"profiling={sched_profiling}",
                    affected    = "kube-scheduler",
                    remediation = "Añadir --profiling=false al kube-scheduler.",
                    cvss       = 3.1,
                    tags       = ["scheduler", "profiling", "cis-1.4.1"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # CIS 1.4.2 — --bind-address=127.0.0.1
            sched_bind = sched_args.get("bind-address", "0.0.0.0")
            if sched_bind not in ("127.0.0.1", "::1"):
                self._add(Finding(
                    id          = "K8S-KSCHED-002",
                    title       = "CIS 1.4.2: kube-scheduler expone métricas en all-interfaces",
                    severity    = "LOW",
                    description = (
                        f"--bind-address={sched_bind} en kube-scheduler. "
                        "El endpoint de métricas del scheduler es accesible en toda "
                        "la red del nodo master."
                    ),
                    evidence    = f"bind-address={sched_bind}",
                    affected    = "kube-scheduler",
                    remediation = "Añadir --bind-address=127.0.0.1 al kube-scheduler.",
                    cvss       = 3.7,
                    tags       = ["scheduler", "red", "cis-1.4.2"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

            # Extra: --secure-port en scheduler
            if sched_args.get("secure-port", "10259") == "0":
                self._add(Finding(
                    id          = "K8S-KSCHED-003",
                    title       = "kube-scheduler con --secure-port=0 (HTTPS deshabilitado)",
                    severity    = "MEDIUM",
                    description = (
                        "--secure-port=0 deshabilita el endpoint HTTPS del scheduler. "
                        "Las métricas de scheduling y healthcheck no están protegidas por TLS."
                    ),
                    evidence    = "secure-port=0 en kube-scheduler",
                    affected    = "kube-scheduler",
                    remediation = "No usar --secure-port=0; dejar el puerto por defecto 10259.",
                    cvss       = 5.3,
                    tags       = ["scheduler", "tls"],
                    references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                ))

        # ── 4.2.x Kubelet (lectura de args de nodos) ───────────────────────
        _log_info("kubelet: verificando configuración CIS en nodos …")
        nodos_data = _kubectl(["get", "nodes", "-o", "json"], context=self.context)
        if nodos_data:
            for nodo in nodos_data.get("items", [])[:5]:  # hasta 5 nodos
                nombre_nodo = nodo.get("metadata", {}).get("name", "desconocido")
                node_info   = nodo.get("status", {}).get("nodeInfo", {})
                node_info.get("kubeletVersion", "")

                # CIS 4.2.1 — --anonymous-auth=false
                kubelet_cfg = _kubectl(
                    ["get", "--raw", f"/api/v1/nodes/{nombre_nodo}/proxy/configz"],
                    context=self.context,
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
                            f"El kubelet del nodo '{nombre_nodo}' tiene --anonymous-auth=true "
                            "o equivalente. Cualquier petición no autenticada al kubelet "
                            "se procesa como anónima (system:anonymous), pudiendo ejecutar "
                            "pods, leer logs o hacer exec en contenedores sin credenciales."
                        ),
                        evidence    = f"anonymous.enabled={anon_auth} en /configz de {nombre_nodo}",
                        affected    = f"kubelet/{nombre_nodo}",
                        remediation = (
                            "Añadir --anonymous-auth=false en el kubelet o en KubeletConfiguration. "
                            "Habilitar --authorization-mode=Webhook para que el kubelet "
                            "valide tokens contra el API server."
                        ),
                        cvss       = 9.8,
                        tags       = ["kubelet", "autenticación", "cis-4.2.1"],
                        references = ["https://www.cisecurity.org/benchmark/kubernetes"],
                    ))
                    break  # un finding es suficiente, no spamear por nodo

    def run(self) -> int:
        """
        Ejecuta las 8 fases de auditoría y devuelve el exit code.

        Códigos de salida:
          0 — sin hallazgos CRITICAL o HIGH
          1 — al menos un hallazgo HIGH
          2 — al menos un hallazgo CRITICAL
        """
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

        # Fase 10: auditoría de Helm charts (v1.3, activa con --helm)
        if self.audit_helm:
            self._audit_helm_charts(self.findings)

        # Fase 11: Control plane CIS (v2.0, activa con --control-plane)
        if getattr(self, "audit_control_plane", False):
            self.fase10_control_plane_cis()

        return self._calcular_exit_code()

    def _calcular_exit_code(self) -> int:
        """Calcula el exit code basado en la severidad máxima encontrada."""
        tiene_critical = any(f.severity == "CRITICAL" for f in self.findings)
        tiene_high     = any(f.severity == "HIGH"     for f in self.findings)
        if tiene_critical:
            return 2
        if tiene_high:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Resumen de consola
# ---------------------------------------------------------------------------

def _imprimir_resumen(hallazgos: list) -> None:
    """Imprime el resumen final de hallazgos en consola con colores ANSI."""
    from collections import Counter

    print(f"\n{'═' * 68}")
    print(f"{ANSI_BOLD}{ANSI_CYAN}  RESUMEN DE AUDITORÍA — vamp-k8s-audit{ANSI_RESET}")
    print(f"{'═' * 68}")

    if not hallazgos:
        print(f"\n  {ANSI_GREEN}{ANSI_BOLD}No se detectaron hallazgos de seguridad.{ANSI_RESET}\n")
        return

    conteo = Counter(f.severity for f in hallazgos)
    orden  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    total  = len(hallazgos)

    for sev in orden:
        n = conteo.get(sev, 0)
        if not n:
            continue
        color = _SEV_COLOR.get(sev, ANSI_GREY)
        barra = "█" * min(n * 2, 30)
        print(f"  {color}{ANSI_BOLD}{sev:8}{ANSI_RESET}  {color}{barra}{ANSI_RESET}  {n}")

    print(f"\n  {ANSI_BOLD}Total de hallazgos: {total}{ANSI_RESET}")
    print(f"{'─' * 68}\n")


# ---------------------------------------------------------------------------
# Punto de entrada CLI
# ---------------------------------------------------------------------------

def apply_delta_scan(
    findings: "List[Finding]", delta_path: str
) -> "tuple[List[Finding], List[str], List[str], List[str]]":
    """
    Compara hallazgos actuales con un informe JSON previo (--delta FILE).
    Clave única: finding.id (e.g. K8S-001).
    Devuelve (findings, new_ids, recurring_ids, resolved_ids).
    """
    try:
        baseline_data = json.loads(Path(delta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se puede leer el delta baseline '{delta_path}': {exc}") from exc
    baseline_ids = {f["id"] for f in baseline_data.get("findings", []) if "id" in f}
    current_ids  = {f.id for f in findings}
    new_ids      = sorted(current_ids - baseline_ids)
    recurring_ids = sorted(current_ids & baseline_ids)
    resolved_ids  = sorted(baseline_ids - current_ids)
    return findings, new_ids, recurring_ids, resolved_ids


def _construir_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el parser de argumentos CLI."""
    p = argparse.ArgumentParser(
        prog        = "vamp-k8s-audit",
        description = (
            "VampSecure Labs — Kubernetes Security Auditor\n"
            "Auditor de seguridad para clústeres Kubernetes.\n"
            "© VampSecure Studios — VampSecure Labs Security Research Division"
        ),
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--context", metavar="CTX", default=None,
        help="Contexto de kubectl a usar (default: contexto activo)",
    )
    p.add_argument(
        "--namespace", "-n", metavar="NS", default=None,
        help="Limita la auditoría a un namespace específico (default: todos)",
    )
    p.add_argument(
        "--kubeconfig", metavar="PATH", default=None,
        help="Ruta al fichero kubeconfig (default: ~/.kube/config)",
    )
    p.add_argument(
        "--output", "-o", metavar="FILE", default=None,
        help="Guarda los hallazgos en formato JSON en FILE",
    )
    p.add_argument(
        "--report-html", metavar="FILE", dest="report_html", default=None,
        help="Genera informe HTML profesional VSL en FILE",
    )
    p.add_argument(
        "--client", metavar="NOMBRE", default="Confidencial",
        help="Nombre del cliente para el informe",
    )
    p.add_argument(
        "--engagement", metavar="DESC", default="",
        help="Descripción del engagement para el informe",
    )
    p.add_argument(
        "--auditor", metavar="NOMBRE",
        default="VampSecure Labs — Security Research Division",
        help="Nombre del auditor para el informe",
    )
    p.add_argument(
        "--skip-images", action="store_true", dest="skip_images",
        help="Omite el análisis de imágenes (fase 6) para ejecuciones más rápidas",
    )
    p.add_argument(
        "--skip-cve", action="store_true", dest="skip_cve",
        help="Omite la fase de CVEs activos (fase 9): runc CVE-2025-52881 y ACM CVE-2026-66786",
    )
    p.add_argument(
        "--helm", action="store_true",
        help="Auditar Helm charts desplegados en el clúster (requiere helm CLI) — v1.3",
    )
    p.add_argument(
        "--control-plane", action="store_true", dest="control_plane",
        help=(
            "Auditar componentes del control plane: etcd (CIS 2.x), "
            "kube-controller-manager (CIS 1.3.x), kube-scheduler (CIS 1.4.x) "
            "y kubelet (CIS 4.2.x) — v2.0"
        ),
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Modo detallado: muestra evidencias adicionales en consola",
    )
    p.add_argument(
        "--delta", metavar="FILE", default=None,
        help="Delta scan: comparar con un informe JSON previo (--output). "
             "Muestra hallazgos como NEW/RECURRING y lista los RESOLVED.",
    )
    p.add_argument(
        "--version", action="version",
        version=f"vamp-k8s-audit {VERSION}",
    )

    return p


def _inicializar_kubectl(args: argparse.Namespace) -> None:
    """
    Construye la lista de comandos base para kubectl con los flags globales.

    Modifica la variable global _KUBECTL_CMD con los argumentos de contexto,
    kubeconfig y namespace según los argumentos de línea de comandos.
    """
    global _KUBECTL_CMD
    cmd = ["kubectl"]
    if args.kubeconfig:
        cmd += ["--kubeconfig", args.kubeconfig]
    if args.context:
        cmd += ["--context", args.context]
    _KUBECTL_CMD = cmd


def _verificar_kubectl_disponible() -> None:
    """
    Verifica que kubectl está instalado y accesible.

    Termina el proceso con código 1 si kubectl no está disponible.
    """
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


def main() -> None:
    """Punto de entrada principal del auditor de Kubernetes."""
    global _VERBOSE

    parser = _construir_parser()
    args   = parser.parse_args()

    _VERBOSE = args.verbose
    _inicializar_kubectl(args)
    _verificar_kubectl_disponible()

    auditor = K8SAuditor(
        context              = args.context,
        namespace            = args.namespace,
        skip_images          = args.skip_images,
        skip_cve             = args.skip_cve,
        audit_helm           = args.helm,
        audit_control_plane  = args.control_plane,
    )

    exit_code = auditor.run()
    _imprimir_resumen(auditor.findings)

    # ── Delta scan (--delta) ─────────────────────────────────────────────────
    if getattr(args, "delta", None):
        try:
            _, new_ids, recurring_ids, resolved_ids = apply_delta_scan(
                auditor.findings, args.delta
            )
            print(
                f"\n  {ANSI_BOLD}DELTA vs {args.delta}:{ANSI_RESET} "
                f"{ANSI_GREEN}{len(new_ids)} NEW{ANSI_RESET} · "
                f"{len(recurring_ids)} RECURRING · "
                f"{len(resolved_ids)} RESOLVED"
            )
            if new_ids:
                print(f"  [+NEW     ] {', '.join(new_ids)}")
            if resolved_ids:
                print(f"  [-RESOLVED] {', '.join(resolved_ids)}")
        except ValueError as exc:
            print(f"  {ANSI_RED}[!] Delta error: {exc}{ANSI_RESET}")

    # ── Exportar JSON
    if args.output:
        meta = meta_from_args(
            args, tool=TOOL_NAME, version=VERSION,
        )
        # Añadir scope al meta basado en el contexto/namespace auditado
        scope_parts = []
        if args.context:
            scope_parts.append(f"contexto: {args.context}")
        if args.namespace:
            scope_parts.append(f"namespace: {args.namespace}")
        else:
            scope_parts.append("todos los namespaces")
        meta.scope = ", ".join(scope_parts) if scope_parts else "clúster completo"

        reporte = VampSecReport(meta, auditor.findings)
        reporte.to_json(args.output)
        print(
            f"  {ANSI_GREEN}✓{ANSI_RESET} Informe JSON guardado: "
            f"{ANSI_BOLD}{args.output}{ANSI_RESET}"
        )

    # ── Exportar HTML
    if args.report_html:
        meta = meta_from_args(
            args, tool=TOOL_NAME, version=VERSION,
        )
        scope_parts = []
        if args.context:
            scope_parts.append(f"contexto: {args.context}")
        if args.namespace:
            scope_parts.append(f"namespace: {args.namespace}")
        else:
            scope_parts.append("todos los namespaces")
        meta.scope = ", ".join(scope_parts) if scope_parts else "clúster completo"

        reporte = VampSecReport(meta, auditor.findings)
        reporte.to_html_client(args.report_html)
        print(
            f"  {ANSI_GREEN}✓{ANSI_RESET} Informe HTML guardado: "
            f"{ANSI_BOLD}{args.report_html}{ANSI_RESET}"
        )

    # ── Copyright y aviso legal
    print(
        f"\n  {ANSI_DIM}© VampSecure Studios — "
        f"VampSecure Labs Security Research Division{ANSI_RESET}"
    )
    print(
        f"  {ANSI_DIM}Uso exclusivo en auditorías con permiso explícito.{ANSI_RESET}\n"
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
