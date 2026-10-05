# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_k8s_audit.py.

Cubre el motor de análisis de Kubernetes sin necesitar un clúster activo:
- Detección de pods privilegiados y configuraciones inseguras de SecurityContext
- Análisis de RBAC (ClusterRole wildcard, SA con cluster-admin)
- Ausencia de NetworkPolicy
- Detección de secrets en variables de entorno de pods
- Helpers de color ANSI
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_k8s_audit import K8SAuditor, _color, _sev_badge


# ---------------------------------------------------------------------------
# Helper: construir auditor sin acceso real al clúster
# ---------------------------------------------------------------------------

def _make_auditor(**kwargs) -> K8SAuditor:
    defaults = {"context": None, "namespace": None}
    defaults.update(kwargs)
    return K8SAuditor(**defaults)


# ---------------------------------------------------------------------------
# Tests 1-2: Helpers de color ANSI
# ---------------------------------------------------------------------------

class TestHelpersColor:
    """Verifica que los helpers de consola producen salida correcta."""

    def test_color_aplica_codigo_ansi(self):
        """_color debe envolver el texto con el código ANSI y el reset."""
        resultado = _color("HOLA", "\033[91m")
        assert "\033[91m" in resultado
        assert "\033[0m" in resultado
        assert "HOLA" in resultado

    def test_sev_badge_contiene_severidad(self):
        """_sev_badge debe contener el texto de la severidad en el badge."""
        badge = _sev_badge("CRITICAL")
        assert "CRITICAL" in badge


# ---------------------------------------------------------------------------
# Tests 3-4: Pod privilegiado → CRITICAL K8S-030
# ---------------------------------------------------------------------------

class TestPodPrivilegiado:
    """Verifica detección de pods con securityContext.privileged=true."""

    def test_pod_privilegiado_genera_critical(self, pod_privilegiado_json):
        """Pod con privileged=true debe generar hallazgo K8S-030 CRITICAL."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        criticos = [
            f for f in auditor.findings
            if f.severity == "CRITICAL" and "K8S-030" in f.id
        ]
        assert criticos, "Pod privilegiado debe generar K8S-030 CRITICAL"

    def test_pod_privilegiado_evidencia_contiene_nombre(self, pod_privilegiado_json):
        """La evidencia del hallazgo debe mencionar el pod afectado."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        hallazgos = [f for f in auditor.findings if "K8S-030" in f.id]
        assert hallazgos
        assert "vuln-pod" in hallazgos[0].evidence or "vuln-pod" in hallazgos[0].affected


# ---------------------------------------------------------------------------
# Tests 5-6: hostNetwork=true → HIGH K8S-036
# ---------------------------------------------------------------------------

class TestHostNetwork:
    """Verifica detección de pods con hostNetwork=true."""

    def test_host_network_genera_high(self, pod_host_network_json):
        """Pod con hostNetwork=true debe generar hallazgo K8S-036 HIGH."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_host_network_json)
            auditor.fase3_pods()

        altos = [
            f for f in auditor.findings
            if f.severity == "HIGH" and "K8S-036" in f.id
        ]
        assert altos, "hostNetwork=true debe generar K8S-036 HIGH"

    def test_host_network_evidencia_correcto(self, pod_host_network_json):
        """La evidencia debe indicar hostNetwork=true."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_host_network_json)
            auditor.fase3_pods()

        hallazgos = [f for f in auditor.findings if "K8S-036" in f.id]
        assert hallazgos
        assert "hostNetwork" in hallazgos[0].evidence or "hostNetwork" in hallazgos[0].description


# ---------------------------------------------------------------------------
# Test 7: runAsUser=0 → HIGH K8S-031
# ---------------------------------------------------------------------------

class TestRunAsRoot:
    """Verifica detección de contenedores que corren como UID 0."""

    def test_run_as_root_genera_high(self, pod_privilegiado_json):
        """runAsUser=0 explícito debe generar K8S-031 HIGH."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        root_findings = [
            f for f in auditor.findings
            if f.severity == "HIGH" and "K8S-031" in f.id
        ]
        assert root_findings, "runAsUser=0 debe generar K8S-031 HIGH"


# ---------------------------------------------------------------------------
# Test 8: allowPrivilegeEscalation=true → HIGH K8S-032
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    """Verifica detección de contenedores con allowPrivilegeEscalation=true."""

    def test_allow_escalation_true_genera_high(self, pod_privilegiado_json):
        """allowPrivilegeEscalation=true explícito genera K8S-032 HIGH."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        esc_findings = [
            f for f in auditor.findings
            if f.severity == "HIGH" and "K8S-032" in f.id
        ]
        assert esc_findings, "allowPrivilegeEscalation=true debe generar K8S-032 HIGH"


# ---------------------------------------------------------------------------
# Tests 9-10: ClusterRole wildcard → CRITICAL K8S-011
# ---------------------------------------------------------------------------

class TestClusterRoleWildcard:
    """Verifica detección de ClusterRole con verbos y recursos wildcard."""

    def test_clusterrole_wildcard_genera_critical(self, clusterrole_wildcard_json):
        """ClusterRole con verbs=['*'] y resources=['*'] genera K8S-011 CRITICAL."""
        auditor = _make_auditor()

        def mock_kubectl(args):
            if "clusterrolebindings" in args:
                return {"items": []}
            if "clusterroles" in args:
                return json.loads(clusterrole_wildcard_json)
            if "rolebindings" in args:
                return {"items": []}
            if "serviceaccounts" in args:
                return {"items": []}
            return None

        with patch("vamp_k8s_audit._kubectl", side_effect=mock_kubectl):
            with patch("vamp_k8s_audit._kubectl_raw", return_value=""):
                auditor.fase2_rbac()

        criticos = [
            f for f in auditor.findings
            if f.severity == "CRITICAL" and "K8S-011" in f.id
        ]
        assert criticos, "ClusterRole wildcard debe generar K8S-011 CRITICAL"

    def test_clusterrole_wildcard_nombre_en_evidencia(self, clusterrole_wildcard_json):
        """El nombre del ClusterRole peligroso debe aparecer en la evidencia."""
        auditor = _make_auditor()

        def mock_kubectl(args):
            if "clusterroles" in args:
                return json.loads(clusterrole_wildcard_json)
            return {"items": []}

        with patch("vamp_k8s_audit._kubectl", side_effect=mock_kubectl):
            with patch("vamp_k8s_audit._kubectl_raw", return_value=""):
                auditor.fase2_rbac()

        hallazgos = [f for f in auditor.findings if "K8S-011" in f.id]
        if hallazgos:
            evidencia = hallazgos[0].evidence
            assert "peligroso-role" in evidencia


# ---------------------------------------------------------------------------
# Test 11: SA default con cluster-admin → CRITICAL K8S-010
# ---------------------------------------------------------------------------

class TestSACLusterAdmin:
    """Verifica detección de ServiceAccount con rol cluster-admin."""

    def test_sa_cluster_admin_genera_critical(self, clusterrolebinding_cluster_admin_json):
        """SA con ClusterRoleBinding a cluster-admin genera K8S-010 CRITICAL."""
        auditor = _make_auditor()

        def mock_kubectl(args):
            if "clusterrolebindings" in args:
                return json.loads(clusterrolebinding_cluster_admin_json)
            if "clusterroles" in args:
                return {"items": []}
            if "rolebindings" in args:
                return {"items": []}
            if "serviceaccounts" in args:
                return {"items": []}
            return None

        with patch("vamp_k8s_audit._kubectl", side_effect=mock_kubectl):
            with patch("vamp_k8s_audit._kubectl_raw", return_value=""):
                auditor.fase2_rbac()

        criticos = [
            f for f in auditor.findings
            if f.severity == "CRITICAL" and "K8S-010" in f.id
        ]
        assert criticos, "SA con cluster-admin debe generar K8S-010 CRITICAL"


# ---------------------------------------------------------------------------
# Test 12: Namespace sin NetworkPolicy → HIGH K8S-061
# ---------------------------------------------------------------------------

class TestNetworkPolicyAusente:
    """Verifica que la ausencia de NetworkPolicy en un namespace genera HIGH."""

    def test_sin_network_policy_genera_high(
        self, pod_host_network_json, networkpolicy_vacia_json
    ):
        """Namespace con pods pero sin NetworkPolicy genera K8S-061 HIGH."""
        auditor = _make_auditor()

        pods_data = json.loads(pod_host_network_json)
        np_data   = json.loads(networkpolicy_vacia_json)

        def mock_kubectl(args):
            if "networkpolicies" in args:
                return np_data
            if "pods" in args:
                return pods_data
            if "services" in args:
                return {"items": []}
            if "ingresses" in args:
                return {"items": []}
            return None

        with patch("vamp_k8s_audit._kubectl", side_effect=mock_kubectl):
            with patch("vamp_k8s_audit.K8SAuditor._check_etcd_expuesto"):
                auditor._server_url = ""
                auditor.fase4_red()

        np_findings = [
            f for f in auditor.findings
            if f.severity == "HIGH" and "K8S-061" in f.id
        ]
        assert np_findings, "Namespace sin NetworkPolicy debe generar K8S-061 HIGH"


# ---------------------------------------------------------------------------
# Test 13: Pod sin límites de recursos → LOW K8S-038
# ---------------------------------------------------------------------------

class TestSinLimitesRecursos:
    """Verifica que pods sin resource limits generan K8S-038 LOW."""

    def test_pod_sin_limits_genera_low(self, pod_privilegiado_json):
        """Pod sin resource.limits debe generar K8S-038 LOW."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        lows = [f for f in auditor.findings if "K8S-038" in f.id]
        assert lows, "Pod sin resource.limits debe generar K8S-038 LOW"


# ---------------------------------------------------------------------------
# Test 14: Lista de findings ordenada por severidad
# ---------------------------------------------------------------------------

class TestOrdenFindigns:
    """Verifica que los findings se acumulan correctamente en la lista."""

    def test_findings_se_acumulan_en_lista(self, pod_privilegiado_json):
        """Después de fase3_pods, la lista findings debe tener al menos un elemento."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        assert len(auditor.findings) > 0, "Debe haber hallazgos tras analizar pod inseguro"

    def test_findings_tienen_id_no_vacio(self, pod_privilegiado_json):
        """Cada finding debe tener un ID no vacío."""
        auditor = _make_auditor()

        with patch("vamp_k8s_audit._kubectl") as mock_kubectl:
            mock_kubectl.return_value = json.loads(pod_privilegiado_json)
            auditor.fase3_pods()

        for f in auditor.findings:
            assert f.id, f"Finding sin ID detectado: {f}"
