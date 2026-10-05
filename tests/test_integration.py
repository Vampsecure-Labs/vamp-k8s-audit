# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_k8s_audit.py.

Verifica flujos end-to-end con subprocess mockeado que simula respuestas
de kubectl. No requiere un clúster Kubernetes activo.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).parent.parent))

import vamp_k8s_audit as k8s
from vamp_k8s_audit import K8SAuditor, _kubectl, _kubectl_raw


# ---------------------------------------------------------------------------
# Helper: mock de subprocess.run para kubectl
# ---------------------------------------------------------------------------

def _mock_kubectl_run(output: str, returncode: int = 0):
    """Crea un mock de subprocess.run que devuelve la salida dada."""
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = output
    mock.stderr = ""
    return mock


# ---------------------------------------------------------------------------
# Test integración 1: _kubectl parsea JSON correctamente
# ---------------------------------------------------------------------------

class TestKubectlHelper:
    """Verifica que _kubectl parsea la salida JSON de kubectl correctamente."""

    def test_kubectl_parsea_json_valido(self):
        """_kubectl debe retornar un dict cuando la salida es JSON válido."""
        datos = {"items": [{"metadata": {"name": "test"}}]}
        mock_result = _mock_kubectl_run(json.dumps(datos))

        with patch("subprocess.run", return_value=mock_result):
            k8s._KUBECTL_CMD = ["kubectl"]
            resultado = _kubectl(["get", "pods", "-o", "json"])

        assert resultado is not None
        assert "items" in resultado

    def test_kubectl_retorna_none_en_error(self):
        """_kubectl debe retornar None cuando kubectl falla (returncode != 0)."""
        mock_result = _mock_kubectl_run("", returncode=1)
        mock_result.stderr = "Error from server: NotFound"

        with patch("subprocess.run", return_value=mock_result):
            k8s._KUBECTL_CMD = ["kubectl"]
            resultado = _kubectl(["get", "pods", "-o", "json"])

        assert resultado is None

    def test_kubectl_retorna_none_en_json_invalido(self):
        """_kubectl retorna None si la salida no es JSON."""
        mock_result = _mock_kubectl_run("No resources found.")

        with patch("subprocess.run", return_value=mock_result):
            k8s._KUBECTL_CMD = ["kubectl"]
            resultado = _kubectl(["get", "pods", "-o", "json"])

        assert resultado is None


# ---------------------------------------------------------------------------
# Test integración 2: fase3_pods con pod privilegiado mockeado completo
# ---------------------------------------------------------------------------

class TestFase3ConSubprocessMock:
    """Verifica fase3_pods con subprocess.run completamente mockeado."""

    def test_fase3_detecta_critical_con_pod_privilegiado(self):
        """fase3_pods detecta CRITICAL al procesar pod privilegiado desde subprocess."""
        pod_data = {
            "items": [{
                "metadata": {"name": "evil-pod", "namespace": "default"},
                "spec": {
                    "hostNetwork": False, "hostPID": False, "hostIPC": False,
                    "containers": [{
                        "name": "app",
                        "image": "evil:latest",
                        "securityContext": {
                            "privileged": True,
                            "allowPrivilegeEscalation": True,
                            "runAsUser": 0,
                        },
                        "resources": {},
                    }],
                    "volumes": [],
                }
            }]
        }

        mock_result = _mock_kubectl_run(json.dumps(pod_data))

        with patch("subprocess.run", return_value=mock_result):
            k8s._KUBECTL_CMD = ["kubectl"]
            auditor = K8SAuditor(context=None, namespace=None)
            auditor.fase3_pods()

        criticos = [f for f in auditor.findings if f.severity == "CRITICAL"]
        assert criticos, "fase3_pods debe detectar CRITICAL en pod privilegiado"


# ---------------------------------------------------------------------------
# Test integración 3: fase2_rbac con CRB wildcard mockeado
# ---------------------------------------------------------------------------

class TestFase2ConSubprocessMock:
    """Verifica fase2_rbac detecta wildcard ClusterRole con subprocess mockeado."""

    def test_fase2_detecta_wildcard_clusterrole(self):
        """fase2_rbac con ClusterRole wildcard mockeado genera CRITICAL."""
        crb_data = json.dumps({"items": []})
        cr_data  = json.dumps({
            "items": [{
                "metadata": {"name": "super-admin-role"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            }]
        })
        rb_data  = json.dumps({"items": []})
        sa_data  = json.dumps({"items": []})

        def side_effect(cmd, **kwargs):
            output = ""
            if "clusterrolebindings" in cmd and "clusterroles" not in cmd:
                output = crb_data
            elif "clusterroles" in cmd:
                output = cr_data
            elif "rolebindings" in cmd:
                output = rb_data
            elif "serviceaccounts" in cmd:
                output = sa_data
            elif "auth" in cmd:
                output = ""
            return _mock_kubectl_run(output)

        with patch("subprocess.run", side_effect=side_effect):
            k8s._KUBECTL_CMD = ["kubectl"]
            auditor = K8SAuditor(context=None, namespace=None)
            auditor.fase2_rbac()

        criticos = [f for f in auditor.findings if f.severity == "CRITICAL"]
        assert criticos, "fase2_rbac debe detectar CRITICAL con ClusterRole wildcard"


# ---------------------------------------------------------------------------
# Test integración 4: fase5_secretos detecta literal de credencial en pod
# ---------------------------------------------------------------------------

class TestFase5Secretos:
    """Verifica detección de credenciales literales en variables de entorno de pods."""

    def test_detecta_credencial_literal_en_env(self):
        """Env con var PASSWORD y valor literal genera hallazgo HIGH K8S-080."""
        pods_data = json.dumps({
            "items": [{
                "metadata": {"name": "db-pod", "namespace": "default"},
                "spec": {
                    "containers": [{
                        "name": "db",
                        "image": "postgres:15",
                        "env": [
                            {"name": "POSTGRES_PASSWORD", "value": "supersecretpassword"},
                        ],
                    }]
                }
            }]
        })

        def side_effect(cmd, **kwargs):
            if "pods" in cmd:
                return _mock_kubectl_run(pods_data)
            if "configmaps" in cmd:
                return _mock_kubectl_run(json.dumps({"items": []}))
            if "secrets" in cmd:
                return _mock_kubectl_run(json.dumps({"items": []}))
            return _mock_kubectl_run("")

        with patch("subprocess.run", side_effect=side_effect):
            k8s._KUBECTL_CMD = ["kubectl"]
            auditor = K8SAuditor(context=None, namespace=None)
            auditor.fase5_secretos()

        secretos = [
            f for f in auditor.findings
            if f.severity == "HIGH" and "K8S-080" in f.id
        ]
        assert secretos, "Credencial literal en env debe generar K8S-080 HIGH"


# ---------------------------------------------------------------------------
# Test integración 5: _kubectl_raw retorna texto plano
# ---------------------------------------------------------------------------

class TestKubectlRaw:
    """Verifica que _kubectl_raw retorna stdout como string plano."""

    def test_kubectl_raw_retorna_texto(self):
        """_kubectl_raw debe retornar el stdout como cadena de texto."""
        mock_result = _mock_kubectl_run("v1.27.3")

        with patch("subprocess.run", return_value=mock_result):
            k8s._KUBECTL_CMD = ["kubectl"]
            resultado = _kubectl_raw(["version", "--short"])

        assert isinstance(resultado, str)
        assert "v1.27.3" in resultado

    def test_kubectl_raw_retorna_vacio_en_error(self):
        """_kubectl_raw retorna cadena vacía ante FileNotFoundError."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            k8s._KUBECTL_CMD = ["kubectl"]
            resultado = _kubectl_raw(["version"])

        assert resultado == ""
