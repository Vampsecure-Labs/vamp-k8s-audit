# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para la suite de test de vamp-k8s-audit.
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def kubectl_available() -> bool:
    """Comprueba si el binario kubectl está disponible en el PATH."""
    return shutil.which("kubectl") is not None


# ---------------------------------------------------------------------------
# Fixtures de respuestas kubectl simuladas
# ---------------------------------------------------------------------------

@pytest.fixture
def pod_privilegiado_json() -> str:
    """JSON de respuesta kubectl get pods con un contenedor privilegiado."""
    return json.dumps({
        "items": [{
            "metadata": {"name": "vuln-pod", "namespace": "default"},
            "spec": {
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
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
    })


@pytest.fixture
def pod_host_network_json() -> str:
    """JSON de respuesta kubectl con pod que usa hostNetwork=true."""
    return json.dumps({
        "items": [{
            "metadata": {"name": "hostnet-pod", "namespace": "production"},
            "spec": {
                "hostNetwork": True,
                "hostPID": False,
                "hostIPC": False,
                "containers": [{
                    "name": "proxy",
                    "image": "haproxy:2.8",
                    "securityContext": {"runAsUser": 1000},
                    "resources": {},
                }],
                "volumes": [],
            }
        }]
    })


@pytest.fixture
def pod_automount_token_json() -> str:
    """JSON de pods donde automountServiceAccountToken no está en False."""
    return json.dumps({
        "items": [{
            "metadata": {"name": "sa-pod", "namespace": "default"},
            "spec": {
                "automountServiceAccountToken": True,
                "hostNetwork": False, "hostPID": False, "hostIPC": False,
                "containers": [{
                    "name": "worker",
                    "image": "python:3.11",
                    "securityContext": {"runAsUser": 500},
                    "resources": {"limits": {"cpu": "100m"}},
                }],
                "volumes": [],
            }
        }]
    })


@pytest.fixture
def clusterrole_wildcard_json() -> str:
    """JSON de ClusterRole con verbos y recursos wildcard."""
    return json.dumps({
        "items": [{
            "metadata": {"name": "peligroso-role"},
            "rules": [{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"],
            }]
        }]
    })


@pytest.fixture
def clusterrolebinding_cluster_admin_json() -> str:
    """JSON de ClusterRoleBinding asignando cluster-admin a una SA."""
    return json.dumps({
        "items": [{
            "metadata": {"name": "risky-binding"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": "monitoring",
            }]
        }]
    })


@pytest.fixture
def pods_vacio_json() -> str:
    """Respuesta kubectl con lista de pods vacía."""
    return json.dumps({"items": []})


@pytest.fixture
def networkpolicy_vacia_json() -> str:
    """Respuesta kubectl sin NetworkPolicies definidas."""
    return json.dumps({"items": []})
