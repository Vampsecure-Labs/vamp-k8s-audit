# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, metadatos y helpers de presentación.
Sin I/O: módulo seguro para importación desde cualquier capa.
"""
from __future__ import annotations

from typing import Dict

# ---------------------------------------------------------------------------
# Metadatos
# ---------------------------------------------------------------------------

VERSION   = "2.2.0"
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
  vamp-k8s-audit v2.2.0 · Kubernetes Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""
