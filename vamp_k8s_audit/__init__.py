# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_k8s_audit — Kubernetes Security Auditor
Re-exporta todos los símbolos públicos para mantener compatibilidad
con código y tests que importan desde el paquete directamente.
"""
from __future__ import annotations

from ._models import (
    VERSION,
    TOOL_NAME,
    BANNER,
    _color,
    _sev_badge,
    ANSI_RESET,
    ANSI_BOLD,
    ANSI_RED,
    ANSI_ORANGE,
    ANSI_YELLOW,
    ANSI_BLUE,
    ANSI_CYAN,
    ANSI_GREEN,
    ANSI_GREY,
    ANSI_DIM,
    ANSI_WHITE,
    _SEV_COLOR,
)
from ._core import (
    K8SAuditor,
    apply_delta_scan,
    _kubectl,
    _kubectl_raw,
    _KUBECTL_CMD,
    _VERBOSE,
    _log_info,
    _log_warn,
    _log_phase,
    _log_finding,
    _log_clean,
    _inicializar_kubectl,
    _verificar_kubectl_disponible,
)
from ._report import Finding, VampSecReport, meta_from_args
from .cli import main, _construir_parser, _imprimir_resumen

__all__ = [
    "VERSION", "TOOL_NAME", "BANNER",
    "_color", "_sev_badge",
    "ANSI_RESET", "ANSI_BOLD", "ANSI_RED", "ANSI_ORANGE", "ANSI_YELLOW",
    "ANSI_BLUE", "ANSI_CYAN", "ANSI_GREEN", "ANSI_GREY", "ANSI_DIM",
    "ANSI_WHITE", "_SEV_COLOR",
    "K8SAuditor", "apply_delta_scan",
    "_kubectl", "_kubectl_raw", "_KUBECTL_CMD", "_VERBOSE",
    "_log_info", "_log_warn", "_log_phase", "_log_finding", "_log_clean",
    "_inicializar_kubectl", "_verificar_kubectl_disponible",
    "Finding", "VampSecReport", "meta_from_args",
    "main", "_construir_parser", "_imprimir_resumen",
]
