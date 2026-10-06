# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Capa de informe.
Re-exporta Finding, VampSecReport y meta_from_args desde vampsec_report
para que el resto del paquete pueda importar desde aquí sin acoplarse
directamente a la dependencia externa.
"""
from __future__ import annotations

import json
from pathlib import Path

from vampsec_report import (
    Finding,
    VampSecReport,
    meta_from_args,
)

__all__ = ["Finding", "VampSecReport", "meta_from_args"]
