# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Punto de entrada CLI: parser, resumen y main().
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import vamp_k8s_audit._core as _core

from ._models import (
    VERSION, TOOL_NAME,
    ANSI_RESET, ANSI_BOLD, ANSI_RED, ANSI_ORANGE, ANSI_YELLOW,
    ANSI_BLUE, ANSI_CYAN, ANSI_GREEN, ANSI_GREY, ANSI_DIM, ANSI_WHITE,
    _SEV_COLOR, _color, _sev_badge,
)
from ._core import (
    K8SAuditor, apply_delta_scan,
    _log_info, _log_warn,
    _inicializar_kubectl, _verificar_kubectl_disponible,
)
from ._report import VampSecReport, meta_from_args


# ---------------------------------------------------------------------------
# Resumen final de hallazgos
# ---------------------------------------------------------------------------

def _imprimir_resumen(hallazgos: list) -> None:
    conteo = Counter(f.severity for f in hallazgos)
    print(f"\n{'─' * 70}")
    print(f"{ANSI_BOLD}{ANSI_WHITE}  RESUMEN DE HALLAZGOS{ANSI_RESET}")
    print(f"{'─' * 70}")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = conteo.get(sev, 0)
        if n > 0:
            color = _SEV_COLOR.get(sev, ANSI_GREY)
            print(f"  {_color(f'{sev:8}', color + ANSI_BOLD)}  {n:>3} hallazgo(s)")

    total = len(hallazgos)
    print(f"{'─' * 70}")
    print(f"  {ANSI_BOLD}TOTAL{ANSI_RESET}         {total:>3} hallazgo(s)\n")


# ---------------------------------------------------------------------------
# Parser de argumentos
# ---------------------------------------------------------------------------

def _construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "vamp-k8s-audit",
        description = (
            "Auditor de seguridad para clústeres Kubernetes — VampSecure Labs"
        ),
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = (
            "Ejemplos:\n"
            "  vamp-k8s-audit\n"
            "  vamp-k8s-audit --context micluster --namespace produccion\n"
            "  vamp-k8s-audit --output informe.json --format json\n"
            "  vamp-k8s-audit --audit-helm --audit-control-plane\n"
            "  vamp-k8s-audit --delta baseline.json --output delta.json\n"
        ),
    )

    p.add_argument(
        "--context", default=None,
        help="Contexto de kubectl a usar (por defecto: contexto activo)",
    )
    p.add_argument(
        "--namespace", "-n", default=None,
        help="Analizar solo este namespace (por defecto: todos)",
    )
    p.add_argument(
        "--output", "-o", default=None,
        help="Guardar informe en este fichero",
    )
    p.add_argument(
        "--format", "-f", default="json",
        choices=["json", "html", "markdown", "pdf"],
        help="Formato del informe de salida (por defecto: json)",
    )
    p.add_argument(
        "--skip-images", action="store_true",
        help="Omitir análisis de imágenes de contenedor (fase 6)",
    )
    p.add_argument(
        "--skip-cve", action="store_true",
        help="Omitir verificación de CVEs activos (fase 9)",
    )
    p.add_argument(
        "--audit-helm", action="store_true",
        help="Incluir auditoría de valores de Helm charts",
    )
    p.add_argument(
        "--audit-control-plane", action="store_true",
        help="Incluir checks CIS del control plane (etcd, kcm, scheduler, kubelet)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Salida detallada (incluye evidencias en consola)",
    )
    p.add_argument(
        "--kubeconfig", default=None,
        help="Ruta al fichero kubeconfig (por defecto: ~/.kube/config)",
    )
    p.add_argument(
        "--delta", default=None, metavar="FILE",
        help="Comparar con informe previo en FILE y mostrar nuevos/resueltos hallazgos",
    )
    p.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {VERSION}",
    )
    return p


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _construir_parser()
    args   = parser.parse_args()

    # Propagamos el flag verbose al módulo _core (variable de módulo)
    _core._VERBOSE = args.verbose

    _inicializar_kubectl(args)
    _verificar_kubectl_disponible()

    auditor = K8SAuditor(
        context             = args.context,
        namespace           = args.namespace,
        skip_images         = args.skip_images,
        skip_cve            = args.skip_cve,
        audit_helm          = args.audit_helm,
        audit_control_plane = args.audit_control_plane,
    )

    exit_code = auditor.run()
    hallazgos = auditor.findings

    # ── Delta scan ────────────────────────────────────────────────────────
    new_ids: list      = []
    recurring_ids: list = []
    resolved_ids: list  = []

    if args.delta:
        try:
            hallazgos, new_ids, recurring_ids, resolved_ids = apply_delta_scan(
                hallazgos, args.delta
            )
            print(f"\n{ANSI_BOLD}{ANSI_CYAN}DELTA SCAN (vs {args.delta}){ANSI_RESET}")
            print(f"  {ANSI_GREEN}Nuevos:    {len(new_ids)}{ANSI_RESET}   {sorted(new_ids)[:8]}")
            print(f"  {ANSI_YELLOW}Recurrentes: {len(recurring_ids)}{ANSI_RESET}")
            print(f"  {ANSI_DIM}Resueltos: {len(resolved_ids)}{ANSI_RESET}   {sorted(resolved_ids)[:8]}")
        except ValueError as exc:
            print(f"{ANSI_RED}[DELTA ERROR]{ANSI_RESET} {exc}", file=sys.stderr)

    # ── Resumen ───────────────────────────────────────────────────────────
    _imprimir_resumen(hallazgos)

    # ── Informe a fichero ─────────────────────────────────────────────────
    if args.output:
        try:
            meta = meta_from_args(args)
            report = VampSecReport(
                meta     = meta,
                findings = hallazgos,
            )
            report_path = Path(args.output)
            if args.format == "json":
                report.save_json(report_path)
            elif args.format == "html":
                report.save_html(report_path)
            elif args.format == "markdown":
                report.save_markdown(report_path)
            elif args.format == "pdf":
                report.save_pdf(report_path)
            print(f"  {ANSI_GREEN}✓{ANSI_RESET} Informe guardado en: {args.output}")
        except Exception as exc:
            print(
                f"{ANSI_RED}[INFORME ERROR]{ANSI_RESET} No se pudo generar el informe: {exc}",
                file=sys.stderr,
            )

    sys.exit(exit_code)
