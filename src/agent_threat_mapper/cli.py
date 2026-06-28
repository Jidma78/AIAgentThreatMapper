"""Point d'entrée de la CLI : sous-commandes export et report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_threat_mapper.azure_export.exporter import export_agent_context
from agent_threat_mapper.normalization.context_parser import parse_context
from agent_threat_mapper.normalization.intent_parser import parse_intent
from agent_threat_mapper.reporting.formatter import generate_report
from agent_threat_mapper.rules.engine import run_rules
from agent_threat_mapper.threat_model.builder import build_threat_model


def main() -> None:
    """Point d'entrée de la commande `atm`."""
    parser = argparse.ArgumentParser(
        prog="atm",
        description="Agent Threat Mapper — analyse la posture de sécurité d'un agent IA Azure.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sous-commande : export
    export_parser = subparsers.add_parser(
        "export",
        help="Exporte le contexte Azure d'une identité managée vers agent_context.json.",
    )
    export_parser.add_argument(
        "--identity",
        required=True,
        metavar="RESOURCE_ID",
        help=(
            "Resource ID complet de l'identité managée (user-assigned). "
            "Ex: /subscriptions/{sub}/resourceGroups/{rg}"
            "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"
        ),
    )
    export_parser.add_argument(
        "--output",
        default="agent_context.json",
        metavar="FILE",
        help="Chemin du fichier de sortie (défaut : agent_context.json).",
    )

    # Sous-commande : report
    report_parser = subparsers.add_parser(
        "report",
        help="Analyse un contexte + un rôle métier et génère un rapport Markdown.",
    )
    report_parser.add_argument(
        "--context",
        default="agent_context.json",
        metavar="FILE",
        help="Chemin du contexte Azure exporté (défaut : agent_context.json).",
    )
    report_parser.add_argument(
        "--role",
        default="agent_role.txt",
        metavar="FILE",
        help="Chemin du fichier de rôle métier de l'agent (défaut : agent_role.txt).",
    )
    report_parser.add_argument(
        "--output",
        default="report.md",
        metavar="FILE",
        help="Chemin du rapport Markdown (défaut : report.md).",
    )

    args = parser.parse_args()

    if args.command == "export":
        try:
            output_path = Path(args.output)
            export_agent_context(args.identity, output_path)
            print(f"Exporté vers {output_path}")
        except (ValueError, RuntimeError) as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "report":
        try:
            context = parse_context(Path(args.context))
            intent = parse_intent(Path(args.role))
            threat_model = build_threat_model(context, intent)
            findings = run_rules(threat_model, intent)
            markdown = generate_report(findings, threat_model, intent)
            output_path = Path(args.output)
            output_path.write_text(markdown, encoding="utf-8")
            print(f"Rapport généré : {output_path} ({len(findings)} finding(s))")
        except FileNotFoundError as exc:
            print(f"Erreur : fichier introuvable — {exc}", file=sys.stderr)
            sys.exit(1)
        except (ValueError, RuntimeError) as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            sys.exit(1)
