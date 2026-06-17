"""Point d'entrée de la CLI : sous-commandes export, analyze et report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_threat_mapper.azure_export.exporter import export_agent_context


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

    args = parser.parse_args()

    if args.command == "export":
        try:
            output_path = Path(args.output)
            export_agent_context(args.identity, output_path)
            print(f"Exporté vers {output_path}")
        except ValueError as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            sys.exit(1)
