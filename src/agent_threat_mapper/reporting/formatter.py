"""Transforme la liste de Findings en données structurées prêtes pour le rendu du rapport.

STAGE 5 ENTIÈREMENT DÉTERMINISTE : aucun appel à un LLM, aucune dépendance réseau, aucune clé API.
Le rapport est produit uniquement par le template Jinja2 à partir des findings et du threat model.
(Un enrichissement LLM optionnel pourra venir dans une étape ultérieure séparée — pas ici.)
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ThreatModel
from agent_threat_mapper.rules.base import Finding, Severity

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "report.md.j2"

# Ordre de tri (croissant = sévérité décroissante dans le rapport).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 **[CRITICAL]**",
    Severity.HIGH: "🟠 **[HIGH]**",
    Severity.MEDIUM: "🟡 **[MEDIUM]**",
    Severity.LOW: "🔵 **[LOW]**",
    Severity.INFO: "⚪ **[INFO]**",
}

# Findings où les permissions réelles contredisent l'intention déclarée — le cœur de l'outil.
_MISMATCH_RULE_IDS = {"ATM-IDENTITY-002", "ATM-KEYVAULT-004", "ATM-STORAGE-004"}

# Règles de type chemin d'attaque → origine non fiable attendue du chemin.
_PATH_RULES = {"ATM-LLM-001": "user", "ATM-LLM-002": "rag"}
_B5 = "B5"


def _attack_paths_for(finding: Finding, threat_model: ThreatModel, rid_to_node: dict[str, str]) -> list[str]:
    """Chemins d'attaque concrets pour les findings LLM-001/LLM-002, extraits du threat model."""
    origin = _PATH_RULES.get(finding.rule_id)
    if origin is None:
        return []
    rendered: list[str] = []
    for resource_id in finding.affected_resources:
        node_id = rid_to_node.get(resource_id)
        if node_id is None:
            continue
        for path in threat_model.paths_from_untrusted_to(node_id):
            if path.origin.id != origin:
                continue
            if _B5 not in {b.id for b in path.crossed_boundaries}:
                continue
            chain = " → ".join(n.id for n in path.nodes)
            boundaries = ", ".join(b.id for b in path.crossed_boundaries)
            line = f"{chain}  (boundaries: {boundaries})"
            vector = path.lateral_vector_label()
            if vector:
                line += f"  [lateral: {vector}]"
            rendered.append(line)
    return rendered


def _finding_view(finding: Finding, threat_model: ThreatModel, rid_to_node: dict[str, str]) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.name,
        "severity_badge": _SEVERITY_BADGE[finding.severity],
        "category": finding.category,
        "explanation": finding.explanation,
        "mitigation": finding.mitigation,
        "owasp_ref": finding.owasp_ref,
        "affected_resources": list(finding.affected_resources),
        "attack_paths": _attack_paths_for(finding, threat_model, rid_to_node),
    }


def _summary_sentence(high_count: int, total: int) -> str:
    """Phrase de synthèse déterministe (condition simple sur les comptes)."""
    if high_count > 0:
        plural = "s" if high_count > 1 else ""
        return (
            f"This agent has {high_count} high-severity finding{plural} requiring immediate remediation."
        )
    if total > 0:
        return "No high-severity findings; review the items below for hardening opportunities."
    return "No findings detected — the agent's permissions align with its declared intent."


def build_report_data(
    findings: list[Finding],
    threat_model: ThreatModel,
    intent: AgentIntent,
    generated_at: Optional[str] = None,
) -> dict:
    """Prépare toutes les données du rapport (tri, comptes, mismatch, chemins). Sans rendu."""
    rid_to_node = {
        node.resource_ref.resource_id: node.id
        for node in threat_model.resource_nodes()
        if node.resource_ref is not None
    }

    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])
    views = [_finding_view(f, threat_model, rid_to_node) for f in ordered]

    severity_counts = {sev.name: 0 for sev in Severity}
    for f in findings:
        severity_counts[f.severity.name] += 1

    high_count = severity_counts["CRITICAL"] + severity_counts["HIGH"]

    return {
        "agent_name": intent.name,
        "autonomy_level": intent.autonomy_level.value,
        "generated_at": generated_at or date.today().isoformat(),
        "total": len(findings),
        "severity_counts": severity_counts,
        "summary_sentence": _summary_sentence(high_count, len(findings)),
        "capability_mismatch": [v for v in views if v["rule_id"] in _MISMATCH_RULE_IDS],
        "findings": views,
        "boundaries": [
            {"id": b.id, "name": b.name, "description": b.description}
            for b in threat_model.boundaries
        ],
    }


def generate_report(
    findings: list[Finding],
    threat_model: ThreatModel,
    intent: AgentIntent,
    generated_at: Optional[str] = None,
) -> str:
    """Retourne le rapport Markdown complet. Pure : ne lit que le template bundlé, n'écrit rien."""
    data = build_report_data(findings, threat_model, intent, generated_at)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=False,  # sortie Markdown, pas HTML
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(_TEMPLATE_NAME).render(**data)
