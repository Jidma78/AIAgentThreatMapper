"""Exécute toutes les règles enregistrées sur le modèle de menace et collecte les Findings résultants."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ThreatModel
from agent_threat_mapper.rules.base import Finding
from agent_threat_mapper.rules.registry import REGISTERED_RULES


def run_rules(threat_model: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """Exécute toutes les règles enregistrées et retourne les Findings dédupliqués.

    Pure, sans I/O. La déduplication se fait par (rule_id, ensemble des affected_resources) :
    deux règles ne produiront jamais deux findings identiques pour la même ressource."""
    findings: list[Finding] = []
    for rule in REGISTERED_RULES:
        findings.extend(rule(threat_model, intent))
    return _deduplicate(findings)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, tuple(sorted(f.affected_resources)))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
