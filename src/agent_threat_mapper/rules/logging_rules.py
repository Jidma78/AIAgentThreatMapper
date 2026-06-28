"""Règles sur l'absence ou l'insuffisance des diagnostic settings / logs."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ResourceType, ThreatModel
from agent_threat_mapper.rules import _common
from agent_threat_mapper.rules.base import Finding, Severity

_CATEGORY = "Observabilité"
_OWASP = "LLM09: Misinformation"


def resource_without_diagnostics(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-LOGGING-001 — ressource accessible sans diagnostic settings actifs.

    Sévérité HIGH pour un Key Vault (une compromission de secrets non loguée est le pire
    scénario), MEDIUM pour les autres ressources (storage, AI Search)."""
    findings: list[Finding] = []
    for node in tm.resource_nodes():
        if not _common.is_accessible(node):
            continue
        if tm.reaches_log_sink(node.id):
            continue
        is_kv = node.resource_type == ResourceType.KEY_VAULT
        severity = Severity.HIGH if is_kv else Severity.MEDIUM
        rid = getattr(node.resource_ref, "resource_id", node.id)
        kind_label = node.resource_type.value
        findings.append(
            Finding(
                rule_id="ATM-LOGGING-001",
                title="Ressource accessible sans traçabilité (diagnostic settings absents)",
                severity=severity,
                category=_CATEGORY,
                explanation=(
                    f"La ressource '{node.label}' ({kind_label}), accessible par l'agent via "
                    f"{_common.roles_str(node)}, n'a aucun diagnostic setting actif : une compromission "
                    f"ou un accès anormal ne laisserait aucune trace exploitable."
                ),
                mitigation=(
                    f"Activer les diagnostic settings vers un Log Analytics workspace : "
                    f"`az monitor diagnostic-settings create --name atm-diag --resource {rid} "
                    f"--workspace <workspaceId> --logs '[{{\"categoryGroup\":\"audit\",\"enabled\":true}}]'`."
                ),
                affected_resources=[rid],
                owasp_ref=_OWASP,
            )
        )
    return findings
