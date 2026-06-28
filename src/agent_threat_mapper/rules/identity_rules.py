"""Règles sur les rôles IAM trop larges (Owner/Contributor) et le capability mismatch entre intention déclarée et permissions réelles."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import NodeKind, ResourceType, ThreatModel
from agent_threat_mapper.rules import _common
from agent_threat_mapper.rules.base import Finding, Severity

_CATEGORY = "Identity & IAM"
_OWASP = "LLM06: Excessive Agency"
_BROAD_ROLES = {"owner", "contributor"}


def broad_role_on_wide_scope(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-IDENTITY-001 — Owner/Contributor sur un scope subscription ou resource group
    pour un agent dont le rôle métier interdit la modification/suppression de ressources."""
    if not _common.forbids(intent, *_common.WRITE_MODIFY_STEMS):
        return []

    # Rôles uniques (par assignment_id) couvrant une ressource exportée. NB : un rôle large
    # couvre de toute façon ces ressources (le stage 1 n'exporte que l'atteignable).
    seen_assignments: set[str] = set()
    findings: list[Finding] = []
    seen_scopes: set[str] = set()
    for node in tm.nodes_by_kind(NodeKind.AZURE_RESOURCE):
        for r in node.applicable_roles:
            if r.assignment_id in seen_assignments:
                continue
            seen_assignments.add(r.assignment_id)
            if r.role_definition_name.strip().lower() not in _BROAD_ROLES:
                continue
            if _common.scope_level(r.scope) not in ("subscription", "resource_group"):
                continue
            if r.scope in seen_scopes:
                continue
            seen_scopes.add(r.scope)
            findings.append(
                Finding(
                    rule_id="ATM-IDENTITY-001",
                    title="Rôle IAM trop large pour l'intention déclarée de l'agent",
                    severity=Severity.CRITICAL,
                    category=_CATEGORY,
                    explanation=(
                        f"L'identité de l'agent porte le rôle '{r.role_definition_name}' sur le scope "
                        f"'{r.scope}' (niveau {_common.scope_level(r.scope)}), ce qui confère un contrôle "
                        f"de gestion étendu sur les ressources. Or le rôle métier déclaré interdit la "
                        f"modification/suppression de ressources Azure."
                    ),
                    mitigation=(
                        f"Supprimer cette attribution et la remplacer par un rôle data-plane à portée "
                        f"minimale sur les seules ressources nécessaires : "
                        f"`az role assignment delete --assignee <principalId> "
                        f"--role \"{r.role_definition_name}\" --scope {r.scope}`."
                    ),
                    affected_resources=[r.scope],
                    owasp_ref=_OWASP,
                )
            )
    return findings


def effective_permissions_exceed_intent(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-IDENTITY-002 — permissions effectives d'écriture/suppression sur un Key Vault ou un
    AI Search alors que l'intention interdit l'écriture/modification. (Le mismatch storage est
    possédé par storage_rules pour éviter les doublons.)"""
    if not _common.forbids(intent, *_common.WRITE_MODIFY_STEMS):
        return []

    findings: list[Finding] = []
    for node in tm.resource_nodes():
        if node.resource_type not in (ResourceType.KEY_VAULT, ResourceType.AI_SEARCH):
            continue
        perms = _common.effective_permissions(node)
        if not (perms.can_write_data or perms.can_delete_data):
            continue
        findings.append(
            Finding(
                rule_id="ATM-IDENTITY-002",
                title="Permissions effectives supérieures à l'intention déclarée",
                severity=Severity.HIGH,
                category=_CATEGORY,
                explanation=(
                    f"La ressource '{node.label}' ({node.resource_type.value}) est accessible en "
                    f"écriture/suppression via le(s) rôle(s) {_common.roles_str(node)} "
                    f"(can_write_data={perms.can_write_data}, can_delete_data={perms.can_delete_data}), "
                    f"alors que le rôle métier de l'agent interdit l'écriture/modification."
                ),
                mitigation=(
                    f"Restreindre à un rôle en lecture seule (ex. data Reader) sur '{node.label}' et "
                    f"retirer le rôle d'écriture : `az role assignment delete --assignee <principalId> "
                    f"--scope {getattr(node.resource_ref, 'resource_id', node.id)}`."
                ),
                affected_resources=[getattr(node.resource_ref, "resource_id", node.id)],
                owasp_ref=_OWASP,
            )
        )
    return findings
