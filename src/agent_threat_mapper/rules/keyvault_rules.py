"""Règles sur les Key Vaults : exposition réseau, protection des secrets, et capability mismatch d'accès aux secrets."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ResourceType, ThreatModel
from agent_threat_mapper.rules import _common
from agent_threat_mapper.rules.base import Finding, Severity

_CATEGORY = "Key Vault"
_OWASP_NETWORK = "LLM08: Vector and Embedding Weaknesses"
_OWASP_MISMATCH = "LLM06: Excessive Agency"


def _keyvault_nodes(tm: ThreatModel):
    return tm.resource_nodes(ResourceType.KEY_VAULT)


def keyvault_network_open(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-KEYVAULT-001 — pare-feu par défaut ouvert sur un Key Vault accessible par l'agent."""
    findings: list[Finding] = []
    for node in _keyvault_nodes(tm):
        kv = node.resource_ref
        if kv.network_acls_default_action == "Allow" and _common.is_accessible(node):
            findings.append(
                Finding(
                    rule_id="ATM-KEYVAULT-001",
                    title="Key Vault sans restriction réseau",
                    severity=Severity.HIGH,
                    category=_CATEGORY,
                    explanation=(
                        f"Le Key Vault '{kv.name}' a network_acls_default_action='Allow' (pare-feu "
                        f"ouvert à tous les réseaux) et est accessible par l'agent via {_common.roles_str(node)}."
                    ),
                    mitigation=(
                        f"Fermer le pare-feu par défaut puis autoriser uniquement les réseaux requis : "
                        f"`az keyvault update --name {kv.name} --default-action Deny`."
                    ),
                    affected_resources=[kv.resource_id],
                    owasp_ref=_OWASP_NETWORK,
                )
            )
    return findings


def keyvault_no_purge_protection(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-KEYVAULT-002 — purge protection désactivée."""
    findings: list[Finding] = []
    for node in _keyvault_nodes(tm):
        kv = node.resource_ref
        if kv.purge_protection_enabled is False:
            findings.append(
                Finding(
                    rule_id="ATM-KEYVAULT-002",
                    title="Key Vault sans purge protection",
                    severity=Severity.MEDIUM,
                    category=_CATEGORY,
                    explanation=(
                        f"Le Key Vault '{kv.name}' a purge_protection_enabled=False : un secret supprimé "
                        f"peut être purgé définitivement avant la fin de la période de rétention."
                    ),
                    mitigation=(
                        f"Activer la purge protection (irréversible) : "
                        f"`az keyvault update --name {kv.name} --enable-purge-protection true`."
                    ),
                    affected_resources=[kv.resource_id],
                    owasp_ref=None,
                )
            )
    return findings


def keyvault_no_soft_delete(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-KEYVAULT-003 — soft delete désactivé."""
    findings: list[Finding] = []
    for node in _keyvault_nodes(tm):
        kv = node.resource_ref
        if kv.soft_delete_enabled is False:
            findings.append(
                Finding(
                    rule_id="ATM-KEYVAULT-003",
                    title="Key Vault sans soft delete",
                    severity=Severity.MEDIUM,
                    category=_CATEGORY,
                    explanation=(
                        f"Le Key Vault '{kv.name}' a soft_delete_enabled=False : un secret supprimé "
                        f"n'est pas récupérable."
                    ),
                    mitigation=(
                        f"Activer le soft delete : "
                        f"`az keyvault update --name {kv.name} --enable-soft-delete true`."
                    ),
                    affected_resources=[kv.resource_id],
                    owasp_ref=None,
                )
            )
    return findings


def keyvault_secrets_access_forbidden(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-KEYVAULT-004 — l'agent peut lire les secrets alors que son rôle métier l'interdit."""
    if not _common.forbids(intent, *_common.SECRET_STEMS):
        return []
    findings: list[Finding] = []
    for node in _keyvault_nodes(tm):
        kv = node.resource_ref
        perms = _common.effective_permissions(node)
        if not perms.can_read_data:
            continue
        findings.append(
            Finding(
                rule_id="ATM-KEYVAULT-004",
                title="Accès aux secrets en contradiction avec l'intention déclarée",
                severity=Severity.CRITICAL,
                category=_CATEGORY,
                explanation=(
                    f"L'agent peut lire les valeurs de secrets du Key Vault '{kv.name}' via "
                    f"{_common.roles_str(node)} (can_read_data=True), alors que son rôle métier "
                    f"interdit l'accès aux secrets."
                ),
                mitigation=(
                    f"Retirer le rôle de lecture des secrets sur '{kv.name}' : "
                    f"`az role assignment delete --assignee <principalId> --scope {kv.resource_id}`."
                ),
                affected_resources=[kv.resource_id],
                owasp_ref=_OWASP_MISMATCH,
            )
        )
    return findings
