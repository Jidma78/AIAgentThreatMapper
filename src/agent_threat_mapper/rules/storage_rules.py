"""Règles sur les comptes Storage pouvant servir à empoisonner un pipeline RAG."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ResourceType, ThreatModel
from agent_threat_mapper.rules import _common
from agent_threat_mapper.rules.base import Finding, Severity

_CATEGORY = "Storage"
_OWASP = "LLM08: Vector and Embedding Weaknesses"


def _storage_nodes(tm: ThreatModel):
    return tm.resource_nodes(ResourceType.STORAGE)


def storage_network_open_writable(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-STORAGE-001 — pare-feu ouvert sur un storage accessible en écriture (vecteur RAG poisoning)."""
    findings: list[Finding] = []
    for node in _storage_nodes(tm):
        sa = node.resource_ref
        perms = _common.effective_permissions(node)
        if sa.network_acls_default_action == "Allow" and perms.can_write_data:
            findings.append(
                Finding(
                    rule_id="ATM-STORAGE-001",
                    title="Storage inscriptible et exposé réseau (vecteur de RAG poisoning)",
                    severity=Severity.HIGH,
                    category=_CATEGORY,
                    explanation=(
                        f"Le compte Storage '{sa.name}' a network_acls_default_action='Allow' et est "
                        f"accessible en écriture via {_common.roles_str(node)} : un attaquant peut y "
                        f"déposer des documents empoisonnés ingérés ensuite par le pipeline RAG."
                    ),
                    mitigation=(
                        f"Fermer le pare-feu par défaut : `az storage account update --name {sa.name} "
                        f"--default-action Deny`, puis n'autoriser que les réseaux nécessaires."
                    ),
                    affected_resources=[sa.resource_id],
                    owasp_ref=_OWASP,
                )
            )
    return findings


def storage_public_blob_access(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-STORAGE-002 — accès public aux blobs activé."""
    findings: list[Finding] = []
    for node in _storage_nodes(tm):
        sa = node.resource_ref
        if sa.allow_blob_public_access is True:
            findings.append(
                Finding(
                    rule_id="ATM-STORAGE-002",
                    title="Storage autorisant l'accès public aux blobs",
                    severity=Severity.HIGH,
                    category=_CATEGORY,
                    explanation=(
                        f"Le compte Storage '{sa.name}' a allow_blob_public_access=True : ses conteneurs "
                        f"peuvent être lus anonymement, exposant le corpus documentaire de l'agent."
                    ),
                    mitigation=(
                        f"Désactiver l'accès public aux blobs : `az storage account update "
                        f"--name {sa.name} --allow-blob-public-access false`."
                    ),
                    affected_resources=[sa.resource_id],
                    owasp_ref=_OWASP,
                )
            )
    return findings


def storage_no_https_only(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-STORAGE-003 — transfert non chiffré autorisé (https_only désactivé)."""
    findings: list[Finding] = []
    for node in _storage_nodes(tm):
        sa = node.resource_ref
        if sa.https_only is False:
            findings.append(
                Finding(
                    rule_id="ATM-STORAGE-003",
                    title="Storage autorisant le trafic non chiffré",
                    severity=Severity.MEDIUM,
                    category=_CATEGORY,
                    explanation=(
                        f"Le compte Storage '{sa.name}' a https_only=False : les données peuvent transiter "
                        f"en clair (HTTP), exposant le contenu à l'interception."
                    ),
                    mitigation=(
                        f"Imposer HTTPS : `az storage account update --name {sa.name} "
                        f"--https-only true`."
                    ),
                    affected_resources=[sa.resource_id],
                    owasp_ref=_OWASP,
                )
            )
    return findings


def storage_writable_forbidden(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-STORAGE-004 — storage accessible en écriture alors que l'intention interdit l'écriture."""
    if not _common.forbids(intent, *_common.WRITE_MODIFY_STEMS):
        return []
    findings: list[Finding] = []
    for node in _storage_nodes(tm):
        sa = node.resource_ref
        perms = _common.effective_permissions(node)
        if not perms.can_write_data:
            continue
        findings.append(
            Finding(
                rule_id="ATM-STORAGE-004",
                title="Écriture storage en contradiction avec l'intention déclarée",
                severity=Severity.HIGH,
                category=_CATEGORY,
                explanation=(
                    f"L'agent peut écrire dans le Storage '{sa.name}' via {_common.roles_str(node)} "
                    f"(can_write_data=True), alors que son rôle métier interdit l'écriture/modification "
                    f"— vecteur d'empoisonnement du corpus documentaire."
                ),
                mitigation=(
                    f"Remplacer le rôle d'écriture par 'Storage Blob Data Reader' sur '{sa.name}' : "
                    f"`az role assignment delete --assignee <principalId> --scope {sa.resource_id}`."
                ),
                affected_resources=[sa.resource_id],
                owasp_ref=_OWASP,
            )
        )
    return findings
