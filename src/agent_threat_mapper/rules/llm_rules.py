"""Règles inspirées de l'OWASP LLM Top 10 : excessive agency et prompt injection impact path."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent, AutonomyLevel
from agent_threat_mapper.models.threat_model import ResourceType, ThreatModel
from agent_threat_mapper.rules import _common
from agent_threat_mapper.rules.base import Finding, Severity

_CATEGORY = "Chemin d'attaque LLM"
_OWASP_INJECTION = "LLM01: Prompt Injection"
_OWASP_AGENCY = "LLM06: Excessive Agency"
_B5 = "B5"


def _has_path_from(tm: ThreatModel, target_id: str, origin: str) -> bool:
    """True s'il existe un chemin depuis `origin` (entrée non fiable) vers `target_id`
    franchissant la frontière d'agency B5 (décision LLM → invocation d'outil)."""
    for p in tm.paths_from_untrusted_to(target_id):
        if p.origin.id == origin and _B5 in {b.id for b in p.crossed_boundaries}:
            return True
    return False


def prompt_injection_path_to_keyvault(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-LLM-001 — un prompt utilisateur peut atteindre un Key Vault en franchissant B5."""
    findings: list[Finding] = []
    for node in tm.resource_nodes(ResourceType.KEY_VAULT):
        if not _has_path_from(tm, node.id, "user"):
            continue
        kv = node.resource_ref
        findings.append(
            Finding(
                rule_id="ATM-LLM-001",
                title="Chemin de prompt injection vers un Key Vault",
                severity=Severity.HIGH,
                category=_CATEGORY,
                explanation=(
                    f"Un prompt utilisateur non fiable peut influencer le LLM (frontière B5) jusqu'à "
                    f"déclencher un accès au Key Vault '{kv.name}' : user → agent → llm → outil → "
                    f"'{kv.name}'. C'est un chemin d'impact de prompt injection vers des secrets."
                ),
                mitigation=(
                    f"Interposer une validation humaine (human-in-the-loop) sur les outils touchant "
                    f"'{kv.name}', ou retirer l'accès au Key Vault du périmètre d'outils du LLM."
                ),
                affected_resources=[kv.resource_id],
                owasp_ref=_OWASP_INJECTION,
            )
        )
    return findings


def rag_poisoning_path_to_writable_storage(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-LLM-002 — un contenu RAG empoisonné peut atteindre un storage inscriptible via B5."""
    findings: list[Finding] = []
    for node in tm.resource_nodes(ResourceType.STORAGE):
        perms = _common.effective_permissions(node)
        if not perms.can_write_data:
            continue
        if not _has_path_from(tm, node.id, "rag"):
            continue
        sa = node.resource_ref
        findings.append(
            Finding(
                rule_id="ATM-LLM-002",
                title="Chemin de RAG poisoning vers un storage inscriptible",
                severity=Severity.HIGH,
                category=_CATEGORY,
                explanation=(
                    f"Un document RAG empoisonné peut influencer le LLM (frontière B5) jusqu'à une "
                    f"écriture dans le Storage '{sa.name}' : rag → agent → llm → outil → '{sa.name}'. "
                    f"L'agent corromprait ainsi son propre corpus documentaire."
                ),
                mitigation=(
                    f"Séparer le storage source RAG (lecture seule) du storage cible d'écriture, ou "
                    f"valider humainement les écritures vers '{sa.name}'."
                ),
                affected_resources=[sa.resource_id],
                owasp_ref=_OWASP_INJECTION,
            )
        )
    return findings


def autonomous_agent_critical_access(tm: ThreatModel, intent: AgentIntent) -> list[Finding]:
    """ATM-LLM-003 — agent AUTONOMOUS avec accès à des ressources critiques (excessive agency)."""
    if intent.autonomy_level != AutonomyLevel.AUTONOMOUS:
        return []

    critical: list[str] = []
    labels: list[str] = []
    for node in tm.resource_nodes():
        if not _common.is_accessible(node):
            continue
        ref = node.resource_ref
        if node.resource_type == ResourceType.KEY_VAULT:
            critical.append(ref.resource_id)
            labels.append(f"Key Vault '{ref.name}'")
        elif node.resource_type == ResourceType.STORAGE and ref.network_acls_default_action == "Allow":
            critical.append(ref.resource_id)
            labels.append(f"Storage '{ref.name}' (réseau ouvert)")

    if not critical:
        return []

    return [
        Finding(
            rule_id="ATM-LLM-003",
            title="Agent autonome avec accès à des ressources critiques",
            severity=Severity.HIGH,
            category=_CATEGORY,
            explanation=(
                f"L'agent est déclaré autonomy_level=AUTONOMOUS et accède sans supervision humaine à "
                f"des ressources critiques : {', '.join(labels)}. L'autonomie amplifie l'impact d'une "
                f"prompt injection ou d'un RAG poisoning (excessive agency)."
            ),
            mitigation=(
                "Abaisser l'autonomie à 'supervised' ou 'human_in_the_loop' pour les outils touchant "
                "ces ressources, ou réduire le périmètre d'accès de l'identité managée."
            ),
            affected_resources=critical,
            owasp_ref=_OWASP_AGENCY,
        )
    ]
