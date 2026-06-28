"""Collecte et enregistre tous les modules de règles afin que le moteur puisse les découvrir et les exécuter.

Ajouter une règle = écrire la fonction dans le bon module puis l'ajouter à REGISTERED_RULES ici.
engine.py n'a jamais besoin de changer."""

from __future__ import annotations

from typing import Callable

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.threat_model import ThreatModel
from agent_threat_mapper.rules import (
    identity_rules,
    keyvault_rules,
    llm_rules,
    logging_rules,
    storage_rules,
)
from agent_threat_mapper.rules.base import Finding

# Une règle est une fonction pure (ThreatModel, AgentIntent) -> list[Finding].
Rule = Callable[[ThreatModel, AgentIntent], list[Finding]]

REGISTERED_RULES: list[Rule] = [
    # identity
    identity_rules.broad_role_on_wide_scope,
    identity_rules.effective_permissions_exceed_intent,
    # key vault
    keyvault_rules.keyvault_network_open,
    keyvault_rules.keyvault_no_purge_protection,
    keyvault_rules.keyvault_no_soft_delete,
    keyvault_rules.keyvault_secrets_access_forbidden,
    # storage
    storage_rules.storage_network_open_writable,
    storage_rules.storage_public_blob_access,
    storage_rules.storage_no_https_only,
    storage_rules.storage_writable_forbidden,
    # observabilité
    logging_rules.resource_without_diagnostics,
    # chemins d'attaque LLM
    llm_rules.prompt_injection_path_to_keyvault,
    llm_rules.rag_poisoning_path_to_writable_storage,
    llm_rules.autonomous_agent_critical_access,
]
