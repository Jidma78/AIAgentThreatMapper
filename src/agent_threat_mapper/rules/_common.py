"""Helpers partagés par les modules de règles (fonctions pures, sans I/O).

`base.py` reste le contrat (`Finding`/`Severity`) ; ce module porte la logique transverse :
interprétation des permissions effectives d'un nœud ressource, matching bilingue des
`forbidden_actions`, et classification du niveau de scope d'un role assignment.
"""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.role_interpreter import (
    EffectivePermissions,
    aggregate_permissions,
)
from agent_threat_mapper.models.threat_model import Node, ResourceType

# Radicaux bilingues (FR/EN), insensibles à la casse, pour matcher des forbidden_actions.
# Le fixture de test est en anglais, les données réelles en français → on couvre les deux.
# LIMITE ASSUMÉE : matching coarse — ne distingue pas « write blobs » de « write secrets ».
WRITE_MODIFY_STEMS = (
    "write", "writ", "écrir", "ecrir", "modif", "supprim", "delete", "creat", "créer", "cré",
)
SECRET_STEMS = ("secret",)


def forbids(intent: AgentIntent, *stems: str) -> bool:
    """True si au moins une forbidden_action contient l'un des radicaux (casse-insensible)."""
    actions = [a.lower() for a in intent.forbidden_actions]
    return any(stem in action for action in actions for stem in stems)


def effective_permissions(node: Node) -> EffectivePermissions:
    """Permissions effectives de l'agent sur un nœud ressource, via aggregate_permissions.

    Passe le mode d'autorisation du Key Vault (`enable_rbac_authorization`) pour lever
    l'ambiguïté Contributor vs access-policy."""
    enable_rbac = None
    if node.resource_type == ResourceType.KEY_VAULT and node.resource_ref is not None:
        enable_rbac = getattr(node.resource_ref, "enable_rbac_authorization", None)
    return aggregate_permissions(node.applicable_roles, node.resource_type, enable_rbac)


def is_accessible(node: Node) -> bool:
    """True si l'agent dispose d'au moins un rôle applicable sur la ressource."""
    return bool(node.applicable_roles)


def roles_str(node: Node) -> str:
    """Liste lisible des rôles applicables, pour les explanations."""
    return ", ".join(r.role_definition_name for r in node.applicable_roles) or "aucun rôle explicite"


def scope_level(scope: str) -> str:
    """'subscription', 'resource_group' ou 'resource' selon le nombre de segments du scope."""
    parts = [s for s in scope.strip("/").split("/") if s]
    if len(parts) == 2:
        return "subscription"
    if len(parts) == 4:
        return "resource_group"
    return "resource"
