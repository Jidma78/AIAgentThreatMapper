"""Dataclasses représentant les ressources Azure normalisées et leurs propriétés de sécurité."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ManagedIdentity:
    principal_id: str
    client_id: str
    tenant_id: str
    object_id: str
    resource_id: str


@dataclass
class RoleAssignment:
    role_definition_name: str
    role_definition_id: str
    scope: str
    principal_id: str
    assignment_id: str


@dataclass
class KeyVault:
    name: str
    resource_id: str
    resource_group: str
    location: str
    network_acls_default_action: str  # "Allow" or "Deny"
    enabled_for_disk_encryption: bool
    soft_delete_enabled: bool
    purge_protection_enabled: bool
    # None = mode d'autorisation inconnu (API ancienne / champ absent). Lève l'ambiguïté
    # Contributor vs access-policy interprétée dans models/role_interpreter.py.
    enable_rbac_authorization: Optional[bool] = None


@dataclass
class StorageAccount:
    name: str
    resource_id: str
    resource_group: str
    location: str
    allow_blob_public_access: bool
    https_only: bool
    network_acls_default_action: str  # "Allow" or "Deny"
    kind: str
    sku_name: str


@dataclass
class AISearch:
    name: str
    resource_id: str
    resource_group: str
    location: str
    sku_name: str
    public_network_access: str  # "Enabled" or "Disabled"
    replica_count: int


@dataclass
class DiagnosticSettings:
    resource_id: str
    name: str
    workspace_id: Optional[str]
    storage_account_id: Optional[str]
    log_categories: list[str]
    enabled: bool


@dataclass
class AgentContext:
    """Conteneur unique rassemblant toutes les ressources exportées pour un agent."""

    managed_identity: ManagedIdentity
    role_assignments: list[RoleAssignment] = field(default_factory=list)
    key_vaults: list[KeyVault] = field(default_factory=list)
    storage_accounts: list[StorageAccount] = field(default_factory=list)
    ai_search_services: list[AISearch] = field(default_factory=list)
    diagnostic_settings: list[DiagnosticSettings] = field(default_factory=list)
