"""Builders inline partagés par les tests de règles (fonctions pures, sans mock Azure)."""

from __future__ import annotations

import pytest

from agent_threat_mapper.models.agent_intent import AgentIntent, AutonomyLevel
from agent_threat_mapper.models.azure_resources import (
    AgentContext,
    AISearch,
    DiagnosticSettings,
    KeyVault,
    ManagedIdentity,
    RoleAssignment,
    StorageAccount,
)

SUB = "cce3f0d7-5933-4838-a31e-4567cbc117d0"
RG_SCOPE = f"/subscriptions/{SUB}/resourceGroups/atm-rg"


def _rid(provider: str, name: str) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/atm-rg/providers/{provider}/{name}"


def identity() -> ManagedIdentity:
    return ManagedIdentity(
        principal_id="pid", client_id="cid", tenant_id="tid", object_id="pid",
        resource_id=_rid("Microsoft.ManagedIdentity/userAssignedIdentities", "atm-id"),
    )


def storage(name="atmstore", network="Allow", public_blob=False, https_only=True) -> StorageAccount:
    return StorageAccount(
        name=name, resource_id=_rid("Microsoft.Storage/storageAccounts", name),
        resource_group="atm-rg", location="francecentral",
        allow_blob_public_access=public_blob, https_only=https_only,
        network_acls_default_action=network, kind="StorageV2", sku_name="Standard_LRS",
    )


def keyvault(name="atm-kv", network="Allow", purge=False, soft_delete=True, rbac=False) -> KeyVault:
    return KeyVault(
        name=name, resource_id=_rid("Microsoft.KeyVault/vaults", name), resource_group="atm-rg",
        location="francecentral", network_acls_default_action=network,
        enabled_for_disk_encryption=False, soft_delete_enabled=soft_delete,
        purge_protection_enabled=purge, enable_rbac_authorization=rbac,
    )


def aisearch(name="atm-search", network="Enabled") -> AISearch:
    return AISearch(
        name=name, resource_id=_rid("Microsoft.Search/searchServices", name), resource_group="atm-rg",
        location="francecentral", sku_name="standard", public_network_access=network, replica_count=1,
    )


def role(name: str, scope: str = RG_SCOPE) -> RoleAssignment:
    return RoleAssignment(
        role_definition_name=name, role_definition_id="/rd", scope=scope,
        principal_id="pid", assignment_id=f"/ra/{name}/{scope}",
    )


def role_on(resource: object, name: str) -> RoleAssignment:
    return role(name, scope=resource.resource_id)


def diag_for(resource: object) -> DiagnosticSettings:
    return DiagnosticSettings(
        resource_id=resource.resource_id, name="diag", workspace_id="/ws",
        storage_account_id=None, log_categories=["Audit"], enabled=True,
    )


def context(storages=None, keyvaults=None, searches=None, roles=None, diags=None) -> AgentContext:
    return AgentContext(
        managed_identity=identity(),
        role_assignments=roles or [],
        key_vaults=keyvaults or [],
        storage_accounts=storages or [],
        ai_search_services=searches or [],
        diagnostic_settings=diags or [],
    )


def intent(name="agent", autonomy=AutonomyLevel.SUPERVISED, allowed=None, forbidden=None) -> AgentIntent:
    return AgentIntent(
        name=name, autonomy_level=autonomy,
        allowed_actions=allowed or [], forbidden_actions=forbidden or [],
    )


@pytest.fixture
def builders():
    """Expose les builders comme une fixture pour les tests qui préfèrent l'injection."""
    return {
        "storage": storage, "keyvault": keyvault, "aisearch": aisearch,
        "role": role, "role_on": role_on, "diag_for": diag_for,
        "context": context, "intent": intent,
    }
