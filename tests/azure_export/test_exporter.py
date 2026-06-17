"""Tests de l'orchestration de l'export Azure (appels `az` mockés)."""

from __future__ import annotations

import json
import subprocess
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_threat_mapper.azure_export.exporter import (
    _classify_scope,
    _collect_resources_for_scope,
    _infer_type_from_id,
    _map_ai_search,
    _map_diagnostic_settings,
    _map_key_vault,
    _map_managed_identity,
    _map_role_assignment,
    _map_storage_account,
    _parse_identity_resource_id,
    export_agent_context,
)
from agent_threat_mapper.models.azure_resources import AgentContext

# ---------------------------------------------------------------------------
# _parse_identity_resource_id
# ---------------------------------------------------------------------------

VALID_IDENTITY_ID = (
    "/subscriptions/sub-0000/resourceGroups/rg-agent"
    "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agent-id"
)


def test_parse_identity_resource_id_valid():
    sub, rg = _parse_identity_resource_id(VALID_IDENTITY_ID)
    assert sub == "sub-0000"
    assert rg == "rg-agent"


def test_parse_identity_resource_id_lowercase_segments():
    rid = (
        "/subscriptions/sub-0000/resourcegroups/rg-agent"
        "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agent-id"
    )
    sub, rg = _parse_identity_resource_id(rid)
    assert sub == "sub-0000"
    assert rg == "rg-agent"


def test_parse_identity_resource_id_too_short():
    with pytest.raises(ValueError, match="malformé"):
        _parse_identity_resource_id("/subscriptions/sub-0000")


def test_parse_identity_resource_id_missing_resourcegroups():
    with pytest.raises(ValueError, match="malformé"):
        _parse_identity_resource_id(
            "/subscriptions/sub-0000/providers/Microsoft.ManagedIdentity"
            "/userAssignedIdentities/bad"
        )


def test_parse_identity_resource_id_empty():
    with pytest.raises(ValueError, match="malformé"):
        _parse_identity_resource_id("")


# ---------------------------------------------------------------------------
# _classify_scope
# ---------------------------------------------------------------------------

def test_classify_scope_subscription():
    assert _classify_scope("/subscriptions/sub-0000") == "subscription"


def test_classify_scope_resource_group():
    assert _classify_scope("/subscriptions/sub-0000/resourceGroups/rg-agent") == "resource_group"


def test_classify_scope_resource():
    assert _classify_scope(
        "/subscriptions/sub-0000/resourceGroups/rg-agent"
        "/providers/Microsoft.Storage/storageAccounts/mystore"
    ) == "resource"


# ---------------------------------------------------------------------------
# _infer_type_from_id
# ---------------------------------------------------------------------------

def test_infer_type_keyvault():
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
    assert _infer_type_from_id(rid) == "Microsoft.KeyVault/vaults"


def test_infer_type_storage():
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"
    assert _infer_type_from_id(rid) == "Microsoft.Storage/storageAccounts"


def test_infer_type_search():
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch"
    assert _infer_type_from_id(rid) == "Microsoft.Search/searchServices"


# ---------------------------------------------------------------------------
# _map_managed_identity
# ---------------------------------------------------------------------------

def test_map_managed_identity():
    raw = {
        "principalId": "pid",
        "clientId": "cid",
        "tenantId": "tid",
        "id": "/rg/identity",
    }
    result = _map_managed_identity(raw)
    assert result["principal_id"] == "pid"
    assert result["object_id"] == "pid"
    assert result["client_id"] == "cid"
    assert result["tenant_id"] == "tid"
    assert result["resource_id"] == "/rg/identity"


def test_map_managed_identity_missing_fields():
    result = _map_managed_identity({})
    assert result["principal_id"] == ""
    assert result["client_id"] == ""


# ---------------------------------------------------------------------------
# _map_role_assignment
# ---------------------------------------------------------------------------

def test_map_role_assignment():
    raw = {
        "roleDefinitionName": "Contributor",
        "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/b24988ac",
        "scope": "/subscriptions/sub-0000",
        "principalId": "pid",
        "id": "/subscriptions/sub-0000/providers/Microsoft.Authorization/roleAssignments/ra-001",
    }
    result = _map_role_assignment(raw)
    assert result["role_definition_name"] == "Contributor"
    assert result["scope"] == "/subscriptions/sub-0000"
    assert result["assignment_id"] == raw["id"]


# ---------------------------------------------------------------------------
# _map_key_vault
# ---------------------------------------------------------------------------

def test_map_key_vault_full():
    raw = {
        "name": "my-kv",
        "id": "/sub/rg/kv/my-kv",
        "resourceGroup": "rg-agent",
        "location": "westeurope",
        "properties": {
            "networkAcls": {"defaultAction": "Deny"},
            "enabledForDiskEncryption": True,
            "enableSoftDelete": True,
            "enablePurgeProtection": True,
        },
    }
    result = _map_key_vault(raw)
    assert result["network_acls_default_action"] == "Deny"
    assert result["soft_delete_enabled"] is True
    assert result["purge_protection_enabled"] is True


def test_map_key_vault_purge_protection_none():
    raw = {
        "name": "kv",
        "id": "/id",
        "resourceGroup": "rg",
        "location": "we",
        "properties": {"enablePurgeProtection": None},
    }
    result = _map_key_vault(raw)
    assert result["purge_protection_enabled"] is False


def test_map_key_vault_missing_properties():
    result = _map_key_vault({"name": "kv", "id": "/id"})
    assert result["network_acls_default_action"] == "Allow"
    assert result["soft_delete_enabled"] is False


# ---------------------------------------------------------------------------
# _map_storage_account
# ---------------------------------------------------------------------------

def test_map_storage_account_enable_https_traffic_only():
    raw = {
        "name": "st",
        "id": "/id",
        "resourceGroup": "rg",
        "location": "we",
        "allowBlobPublicAccess": False,
        "enableHttpsTrafficOnly": True,
        "networkRuleSet": {"defaultAction": "Allow"},
        "kind": "StorageV2",
        "sku": {"name": "Standard_LRS"},
    }
    result = _map_storage_account(raw)
    assert result["https_only"] is True
    assert result["allow_blob_public_access"] is False
    assert result["sku_name"] == "Standard_LRS"


def test_map_storage_account_fallback_supports_https():
    raw = {
        "name": "st",
        "id": "/id",
        "resourceGroup": "rg",
        "location": "we",
        "supportsHttpsTrafficOnly": True,
    }
    result = _map_storage_account(raw)
    assert result["https_only"] is True


def test_map_storage_account_missing_network_rule_set():
    raw = {"name": "st", "id": "/id"}
    result = _map_storage_account(raw)
    assert result["network_acls_default_action"] == "Allow"
    assert result["https_only"] is False


# ---------------------------------------------------------------------------
# _map_ai_search
# ---------------------------------------------------------------------------

def test_map_ai_search_top_level_fields():
    raw = {
        "name": "srch",
        "id": "/id",
        "resourceGroup": "rg",
        "location": "we",
        "sku": {"name": "standard"},
        "publicNetworkAccess": "Enabled",
        "replicaCount": 2,
    }
    result = _map_ai_search(raw)
    assert result["public_network_access"] == "Enabled"
    assert result["replica_count"] == 2
    assert result["sku_name"] == "standard"


def test_map_ai_search_under_properties():
    raw = {
        "name": "srch",
        "id": "/id",
        "resourceGroup": "rg",
        "location": "we",
        "sku": {"name": "basic"},
        "properties": {"publicNetworkAccess": "Disabled", "replicaCount": 3},
    }
    result = _map_ai_search(raw)
    assert result["public_network_access"] == "Disabled"
    assert result["replica_count"] == 3


def test_map_ai_search_defaults():
    result = _map_ai_search({"name": "srch", "id": "/id"})
    assert result["public_network_access"] == "Enabled"
    assert result["replica_count"] == 1


# ---------------------------------------------------------------------------
# _map_diagnostic_settings
# ---------------------------------------------------------------------------

def test_map_diagnostic_settings():
    raw = {
        "name": "diag",
        "workspaceId": "/ws/id",
        "storageAccountId": None,
        "logs": [
            {"category": "AuditEvent", "enabled": True},
            {"category": "AllMetrics", "enabled": False},
        ],
    }
    result = _map_diagnostic_settings(raw, "/resource/id")
    assert result["resource_id"] == "/resource/id"
    assert result["workspace_id"] == "/ws/id"
    assert result["storage_account_id"] is None
    assert result["log_categories"] == ["AuditEvent"]
    assert result["enabled"] is True


def test_map_diagnostic_settings_all_disabled():
    raw = {"name": "diag", "logs": [{"category": "X", "enabled": False}]}
    result = _map_diagnostic_settings(raw, "/r")
    assert result["log_categories"] == []
    assert result["enabled"] is False


# ---------------------------------------------------------------------------
# _collect_resources_for_scope
# ---------------------------------------------------------------------------

@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_collect_subscription_scope(mock_az):
    mock_az.list_resources_in_subscription.return_value = [{"id": "/r1"}]
    result = _collect_resources_for_scope("/subscriptions/sub-0000", "sub-0000")
    mock_az.list_resources_in_subscription.assert_called_once_with("sub-0000")
    assert result == [{"id": "/r1"}]


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_collect_resource_group_scope(mock_az):
    mock_az.list_resource_group_resources.return_value = [{"id": "/r2"}]
    result = _collect_resources_for_scope(
        "/subscriptions/sub-0000/resourceGroups/rg-agent", "sub-0000"
    )
    mock_az.list_resource_group_resources.assert_called_once_with("rg-agent")
    assert result == [{"id": "/r2"}]


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_collect_resource_scope_no_az_call(mock_az):
    scope = (
        "/subscriptions/sub-0000/resourceGroups/rg-agent"
        "/providers/Microsoft.Storage/storageAccounts/mystore"
    )
    result = _collect_resources_for_scope(scope, "sub-0000")
    mock_az.list_resources_in_subscription.assert_not_called()
    mock_az.list_resource_group_resources.assert_not_called()
    assert len(result) == 1
    assert result[0]["id"] == scope
    assert result[0]["type"] == "Microsoft.Storage/storageAccounts"
    assert result[0]["name"] == "mystore"


# ---------------------------------------------------------------------------
# export_agent_context — intégration (tous les az_commands mockés)
# ---------------------------------------------------------------------------

_IDENTITY_ID = (
    "/subscriptions/sub-0000/resourceGroups/rg-agent"
    "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agent-id"
)

_RAW_IDENTITY = {
    "principalId": "pid-001",
    "clientId": "cid-001",
    "tenantId": "tid-001",
    "id": _IDENTITY_ID,
}

_RAW_ROLES = [
    {
        "roleDefinitionName": "Contributor",
        "roleDefinitionId": "/providers/roleDefinitions/b24988ac",
        "scope": "/subscriptions/sub-0000/resourceGroups/rg-agent",
        "principalId": "pid-001",
        "id": "/subscriptions/sub-0000/providers/roleAssignments/ra-001",
    }
]

_RG_RESOURCES = [
    {
        "id": (
            "/subscriptions/sub-0000/resourceGroups/rg-agent"
            "/providers/Microsoft.Storage/storageAccounts/mystore"
        ),
        "type": "Microsoft.Storage/storageAccounts",
        "name": "mystore",
        "resourceGroup": "rg-agent",
    }
]

_RAW_STORAGE = {
    "name": "mystore",
    "id": (
        "/subscriptions/sub-0000/resourceGroups/rg-agent"
        "/providers/Microsoft.Storage/storageAccounts/mystore"
    ),
    "resourceGroup": "rg-agent",
    "location": "westeurope",
    "allowBlobPublicAccess": False,
    "enableHttpsTrafficOnly": True,
    "networkRuleSet": {"defaultAction": "Allow"},
    "kind": "StorageV2",
    "sku": {"name": "Standard_LRS"},
}


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_agent_context_roundtrip(mock_az, tmp_path):
    mock_az.get_managed_identity.return_value = _RAW_IDENTITY
    mock_az.get_role_assignments.return_value = _RAW_ROLES
    mock_az.list_resource_group_resources.return_value = _RG_RESOURCES
    mock_az.get_storage_account.return_value = _RAW_STORAGE
    mock_az.get_diagnostic_settings.return_value = []

    output = tmp_path / "agent_context.json"
    ctx = export_agent_context(_IDENTITY_ID, output)

    assert isinstance(ctx, AgentContext)
    assert output.exists()
    assert ctx.managed_identity.principal_id == "pid-001"
    assert len(ctx.storage_accounts) == 1
    assert ctx.storage_accounts[0].name == "mystore"
    assert ctx.storage_accounts[0].https_only is True
    assert ctx.key_vaults == []
    assert ctx.ai_search_services == []


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_json_file_is_valid(mock_az, tmp_path):
    mock_az.get_managed_identity.return_value = _RAW_IDENTITY
    mock_az.get_role_assignments.return_value = _RAW_ROLES
    mock_az.list_resource_group_resources.return_value = _RG_RESOURCES
    mock_az.get_storage_account.return_value = _RAW_STORAGE
    mock_az.get_diagnostic_settings.return_value = []

    output = tmp_path / "out.json"
    export_agent_context(_IDENTITY_ID, output)

    data = json.loads(output.read_text())
    assert "managed_identity" in data
    assert "role_assignments" in data
    assert data["managed_identity"]["principal_id"] == "pid-001"


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_resource_level_scope_is_enriched(mock_az, tmp_path):
    """Un scope de niveau ressource doit passer par get_storage_account pour ses propriétés."""
    storage_id = (
        "/subscriptions/sub-0000/resourceGroups/rg-other"
        "/providers/Microsoft.Storage/storageAccounts/other-store"
    )
    raw_roles_resource_scope = [
        {
            "roleDefinitionName": "Storage Blob Data Reader",
            "roleDefinitionId": "/providers/roleDefinitions/2a2b9908",
            "scope": storage_id,
            "principalId": "pid-001",
            "id": "/subscriptions/sub-0000/providers/roleAssignments/ra-002",
        }
    ]
    raw_storage_other = {
        **_RAW_STORAGE,
        "name": "other-store",
        "id": storage_id,
        "resourceGroup": "rg-other",
    }

    mock_az.get_managed_identity.return_value = _RAW_IDENTITY
    mock_az.get_role_assignments.return_value = raw_roles_resource_scope
    mock_az.get_storage_account.return_value = raw_storage_other
    mock_az.get_diagnostic_settings.return_value = []

    output = tmp_path / "out.json"
    ctx = export_agent_context(_IDENTITY_ID, output)

    mock_az.get_storage_account.assert_called_once_with("other-store", "rg-other")
    assert ctx.storage_accounts[0].name == "other-store"
    assert ctx.storage_accounts[0].https_only is True


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_inaccessible_resource_is_skipped(mock_az, tmp_path):
    """Une ressource inaccessible déclenche un warning mais n'interrompt pas l'export."""
    mock_az.get_managed_identity.return_value = _RAW_IDENTITY
    mock_az.get_role_assignments.return_value = _RAW_ROLES
    mock_az.list_resource_group_resources.return_value = _RG_RESOURCES
    mock_az.get_storage_account.side_effect = subprocess.CalledProcessError(
        1, "az", stderr="AuthorizationFailed"
    )
    mock_az.get_diagnostic_settings.return_value = []

    output = tmp_path / "out.json"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ctx = export_agent_context(_IDENTITY_ID, output)

    assert len(caught) == 1
    assert "mystore" in str(caught[0].message)
    assert ctx.storage_accounts == []


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_identity_not_found_raises(mock_az, tmp_path):
    mock_az.get_managed_identity.side_effect = subprocess.CalledProcessError(
        1, "az", stderr="does not exist"
    )
    with pytest.raises(RuntimeError, match="introuvable"):
        export_agent_context(_IDENTITY_ID, tmp_path / "out.json")


@patch("agent_threat_mapper.azure_export.exporter.az_commands")
def test_export_authorization_error_raises(mock_az, tmp_path):
    mock_az.get_managed_identity.side_effect = subprocess.CalledProcessError(
        1, "az", stderr="AuthorizationFailed"
    )
    with pytest.raises(RuntimeError, match="Accès refusé"):
        export_agent_context(_IDENTITY_ID, tmp_path / "out.json")


def test_export_malformed_resource_id_raises(tmp_path):
    with pytest.raises(ValueError, match="malformé"):
        export_agent_context("not-a-valid-id", tmp_path / "out.json")
