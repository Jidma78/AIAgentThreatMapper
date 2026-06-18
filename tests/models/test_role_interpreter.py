"""Tests de l'interprétation des rôles built-in Azure (fonctions pures, sans mock Azure)."""

from __future__ import annotations

from agent_threat_mapper.models.azure_resources import RoleAssignment
from agent_threat_mapper.models.role_interpreter import (
    aggregate_permissions,
    interpret_role,
)
from agent_threat_mapper.models.threat_model import ResourceType


def _role(name: str) -> RoleAssignment:
    return RoleAssignment(
        role_definition_name=name, role_definition_id="/rd", scope="/s",
        principal_id="pid", assignment_id="/ra",
    )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def test_storage_blob_data_reader():
    p = interpret_role("Storage Blob Data Reader")
    assert p.can_read_data and p.can_list_metadata
    assert not p.can_write_data and not p.can_delete_data and not p.can_manage_resource


def test_storage_blob_data_contributor():
    p = interpret_role("Storage Blob Data Contributor")
    assert p.can_read_data and p.can_write_data and p.can_delete_data
    assert not p.can_manage_resource


def test_storage_blob_data_owner_includes_acl_note():
    p = interpret_role("Storage Blob Data Owner")
    assert p.can_read_data and p.can_write_data and p.can_delete_data
    assert "ACL" in p.notes


def test_contributor_storage_is_management_only():
    p = interpret_role("Contributor", resource_type=ResourceType.STORAGE)
    assert p.can_manage_resource
    assert not p.can_read_data and not p.can_write_data and not p.can_delete_data


# ---------------------------------------------------------------------------
# Key Vault
# ---------------------------------------------------------------------------

def test_key_vault_secrets_user():
    p = interpret_role("Key Vault Secrets User")
    assert p.can_read_data and p.can_list_metadata
    assert not p.can_write_data


def test_key_vault_secrets_officer():
    p = interpret_role("Key Vault Secrets Officer")
    assert p.can_read_data and p.can_write_data and p.can_delete_data


def test_key_vault_reader_metadata_only_not_values():
    p = interpret_role("Key Vault Reader")
    assert p.can_list_metadata is True
    assert p.can_read_data is False          # liste les noms, PAS les valeurs
    assert not p.can_write_data and not p.can_manage_resource


def test_contributor_keyvault_rbac_mode_management_only():
    p = interpret_role("Contributor", ResourceType.KEY_VAULT, enable_rbac_authorization=True)
    assert p.can_manage_resource
    assert not p.can_read_data and not p.can_write_data
    assert p.ambiguous is False


def test_contributor_keyvault_access_policy_mode_reaches_dataplane():
    p = interpret_role("Contributor", ResourceType.KEY_VAULT, enable_rbac_authorization=False)
    assert p.can_read_data and p.can_write_data and p.can_delete_data
    assert p.ambiguous is True
    assert "access-policy" in p.notes


def test_contributor_keyvault_unknown_rbac_is_ambiguous():
    p = interpret_role("Contributor", ResourceType.KEY_VAULT, enable_rbac_authorization=None)
    assert p.ambiguous is True
    assert p.can_manage_resource
    assert not p.can_read_data                # conservateur : on ne présume pas l'accès
    assert "inconnu" in p.notes


# ---------------------------------------------------------------------------
# AI Search & rôles larges
# ---------------------------------------------------------------------------

def test_search_index_data_reader():
    p = interpret_role("Search Index Data Reader")
    assert p.can_read_data and not p.can_write_data


def test_search_index_data_contributor():
    p = interpret_role("Search Index Data Contributor")
    assert p.can_read_data and p.can_write_data and p.can_delete_data


def test_owner_full_control_and_escalation_note():
    p = interpret_role("Owner")
    assert p.can_read_data and p.can_write_data and p.can_delete_data and p.can_manage_resource
    assert "escalade" in p.notes


# ---------------------------------------------------------------------------
# Robustesse
# ---------------------------------------------------------------------------

def test_unknown_role_is_ambiguous():
    p = interpret_role("My Custom Role")
    assert p.ambiguous is True
    assert not any([p.can_read_data, p.can_write_data, p.can_delete_data, p.can_manage_resource])
    assert "non couvert" in p.notes


def test_role_name_is_case_insensitive():
    assert interpret_role("STORAGE BLOB DATA CONTRIBUTOR").can_write_data is True


# ---------------------------------------------------------------------------
# aggregate_permissions
# ---------------------------------------------------------------------------

def test_aggregate_ors_rights_across_roles():
    roles = [_role("Storage Blob Data Reader"), _role("Storage Blob Data Contributor")]
    p = aggregate_permissions(roles, ResourceType.STORAGE)
    assert p.can_read_data and p.can_write_data and p.can_delete_data


def test_aggregate_empty_is_all_false():
    p = aggregate_permissions([], ResourceType.STORAGE)
    assert not any([p.can_read_data, p.can_write_data, p.can_manage_resource, p.ambiguous])


def test_aggregate_propagates_ambiguous():
    roles = [_role("Contributor")]
    p = aggregate_permissions(roles, ResourceType.KEY_VAULT, enable_rbac_authorization=None)
    assert p.ambiguous is True
