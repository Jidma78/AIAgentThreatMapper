"""Tests du parsing de agent_context.json vers les dataclasses azure_resources."""

from pathlib import Path

import pytest

from agent_threat_mapper.models.azure_resources import (
    AgentContext,
    AISearch,
    DiagnosticSettings,
    KeyVault,
    ManagedIdentity,
    RoleAssignment,
    StorageAccount,
)
from agent_threat_mapper.normalization.context_parser import parse_context

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAMPLE_JSON = FIXTURES / "agent_context_sample.json"


@pytest.fixture
def ctx() -> AgentContext:
    return parse_context(SAMPLE_JSON)


def test_returns_agent_context(ctx):
    assert isinstance(ctx, AgentContext)


def test_managed_identity(ctx):
    mi = ctx.managed_identity
    assert isinstance(mi, ManagedIdentity)
    assert mi.principal_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert mi.client_id == "11111111-2222-3333-4444-555555555555"
    assert mi.tenant_id == "66666666-7777-8888-9999-aaaaaaaaaaaa"
    assert "agent-identity" in mi.resource_id


def test_role_assignments(ctx):
    roles = ctx.role_assignments
    assert len(roles) == 2
    assert all(isinstance(r, RoleAssignment) for r in roles)
    names = {r.role_definition_name for r in roles}
    assert "Contributor" in names
    assert "Storage Blob Data Reader" in names


def test_role_scope_breadth(ctx):
    contributor = next(r for r in ctx.role_assignments if r.role_definition_name == "Contributor")
    assert contributor.scope == "/subscriptions/sub-0000"


def test_key_vaults(ctx):
    kvs = ctx.key_vaults
    assert len(kvs) == 1
    kv = kvs[0]
    assert isinstance(kv, KeyVault)
    assert kv.name == "agent-keyvault"
    assert kv.network_acls_default_action == "Allow"
    assert kv.soft_delete_enabled is True
    assert kv.purge_protection_enabled is False


def test_storage_accounts(ctx):
    stores = ctx.storage_accounts
    assert len(stores) == 1
    s = stores[0]
    assert isinstance(s, StorageAccount)
    assert s.name == "agentstore001"
    assert s.https_only is True
    assert s.allow_blob_public_access is False
    assert s.network_acls_default_action == "Allow"


def test_ai_search_services(ctx):
    searches = ctx.ai_search_services
    assert len(searches) == 1
    a = searches[0]
    assert isinstance(a, AISearch)
    assert a.name == "agent-search"
    assert a.public_network_access == "Enabled"
    assert a.replica_count == 1


def test_diagnostic_settings(ctx):
    diags = ctx.diagnostic_settings
    assert len(diags) == 1
    d = diags[0]
    assert isinstance(d, DiagnosticSettings)
    assert d.name == "kv-diag"
    assert d.enabled is True
    assert d.storage_account_id is None
    assert "AuditEvent" in d.log_categories


def test_parse_context_from_string():
    json_str = """{
        "managed_identity": {
            "principal_id": "pid", "client_id": "cid", "tenant_id": "tid",
            "object_id": "pid", "resource_id": "/rg/id"
        }
    }"""
    ctx = parse_context(json_str)
    assert ctx.managed_identity.principal_id == "pid"
    assert ctx.role_assignments == []
    assert ctx.key_vaults == []


def test_missing_managed_identity_raises():
    with pytest.raises(KeyError):
        parse_context("{}")
