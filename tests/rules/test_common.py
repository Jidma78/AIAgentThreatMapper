"""Tests des helpers partagés des règles (purs, sans mock)."""

from __future__ import annotations

from agent_threat_mapper.models.threat_model import ResourceType
from agent_threat_mapper.rules import _common
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, intent, keyvault, role_on, storage


def test_forbids_french_and_english():
    fr = intent(forbidden=["Écrire dans le stockage", "Supprimer des ressources"])
    en = intent(forbidden=["write or delete any storage blobs"])
    assert _common.forbids(fr, *_common.WRITE_MODIFY_STEMS) is True
    assert _common.forbids(en, *_common.WRITE_MODIFY_STEMS) is True


def test_forbids_secret_bilingual():
    fr = intent(forbidden=["Accéder à des secrets de production"])
    en = intent(forbidden=["read production secrets"])
    assert _common.forbids(fr, *_common.SECRET_STEMS) is True
    assert _common.forbids(en, *_common.SECRET_STEMS) is True


def test_forbids_false_when_unrelated():
    i = intent(forbidden=["send data outside the tenant"])
    assert _common.forbids(i, *_common.WRITE_MODIFY_STEMS) is False


def test_scope_level():
    assert _common.scope_level(f"/subscriptions/{'s'}") == "subscription"
    assert _common.scope_level("/subscriptions/s/resourceGroups/rg") == "resource_group"
    assert _common.scope_level(
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/x"
    ) == "resource"


def test_effective_permissions_keyvault_uses_rbac_mode():
    kv = keyvault(rbac=True)
    tm = build_threat_model(context(keyvaults=[kv], roles=[role_on(kv, "Contributor")]), intent())
    node = tm.get_node("resource:keyvault:atm-kv")
    perms = _common.effective_permissions(node)
    # Contributor en mode RBAC = management seul, pas de data-plane
    assert perms.can_manage_resource is True
    assert perms.can_read_data is False


def test_effective_permissions_storage_writable():
    sa = storage()
    tm = build_threat_model(
        context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Contributor")]), intent()
    )
    node = tm.get_node("resource:storage:atmstore")
    assert _common.effective_permissions(node).can_write_data is True


def test_is_accessible_and_roles_str():
    sa = storage()
    tm = build_threat_model(
        context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Reader")]), intent()
    )
    node = tm.get_node("resource:storage:atmstore")
    assert _common.is_accessible(node) is True
    assert "Storage Blob Data Reader" in _common.roles_str(node)
