"""Tests des règles IAM/identité (rôles trop larges, capability mismatch)."""

from __future__ import annotations

from agent_threat_mapper.rules import identity_rules
from agent_threat_mapper.rules.base import Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import (
    SUB,
    context,
    intent,
    keyvault,
    role,
    role_on,
    storage,
)

_FORBID_RESOURCES = ["create or delete Azure resources", "modify IAM role assignments"]


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


# --- ATM-IDENTITY-001 ------------------------------------------------------

def test_identity_001_contributor_subscription_scope_fires():
    sa = storage()
    itt = intent(forbidden=_FORBID_RESOURCES)
    ctx = context(storages=[sa], roles=[role("Contributor", scope=f"/subscriptions/{SUB}")])
    findings = identity_rules.broad_role_on_wide_scope(_tm(ctx, itt), itt)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ATM-IDENTITY-001"
    assert f.severity == Severity.CRITICAL
    assert "Contributor" in f.explanation
    assert f"/subscriptions/{SUB}" in f.affected_resources[0]


def test_identity_001_french_forbidden_also_fires():
    sa = storage()
    itt = intent(forbidden=["Modifier ou supprimer des ressources Azure"])
    ctx = context(storages=[sa], roles=[role("Owner", scope=f"/subscriptions/{SUB}")])
    findings = identity_rules.broad_role_on_wide_scope(_tm(ctx, itt), itt)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_identity_001_resource_scope_does_not_fire():
    sa = storage()
    itt = intent(forbidden=_FORBID_RESOURCES)
    ctx = context(storages=[sa], roles=[role_on(sa, "Contributor")])
    assert identity_rules.broad_role_on_wide_scope(_tm(ctx, itt), itt) == []


def test_identity_001_silent_when_intent_allows_modification():
    sa = storage()
    itt = intent(forbidden=["send data outside the tenant"])
    ctx = context(storages=[sa], roles=[role("Contributor", scope=f"/subscriptions/{SUB}")])
    assert identity_rules.broad_role_on_wide_scope(_tm(ctx, itt), itt) == []


# --- ATM-IDENTITY-002 ------------------------------------------------------

def test_identity_002_keyvault_writable_mismatch_fires():
    kv = keyvault(rbac=True)
    itt = intent(forbidden=["write or delete any storage blobs"])
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets Officer")])
    findings = identity_rules.effective_permissions_exceed_intent(_tm(ctx, itt), itt)
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-IDENTITY-002"
    assert findings[0].severity == Severity.HIGH
    assert "atm-kv" in findings[0].explanation


def test_identity_002_skips_storage_owned_by_storage_rules():
    sa = storage()
    itt = intent(forbidden=["write or delete any storage blobs"])
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Contributor")])
    assert identity_rules.effective_permissions_exceed_intent(_tm(ctx, itt), itt) == []


def test_identity_002_silent_when_read_only():
    kv = keyvault(rbac=True)
    itt = intent(forbidden=["write or delete any storage blobs"])
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    assert identity_rules.effective_permissions_exceed_intent(_tm(ctx, itt), itt) == []
