"""Tests des règles Key Vault (réseau, protections, accès secrets)."""

from __future__ import annotations

from agent_threat_mapper.rules import keyvault_rules
from agent_threat_mapper.rules.base import Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, intent, keyvault, role_on


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


# --- ATM-KEYVAULT-001 réseau ----------------------------------------------

def test_keyvault_network_open_fires():
    kv = keyvault(network="Allow")
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = keyvault_rules.keyvault_network_open(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-KEYVAULT-001"
    assert findings[0].severity == Severity.HIGH
    assert "atm-kv" in findings[0].explanation
    assert "az keyvault update" in findings[0].mitigation


def test_keyvault_network_deny_does_not_fire():
    kv = keyvault(network="Deny")
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    assert keyvault_rules.keyvault_network_open(_tm(ctx, intent()), intent()) == []


def test_keyvault_network_open_but_inaccessible_does_not_fire():
    kv = keyvault(network="Allow")
    ctx = context(keyvaults=[kv], roles=[])  # aucun rôle → non accessible
    assert keyvault_rules.keyvault_network_open(_tm(ctx, intent()), intent()) == []


# --- ATM-KEYVAULT-002 / 003 protections -----------------------------------

def test_keyvault_no_purge_protection_fires_medium():
    kv = keyvault(purge=False)
    findings = keyvault_rules.keyvault_no_purge_protection(_tm(context(keyvaults=[kv]), intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-KEYVAULT-002"
    assert findings[0].severity == Severity.MEDIUM


def test_keyvault_purge_protection_enabled_silent():
    kv = keyvault(purge=True)
    assert keyvault_rules.keyvault_no_purge_protection(_tm(context(keyvaults=[kv]), intent()), intent()) == []


def test_keyvault_no_soft_delete_fires():
    kv = keyvault(soft_delete=False)
    findings = keyvault_rules.keyvault_no_soft_delete(_tm(context(keyvaults=[kv]), intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-KEYVAULT-003"


def test_keyvault_soft_delete_enabled_silent():
    kv = keyvault(soft_delete=True)
    assert keyvault_rules.keyvault_no_soft_delete(_tm(context(keyvaults=[kv]), intent()), intent()) == []


# --- ATM-KEYVAULT-004 accès secrets interdit -------------------------------

def test_keyvault_secrets_forbidden_fires_critical():
    kv = keyvault()
    itt = intent(forbidden=["Accéder à des secrets de production"])
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = keyvault_rules.keyvault_secrets_access_forbidden(_tm(ctx, itt), itt)
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-KEYVAULT-004"
    assert findings[0].severity == Severity.CRITICAL


def test_keyvault_secrets_allowed_silent():
    kv = keyvault()
    itt = intent(allowed=["retrieve secrets from Key Vault"], forbidden=["write storage"])
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    assert keyvault_rules.keyvault_secrets_access_forbidden(_tm(ctx, itt), itt) == []
