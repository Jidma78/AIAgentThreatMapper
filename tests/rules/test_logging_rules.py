"""Tests des règles de logging/diagnostic settings."""

from __future__ import annotations

from agent_threat_mapper.rules import logging_rules
from agent_threat_mapper.rules.base import Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, diag_for, intent, keyvault, role_on, storage


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


def test_storage_without_diagnostics_fires_medium():
    sa = storage()
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Reader")])
    findings = logging_rules.resource_without_diagnostics(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-LOGGING-001"
    assert findings[0].severity == Severity.MEDIUM


def test_keyvault_without_diagnostics_fires_high():
    kv = keyvault()
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = logging_rules.resource_without_diagnostics(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_resource_with_diagnostics_silent():
    kv = keyvault()
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")], diags=[diag_for(kv)])
    assert logging_rules.resource_without_diagnostics(_tm(ctx, intent()), intent()) == []


def test_inaccessible_resource_not_flagged():
    sa = storage()
    ctx = context(storages=[sa], roles=[])  # aucun rôle → non accessible
    assert logging_rules.resource_without_diagnostics(_tm(ctx, intent()), intent()) == []
