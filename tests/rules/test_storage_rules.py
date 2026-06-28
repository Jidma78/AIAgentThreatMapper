"""Tests des règles Storage (risque d'empoisonnement RAG)."""

from __future__ import annotations

from agent_threat_mapper.rules import storage_rules
from agent_threat_mapper.rules.base import Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, intent, role_on, storage

_CONTRIB = "Storage Blob Data Contributor"
_READER = "Storage Blob Data Reader"


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


# --- ATM-STORAGE-001 réseau ouvert + writable ------------------------------

def test_storage_network_open_writable_fires():
    sa = storage(network="Allow")
    ctx = context(storages=[sa], roles=[role_on(sa, _CONTRIB)])
    findings = storage_rules.storage_network_open_writable(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-STORAGE-001"
    assert findings[0].severity == Severity.HIGH


def test_storage_network_open_but_read_only_does_not_fire():
    sa = storage(network="Allow")
    ctx = context(storages=[sa], roles=[role_on(sa, _READER)])
    assert storage_rules.storage_network_open_writable(_tm(ctx, intent()), intent()) == []


def test_storage_network_deny_does_not_fire():
    sa = storage(network="Deny")
    ctx = context(storages=[sa], roles=[role_on(sa, _CONTRIB)])
    assert storage_rules.storage_network_open_writable(_tm(ctx, intent()), intent()) == []


# --- ATM-STORAGE-002 public blob -------------------------------------------

def test_storage_public_blob_access_fires():
    sa = storage(public_blob=True)
    findings = storage_rules.storage_public_blob_access(_tm(context(storages=[sa]), intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-STORAGE-002"
    assert findings[0].severity == Severity.HIGH


def test_storage_no_public_blob_silent():
    sa = storage(public_blob=False)
    assert storage_rules.storage_public_blob_access(_tm(context(storages=[sa]), intent()), intent()) == []


# --- ATM-STORAGE-003 https only --------------------------------------------

def test_storage_no_https_only_fires_medium():
    sa = storage(https_only=False)
    findings = storage_rules.storage_no_https_only(_tm(context(storages=[sa]), intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-STORAGE-003"
    assert findings[0].severity == Severity.MEDIUM


def test_storage_https_only_silent():
    sa = storage(https_only=True)
    assert storage_rules.storage_no_https_only(_tm(context(storages=[sa]), intent()), intent()) == []


# --- ATM-STORAGE-004 capability mismatch -----------------------------------

def test_storage_writable_forbidden_fires():
    sa = storage()
    itt = intent(forbidden=["write or delete any storage blobs"])
    ctx = context(storages=[sa], roles=[role_on(sa, _CONTRIB)])
    findings = storage_rules.storage_writable_forbidden(_tm(ctx, itt), itt)
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-STORAGE-004"
    assert findings[0].severity == Severity.HIGH


def test_storage_writable_forbidden_french():
    sa = storage()
    itt = intent(forbidden=["Écrire dans le stockage"])
    ctx = context(storages=[sa], roles=[role_on(sa, _CONTRIB)])
    assert len(storage_rules.storage_writable_forbidden(_tm(ctx, itt), itt)) == 1


def test_storage_writable_but_write_not_forbidden_silent():
    # écriture autorisée par l'intention (rien d'interdit côté write) → pas de mismatch
    sa = storage()
    itt = intent(allowed=["write summaries to storage"], forbidden=["send data outside the tenant"])
    ctx = context(storages=[sa], roles=[role_on(sa, _CONTRIB)])
    assert storage_rules.storage_writable_forbidden(_tm(ctx, itt), itt) == []
