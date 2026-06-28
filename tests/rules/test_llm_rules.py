"""Tests des règles de chemins d'attaque LLM (prompt injection, RAG poisoning, autonomie)."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AutonomyLevel
from agent_threat_mapper.rules import llm_rules
from agent_threat_mapper.rules.base import Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, intent, keyvault, role_on, storage


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


# --- ATM-LLM-001 prompt injection → Key Vault ------------------------------

def test_llm_001_user_path_to_keyvault_fires():
    kv = keyvault()
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = llm_rules.prompt_injection_path_to_keyvault(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-LLM-001"
    assert findings[0].severity == Severity.HIGH
    assert "atm-kv" in findings[0].explanation


def test_llm_001_no_keyvault_no_finding():
    sa = storage()
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Reader")])
    assert llm_rules.prompt_injection_path_to_keyvault(_tm(ctx, intent()), intent()) == []


# --- ATM-LLM-002 RAG poisoning → storage writable --------------------------

def test_llm_002_rag_path_to_writable_storage_fires():
    # config B : storage source RAG + inscriptible → chemin depuis rag franchissant B5
    sa = storage()
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Contributor")])
    findings = llm_rules.rag_poisoning_path_to_writable_storage(_tm(ctx, intent()), intent())
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-LLM-002"
    assert findings[0].severity == Severity.HIGH


def test_llm_002_read_only_storage_no_finding():
    sa = storage()
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Reader")])
    assert llm_rules.rag_poisoning_path_to_writable_storage(_tm(ctx, intent()), intent()) == []


# --- ATM-LLM-003 autonomie + ressources critiques --------------------------

def test_llm_003_autonomous_with_keyvault_fires():
    kv = keyvault()
    itt = intent(autonomy=AutonomyLevel.AUTONOMOUS)
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = llm_rules.autonomous_agent_critical_access(_tm(ctx, itt), itt)
    assert len(findings) == 1
    assert findings[0].rule_id == "ATM-LLM-003"
    assert findings[0].severity == Severity.HIGH
    assert "atm-kv" in findings[0].affected_resources[0]


def test_llm_003_supervised_agent_silent():
    kv = keyvault()
    itt = intent(autonomy=AutonomyLevel.SUPERVISED)
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    assert llm_rules.autonomous_agent_critical_access(_tm(ctx, itt), itt) == []


def test_llm_003_autonomous_without_critical_resource_silent():
    # storage à réseau fermé, pas de key vault → pas de ressource critique
    sa = storage(network="Deny")
    itt = intent(autonomy=AutonomyLevel.AUTONOMOUS)
    ctx = context(storages=[sa], roles=[role_on(sa, "Storage Blob Data Reader")])
    assert llm_rules.autonomous_agent_critical_access(_tm(ctx, itt), itt) == []
