"""Tests du moteur exécutant l'ensemble des règles enregistrées."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_threat_mapper.models.agent_intent import AutonomyLevel
from agent_threat_mapper.normalization.context_parser import parse_context
from agent_threat_mapper.normalization.intent_parser import parse_intent
from agent_threat_mapper.rules.base import Finding, Severity
from agent_threat_mapper.rules.engine import _deduplicate, run_rules
from agent_threat_mapper.rules.registry import REGISTERED_RULES
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import SUB, context, intent, keyvault, role, role_on, storage

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "tests" / "fixtures"


def _tm(ctx, itt):
    return build_threat_model(ctx, itt)


# --- Registry & agrégation -------------------------------------------------

def test_registry_non_empty_and_callable():
    assert REGISTERED_RULES
    assert all(callable(r) for r in REGISTERED_RULES)


def test_run_rules_returns_findings():
    kv = keyvault()
    itt = intent(forbidden=["Accéder à des secrets de production"])
    ctx = context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")])
    findings = run_rules(_tm(ctx, itt), itt)
    assert all(isinstance(f, Finding) for f in findings)
    ids = {f.rule_id for f in findings}
    assert "ATM-KEYVAULT-004" in ids  # secrets interdits + accessibles


# --- Déduplication ---------------------------------------------------------

def test_deduplicate_collapses_same_rule_and_resources():
    f1 = Finding("ATM-X", "t", Severity.HIGH, "c", "e", "m", affected_resources=["a", "b"])
    f2 = Finding("ATM-X", "t", Severity.HIGH, "c", "e2", "m2", affected_resources=["b", "a"])  # même clé (ordre inversé)
    f3 = Finding("ATM-X", "t", Severity.HIGH, "c", "e", "m", affected_resources=["a"])  # clé différente
    out = _deduplicate([f1, f2, f3])
    assert len(out) == 2


def test_run_rules_output_has_no_duplicate_keys():
    kv = keyvault()
    itt = intent(forbidden=["create or delete Azure resources"])
    ctx = context(keyvaults=[kv], roles=[role("Contributor", scope=f"/subscriptions/{SUB}")])
    findings = run_rules(_tm(ctx, itt), itt)
    keys = [(f.rule_id, tuple(sorted(f.affected_resources))) for f in findings]
    assert len(keys) == len(set(keys))


# --- Anti-faux-positif sur le radical creat/créer (ajustement 1) ------------

def test_allowed_creation_action_never_triggers_mismatch():
    # "create support tickets" est une action LÉGITIME listée dans allowed → aucun mismatch.
    kv = keyvault(rbac=True)
    sa = storage()
    itt = intent(
        allowed=["create support tickets", "write summaries"],
        forbidden=["send data outside the tenant"],
    )
    ctx = context(
        keyvaults=[kv], storages=[sa],
        roles=[role_on(kv, "Key Vault Secrets Officer"), role_on(sa, "Storage Blob Data Contributor")],
    )
    ids = {f.rule_id for f in run_rules(_tm(ctx, itt), itt)}
    assert "ATM-IDENTITY-002" not in ids
    assert "ATM-STORAGE-004" not in ids
    assert "ATM-KEYVAULT-004" not in ids


def test_forbidden_create_or_delete_triggers_identity_001():
    sa = storage()
    itt = intent(forbidden=["create or delete Azure resources"])
    ctx = context(storages=[sa], roles=[role("Contributor", scope=f"/subscriptions/{SUB}")])
    ids = {f.rule_id for f in run_rules(_tm(ctx, itt), itt)}
    assert "ATM-IDENTITY-001" in ids


# --- Intégration sur les fixtures synthétiques -----------------------------

def test_integration_on_sample_fixtures():
    ctx = parse_context(_FIXTURES / "agent_context_sample.json")
    itt = parse_intent(_FIXTURES / "agent_role_sample.txt")
    findings = run_rules(build_threat_model(ctx, itt), itt)
    ids = {f.rule_id for f in findings}

    expected = {
        "ATM-IDENTITY-001",   # Contributor @ subscription + interdit create/delete
        "ATM-KEYVAULT-001",   # network Allow
        "ATM-KEYVAULT-002",   # purge protection off
        "ATM-LOGGING-001",    # storage + AI Search sans diagnostics
        "ATM-LLM-001",        # chemin user → key vault
    }
    assert expected <= ids
    # le storage du fixture n'est pas inscriptible (Reader + Contributor management) → aucune règle storage
    assert not any(rid.startswith("ATM-STORAGE") for rid in ids)
    # tous les findings sont concrets
    for f in findings:
        assert f.explanation and f.mitigation


# --- Smoke test sur les données réelles (ajustement 2) ---------------------

def test_smoke_run_rules_on_real_data_does_not_raise():
    real_ctx = _REPO_ROOT / "agent_context.json"
    real_role = _REPO_ROOT / "agent_role.txt"
    if not (real_ctx.exists() and real_role.exists()):
        pytest.skip("données réelles absentes (agent_context.json / agent_role.txt)")
    ctx = parse_context(real_ctx)
    itt = parse_intent(real_role)
    tm = build_threat_model(ctx, itt)
    findings = run_rules(tm, itt)  # ne doit lever aucune exception sur la vraie topologie
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)
