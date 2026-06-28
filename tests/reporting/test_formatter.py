"""Tests du formatage des findings en données de rapport (sans rendu Jinja2)."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AutonomyLevel
from agent_threat_mapper.reporting.formatter import build_report_data
from agent_threat_mapper.rules.base import Finding, Severity
from agent_threat_mapper.threat_model.builder import build_threat_model
from tests.rules.conftest import context, intent, keyvault, role_on, storage


def _finding(rule_id="ATM-X-001", severity=Severity.HIGH, resources=None, title="t"):
    return Finding(
        rule_id=rule_id, title=title, severity=severity, category="cat",
        explanation="explanation détaillée", mitigation="az do something",
        affected_resources=resources or ["res-1"], owasp_ref="LLM06: Excessive Agency",
    )


def _empty_tm():
    return build_threat_model(context(), intent(name="my-agent", autonomy=AutonomyLevel.SUPERVISED))


# --- comptes & en-tête ------------------------------------------------------

def test_severity_counts_and_header():
    findings = [
        _finding(severity=Severity.CRITICAL), _finding(severity=Severity.HIGH),
        _finding(severity=Severity.HIGH), _finding(severity=Severity.MEDIUM),
    ]
    data = build_report_data(findings, _empty_tm(), intent(name="my-agent"), generated_at="2026-01-01")
    assert data["agent_name"] == "my-agent"
    assert data["generated_at"] == "2026-01-01"
    assert data["total"] == 4
    assert data["severity_counts"] == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


# --- tri par sévérité décroissante ------------------------------------------

def test_findings_sorted_by_severity_desc():
    findings = [
        _finding(rule_id="m", severity=Severity.MEDIUM),
        _finding(rule_id="c", severity=Severity.CRITICAL),
        _finding(rule_id="h", severity=Severity.HIGH),
    ]
    data = build_report_data(findings, _empty_tm(), intent())
    order = [v["severity"] for v in data["findings"]]
    assert order == ["CRITICAL", "HIGH", "MEDIUM"]


def test_repeated_findings_kept_individually():
    findings = [_finding(rule_id="ATM-STORAGE-001", resources=[f"sa-{i}"]) for i in range(3)]
    data = build_report_data(findings, _empty_tm(), intent())
    assert len([v for v in data["findings"] if v["rule_id"] == "ATM-STORAGE-001"]) == 3


# --- capability mismatch en tête --------------------------------------------

def test_capability_mismatch_subset():
    findings = [
        _finding(rule_id="ATM-IDENTITY-002"),
        _finding(rule_id="ATM-KEYVAULT-004"),
        _finding(rule_id="ATM-STORAGE-004"),
        _finding(rule_id="ATM-KEYVAULT-001"),  # pas un mismatch
        _finding(rule_id="ATM-LOGGING-001"),   # pas un mismatch
    ]
    data = build_report_data(findings, _empty_tm(), intent())
    mismatch_ids = {v["rule_id"] for v in data["capability_mismatch"]}
    assert mismatch_ids == {"ATM-IDENTITY-002", "ATM-KEYVAULT-004", "ATM-STORAGE-004"}


# --- phrase de synthèse déterministe ----------------------------------------

def test_summary_sentence_high_severity():
    findings = [_finding(severity=Severity.CRITICAL), _finding(severity=Severity.HIGH)]
    data = build_report_data(findings, _empty_tm(), intent())
    assert "2 high-severity findings requiring immediate remediation" in data["summary_sentence"]


def test_summary_sentence_no_high():
    findings = [_finding(severity=Severity.MEDIUM)]
    data = build_report_data(findings, _empty_tm(), intent())
    assert "No high-severity findings" in data["summary_sentence"]


def test_summary_sentence_no_findings():
    data = build_report_data([], _empty_tm(), intent())
    assert "No findings detected" in data["summary_sentence"]


# --- badges & boundaries ----------------------------------------------------

def test_severity_badges_present():
    data = build_report_data([_finding(severity=Severity.CRITICAL)], _empty_tm(), intent())
    assert "[CRITICAL]" in data["findings"][0]["severity_badge"]


def test_boundaries_present():
    data = build_report_data([], _empty_tm(), intent())
    assert {b["id"] for b in data["boundaries"]} >= {"B1", "B5"}


# --- chemins d'attaque extraits du threat model -----------------------------

def test_attack_paths_populated_for_llm_finding():
    kv = keyvault()
    tm = build_threat_model(context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")]), intent())
    finding = _finding(rule_id="ATM-LLM-001", resources=[kv.resource_id])
    data = build_report_data([finding], tm, intent())
    paths = data["findings"][0]["attack_paths"]
    assert paths
    assert any("user" in p and "llm" in p and "B5" in p for p in paths)


def test_attack_paths_empty_for_non_path_finding():
    kv = keyvault()
    tm = build_threat_model(context(keyvaults=[kv], roles=[role_on(kv, "Key Vault Secrets User")]), intent())
    finding = _finding(rule_id="ATM-KEYVAULT-001", resources=[kv.resource_id])
    data = build_report_data([finding], tm, intent())
    assert data["findings"][0]["attack_paths"] == []
