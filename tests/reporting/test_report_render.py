"""Test de rendu : generate_report produit un Markdown valide avec les sections attendues."""

from __future__ import annotations

from pathlib import Path

from agent_threat_mapper.normalization.context_parser import parse_context
from agent_threat_mapper.normalization.intent_parser import parse_intent
from agent_threat_mapper.reporting.formatter import generate_report
from agent_threat_mapper.rules.engine import run_rules
from agent_threat_mapper.threat_model.builder import build_threat_model

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _report() -> str:
    ctx = parse_context(_FIXTURES / "agent_context_sample.json")
    intent = parse_intent(_FIXTURES / "agent_role_sample.txt")
    tm = build_threat_model(ctx, intent)
    findings = run_rules(tm, intent)
    return generate_report(findings, tm, intent, generated_at="2026-06-28")


def test_report_contains_all_sections():
    md = _report()
    for section in (
        "# Security Posture Report",
        "## Executive summary",
        "## ⚠️ Capability mismatch",
        "## Detailed findings",
        "## Methodology",
    ):
        assert section in md


def test_report_header_and_summary():
    md = _report()
    assert "Document Summarization Agent" in md          # intent.name du fixture
    assert "Generated**: 2026-06-28" in md
    assert "high-severity finding" in md                  # phrase de synthèse
    assert "| 🔴 CRITICAL |" in md                          # table de comptes


def test_report_contains_finding_details_and_az_command():
    md = _report()
    assert "ATM-KEYVAULT-001" in md
    assert "[CRITICAL]" in md or "[HIGH]" in md
    assert "az " in md                                    # une commande de mitigation Azure
    assert "OWASP" in md


def test_report_includes_attack_path_for_llm_finding():
    md = _report()
    assert "Attack path(s):" in md
    # le chemin concret user → … → key vault avec B5
    assert "user → agent → llm" in md
    assert "B5" in md


def test_report_methodology_is_deterministic_statement():
    md = _report()
    assert "no LLM, no network calls, no API keys" in md
    assert "**B1**" in md and "**B5**" in md              # boundaries listées
