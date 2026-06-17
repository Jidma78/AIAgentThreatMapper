# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

AgentThreatMapper is a Python CLI tool that analyzes the security posture of an AI agent deployed on Azure by comparing:

- what the agent is **supposed to do** (its declared business intent, from a text file);
- what its cloud identity **can actually do** (its real Azure IAM permissions).

## Current status

This repository is a freshly scaffolded skeleton. Every module under `src/agent_threat_mapper/` currently contains only a one-line docstring describing its purpose — no business logic is implemented yet, and `pyproject.toml` declares no dependencies. When implementing a stage, add the dependencies it needs (e.g. a CLI framework for `cli.py`, Jinja2 for `reporting/`) to `pyproject.toml` as you go.

## Commands

- Install in editable mode: `pip install -e .`
- Run the CLI (entry point `atm`, currently raises `NotImplementedError` in `cli.py`): `atm`
- Tests follow pytest naming conventions (`tests/**/test_*.py`) but pytest is not yet declared as a dependency — add it (`pip install pytest`, then add to `pyproject.toml`) before running `pytest` or `pytest tests/path/to/test_file.py::test_name` for a single test.

## Architecture: pipeline stages map directly to packages

The tool's design is a 5-stage pipeline, and each stage corresponds to one package under `src/agent_threat_mapper/`. When extending the tool, identify which stage you're working on and you'll know exactly where the code belongs:

1. **`azure_export/`** — Stage 1: orchestrates `az` CLI calls (managed identity, role assignments, resource group resources, Key Vault, Storage, Azure AI Search, diagnostic settings) and assembles the raw `agent_context.json` export. `exporter.py` orchestrates; `az_commands.py` wraps individual `az` invocations.

2. **`normalization/` + `models/`** — Stage 2: `normalization/context_parser.py` parses raw `agent_context.json` into the dataclasses defined in `models/azure_resources.py` (ManagedIdentity, RoleAssignment, KeyVault, StorageAccount, AISearch, DiagnosticSettings). `normalization/intent_parser.py` parses the agent's business-role text file (allowed/forbidden actions, autonomy level) into `models/agent_intent.py`.

3. **`threat_model/`** — Stage 3: `builder.py` consumes the normalized Azure resources and agent intent to construct the data-flow graph defined in `models/threat_model.py` — nodes for user → agent → LLM → RAG → tools → Azure resources → logs, plus edges and trust boundaries. This is where untrusted entry points are identified.

4. **`rules/`** — Stage 4: a deterministic rules engine inspired by the OWASP LLM Top 10 and Azure IAM best practices, evaluated against the threat model from stage 3.
   - `base.py` defines the `Rule` interface and the `Finding` dataclass (title, severity, explanation, mitigation) — the contract every rule conforms to.
   - `registry.py` collects rule modules; `engine.py` runs all registered rules and collects `Finding`s.
   - Rule categories live in their own modules: `identity_rules.py` (excessive Owner/Contributor roles, capability mismatch between declared intent and actual permissions), `keyvault_rules.py` (Key Vault without network restrictions), `storage_rules.py` (Storage that could poison a RAG pipeline), `logging_rules.py` (missing diagnostic settings), `llm_rules.py` (excessive agency, prompt-injection impact paths).
   - **To add a new rule**: add a function/class to the relevant module (or a new module) and register it in `registry.py` — `engine.py` and `cli.py` should not need to change.

5. **`reporting/`** — Stage 5: `formatter.py` turns the list of `Finding`s into structured report data, rendered via the Jinja2 template `templates/report.md.j2` into a human-readable Markdown report (title, severity, explanation, mitigation per finding).

`cli.py` is the thin entry point (`atm` command) dispatching to subcommands across these stages.

## Key design constraints

- **Avoid circular imports**: `models/` holds all shared dataclasses (Azure resources, agent intent, threat model graph) and has no dependencies on other `agent_threat_mapper` packages. `normalization/`, `threat_model/`, and `rules/` all depend on `models/`, never the reverse.
- **`tests/` mirrors `src/agent_threat_mapper/`** package-for-package. `tests/fixtures/` holds `agent_context_sample.json` and `agent_role_sample.txt` so stages 2–5 can be tested offline without live Azure access (only stage 1, `azure_export/`, requires `az` authentication).
