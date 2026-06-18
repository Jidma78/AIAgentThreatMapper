"""Parse le fichier agent_context.json brut vers les dataclasses de models.azure_resources."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_threat_mapper.models.azure_resources import (
    AgentContext,
    AISearch,
    DiagnosticSettings,
    KeyVault,
    ManagedIdentity,
    RoleAssignment,
    StorageAccount,
)


def parse_context(source: Path | str) -> AgentContext:
    """Parse *source* (fichier ou chaîne JSON) et retourne un AgentContext."""
    if isinstance(source, Path):
        raw: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    else:
        raw = json.loads(source)

    return AgentContext(
        managed_identity=_parse_identity(raw["managed_identity"]),
        role_assignments=[_parse_role(r) for r in raw.get("role_assignments", [])],
        key_vaults=[_parse_keyvault(kv) for kv in raw.get("key_vaults", [])],
        storage_accounts=[_parse_storage(s) for s in raw.get("storage_accounts", [])],
        ai_search_services=[_parse_search(a) for a in raw.get("ai_search_services", [])],
        diagnostic_settings=[_parse_diag(d) for d in raw.get("diagnostic_settings", [])],
    )


def _parse_identity(d: dict[str, Any]) -> ManagedIdentity:
    return ManagedIdentity(
        principal_id=d["principal_id"],
        client_id=d["client_id"],
        tenant_id=d["tenant_id"],
        object_id=d["object_id"],
        resource_id=d["resource_id"],
    )


def _parse_role(d: dict[str, Any]) -> RoleAssignment:
    return RoleAssignment(
        role_definition_name=d["role_definition_name"],
        role_definition_id=d["role_definition_id"],
        scope=d["scope"],
        principal_id=d["principal_id"],
        assignment_id=d["assignment_id"],
    )


def _parse_keyvault(d: dict[str, Any]) -> KeyVault:
    return KeyVault(
        name=d["name"],
        resource_id=d["resource_id"],
        resource_group=d["resource_group"],
        location=d["location"],
        network_acls_default_action=d["network_acls_default_action"],
        enabled_for_disk_encryption=bool(d["enabled_for_disk_encryption"]),
        soft_delete_enabled=bool(d["soft_delete_enabled"]),
        purge_protection_enabled=bool(d["purge_protection_enabled"]),
        enable_rbac_authorization=d.get("enable_rbac_authorization"),
    )


def _parse_storage(d: dict[str, Any]) -> StorageAccount:
    return StorageAccount(
        name=d["name"],
        resource_id=d["resource_id"],
        resource_group=d["resource_group"],
        location=d["location"],
        allow_blob_public_access=bool(d["allow_blob_public_access"]),
        https_only=bool(d["https_only"]),
        network_acls_default_action=d["network_acls_default_action"],
        kind=d["kind"],
        sku_name=d["sku_name"],
    )


def _parse_search(d: dict[str, Any]) -> AISearch:
    return AISearch(
        name=d["name"],
        resource_id=d["resource_id"],
        resource_group=d["resource_group"],
        location=d["location"],
        sku_name=d["sku_name"],
        public_network_access=d["public_network_access"],
        replica_count=int(d["replica_count"]),
    )


def _parse_diag(d: dict[str, Any]) -> DiagnosticSettings:
    return DiagnosticSettings(
        resource_id=d["resource_id"],
        name=d["name"],
        workspace_id=d.get("workspace_id"),
        storage_account_id=d.get("storage_account_id"),
        log_categories=list(d.get("log_categories", [])),
        enabled=bool(d["enabled"]),
    )
