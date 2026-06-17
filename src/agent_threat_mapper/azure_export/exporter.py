"""Orchestre les appels `az` et assemble le fichier agent_context.json structuré."""

from __future__ import annotations

import json
import subprocess
import warnings
from pathlib import Path
from typing import Any

from agent_threat_mapper.azure_export import az_commands
from agent_threat_mapper.models.azure_resources import AgentContext
from agent_threat_mapper.normalization.context_parser import parse_context

_RELEVANT_TYPES = frozenset({
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.search/searchservices",
})


# ---------------------------------------------------------------------------
# Parsing et classification
# ---------------------------------------------------------------------------

def _parse_identity_resource_id(resource_id: str) -> tuple[str, str]:
    """Retourne (subscription_id, resource_group) depuis le resource ID de l'identité.

    Raises ValueError si le format ne correspond pas à un managed identity resource ID.
    """
    parts = resource_id.strip("/").split("/")
    if (
        len(parts) < 8
        or parts[0].lower() != "subscriptions"
        or parts[2].lower() != "resourcegroups"
    ):
        raise ValueError(
            f"Resource ID malformé : {resource_id!r}\n"
            "Format attendu : /subscriptions/{sub}/resourceGroups/{rg}"
            "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"
        )
    return parts[1], parts[3]


def _classify_scope(scope: str) -> str:
    """Retourne 'subscription', 'resource_group', ou 'resource' selon le scope."""
    parts = scope.strip("/").split("/")
    if len(parts) == 2:
        return "subscription"
    if len(parts) == 4:
        return "resource_group"
    return "resource"


def _infer_type_from_id(resource_id: str) -> str:
    """Extrait le type Azure (ex. 'Microsoft.KeyVault/vaults') depuis un resource ID."""
    parts = resource_id.strip("/").split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "providers")
        return f"{parts[idx + 1]}/{parts[idx + 2]}"
    except (StopIteration, IndexError):
        return ""


# ---------------------------------------------------------------------------
# Découverte des ressources par scope
# ---------------------------------------------------------------------------

def _collect_resources_for_scope(scope: str, subscription_id: str) -> list[dict]:
    """Retourne la liste brute des ressources couvertes par ce scope.

    Pour un scope de niveau resource, retourne un dict synthétique minimal.
    La ressource sera ensuite enrichie par get_key_vault / get_storage_account /
    get_ai_search_service exactement comme toute ressource découverte par liste.
    """
    level = _classify_scope(scope)
    if level == "subscription":
        return az_commands.list_resources_in_subscription(subscription_id) or []
    if level == "resource_group":
        rg = scope.strip("/").split("/")[3]
        return az_commands.list_resource_group_resources(rg) or []
    # Niveau ressource : la ressource est directement identifiée par le scope.
    rtype = _infer_type_from_id(scope)
    name = scope.strip("/").split("/")[-1]
    return [{"id": scope, "type": rtype, "name": name}]


# ---------------------------------------------------------------------------
# Mapping Azure CLI camelCase → snake_case JSON
# ---------------------------------------------------------------------------

def _map_managed_identity(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "principal_id": raw.get("principalId", ""),
        "client_id": raw.get("clientId", ""),
        "tenant_id": raw.get("tenantId", ""),
        "object_id": raw.get("principalId", ""),
        "resource_id": raw.get("id", ""),
    }


def _map_role_assignment(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "role_definition_name": raw.get("roleDefinitionName", ""),
        "role_definition_id": raw.get("roleDefinitionId", ""),
        "scope": raw.get("scope", ""),
        "principal_id": raw.get("principalId", ""),
        "assignment_id": raw.get("id", ""),
    }


def _map_key_vault(raw: dict[str, Any]) -> dict[str, Any]:
    props = raw.get("properties") or {}
    network_acls = props.get("networkAcls") or {}
    return {
        "name": raw.get("name", ""),
        "resource_id": raw.get("id", ""),
        "resource_group": raw.get("resourceGroup", ""),
        "location": raw.get("location", ""),
        "network_acls_default_action": network_acls.get("defaultAction", "Allow"),
        "enabled_for_disk_encryption": bool(props.get("enabledForDiskEncryption")),
        "soft_delete_enabled": bool(props.get("enableSoftDelete")),
        "purge_protection_enabled": bool(props.get("enablePurgeProtection") or False),
    }


def _map_storage_account(raw: dict[str, Any]) -> dict[str, Any]:
    network_rule_set = raw.get("networkRuleSet") or {}
    sku = raw.get("sku") or {}
    https_only_value = raw.get("enableHttpsTrafficOnly")
    if https_only_value is None:
        https_only_value = raw.get("supportsHttpsTrafficOnly", False)
    return {
        "name": raw.get("name", ""),
        "resource_id": raw.get("id", ""),
        "resource_group": raw.get("resourceGroup", ""),
        "location": raw.get("location", ""),
        "allow_blob_public_access": bool(raw.get("allowBlobPublicAccess", False)),
        "https_only": bool(https_only_value),
        "network_acls_default_action": network_rule_set.get("defaultAction", "Allow"),
        "kind": raw.get("kind", ""),
        "sku_name": sku.get("name", ""),
    }


def _map_ai_search(raw: dict[str, Any]) -> dict[str, Any]:
    sku = raw.get("sku") or {}
    # publicNetworkAccess / replicaCount peuvent être sous properties ou à la racine
    props = raw.get("properties") or raw
    return {
        "name": raw.get("name", ""),
        "resource_id": raw.get("id", ""),
        "resource_group": raw.get("resourceGroup", ""),
        "location": raw.get("location", ""),
        "sku_name": sku.get("name", ""),
        "public_network_access": props.get("publicNetworkAccess", "Enabled"),
        "replica_count": int(props.get("replicaCount", 1)),
    }


def _map_diagnostic_settings(raw: dict[str, Any], resource_id: str) -> dict[str, Any]:
    logs = raw.get("logs") or []
    log_categories = [
        log["category"]
        for log in logs
        if log.get("enabled") and log.get("category")
    ]
    enabled = any(log.get("enabled", False) for log in logs)
    return {
        "resource_id": resource_id,
        "name": raw.get("name", ""),
        "workspace_id": raw.get("workspaceId"),
        "storage_account_id": raw.get("storageAccountId"),
        "log_categories": log_categories,
        "enabled": enabled,
    }


# ---------------------------------------------------------------------------
# Gestion des erreurs az CLI
# ---------------------------------------------------------------------------

def _wrap_az_error(exc: subprocess.CalledProcessError, context: str) -> RuntimeError:
    stderr = (exc.stderr or "").strip()
    if any(kw in stderr for kw in ("does not exist", "was not found", "ResourceNotFound")):
        return RuntimeError(f"Ressource introuvable : {context}")
    if any(kw in stderr for kw in ("AuthorizationFailed", "Forbidden", "403")):
        return RuntimeError(f"Accès refusé : {context}")
    return RuntimeError(f"Erreur az ({context}) : {stderr}")


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

def export_agent_context(identity_resource_id: str, output_path: Path) -> AgentContext:
    """Exporte le contexte Azure de l'agent et retourne un AgentContext validé.

    Parameters
    ----------
    identity_resource_id:
        Resource ID complet de l'identité managée user-assigned.
    output_path:
        Fichier de sortie JSON (ex. agent_context.json).

    Raises
    ------
    ValueError
        Si le resource ID est malformé.
    RuntimeError
        Si une erreur Azure empêche la récupération de l'identité ou des rôles.
    """
    # 1. Valider et extraire subscription_id avant tout appel az
    subscription_id, _ = _parse_identity_resource_id(identity_resource_id)

    # 2. Identité managée
    try:
        raw_identity = az_commands.get_managed_identity(identity_resource_id)
    except subprocess.CalledProcessError as exc:
        raise _wrap_az_error(exc, identity_resource_id) from exc

    principal_id = raw_identity.get("principalId", "")

    # 3. Role assignments
    try:
        raw_roles = az_commands.get_role_assignments(principal_id) or []
    except subprocess.CalledProcessError as exc:
        raise _wrap_az_error(exc, f"role assignments de {principal_id}") from exc

    # 4. Découvrir les ressources sur tous les scopes uniques (déduplication par id)
    scopes = list({r.get("scope", "") for r in raw_roles if r.get("scope")})
    seen_ids: set[str] = set()
    all_resources: list[dict] = []
    for scope in scopes:
        try:
            candidates = _collect_resources_for_scope(scope, subscription_id)
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            warnings.warn(f"Impossible de lister les ressources pour le scope {scope!r} : {stderr}")
            continue
        for res in candidates:
            rid = (res.get("id") or "").lower()
            if rid and rid not in seen_ids:
                seen_ids.add(rid)
                all_resources.append(res)

    # 5. Filtrer les trois types pertinents (comparaison insensible à la casse)
    relevant = [
        r for r in all_resources
        if (r.get("type") or "").lower() in _RELEVANT_TYPES
    ]

    # 6. Enrichir chaque ressource et récupérer ses diagnostic settings
    key_vaults: list[dict] = []
    storage_accounts: list[dict] = []
    ai_search_services: list[dict] = []
    diagnostic_settings: list[dict] = []

    for res in relevant:
        rtype = (res.get("type") or "").lower()
        name = res.get("name") or (res.get("id", "").strip("/").split("/")[-1])
        res_id = res.get("id", "")
        res_rg = res.get("resourceGroup") or (
            res_id.strip("/").split("/")[3] if res_id else ""
        )

        try:
            if rtype == "microsoft.keyvault/vaults":
                raw = az_commands.get_key_vault(name, res_rg)
                key_vaults.append(_map_key_vault(raw))
                for d in az_commands.get_diagnostic_settings(res_id):
                    diagnostic_settings.append(_map_diagnostic_settings(d, res_id))

            elif rtype == "microsoft.storage/storageaccounts":
                raw = az_commands.get_storage_account(name, res_rg)
                storage_accounts.append(_map_storage_account(raw))
                for d in az_commands.get_diagnostic_settings(res_id):
                    diagnostic_settings.append(_map_diagnostic_settings(d, res_id))

            elif rtype == "microsoft.search/searchservices":
                raw = az_commands.get_ai_search_service(name, res_rg)
                ai_search_services.append(_map_ai_search(raw))
                for d in az_commands.get_diagnostic_settings(res_id):
                    diagnostic_settings.append(_map_diagnostic_settings(d, res_id))

        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            warnings.warn(f"Impossible de récupérer {name} ({res_rg}) : {stderr}")

    # 7. Assembler et écrire le JSON snake_case
    context_dict: dict[str, Any] = {
        "managed_identity": _map_managed_identity(raw_identity),
        "role_assignments": [_map_role_assignment(r) for r in raw_roles],
        "key_vaults": key_vaults,
        "storage_accounts": storage_accounts,
        "ai_search_services": ai_search_services,
        "diagnostic_settings": diagnostic_settings,
    }
    output_path.write_text(json.dumps(context_dict, indent=2), encoding="utf-8")

    # 8. Round-trip parse — valide le mapping et retourne un AgentContext typé
    return parse_context(output_path)
