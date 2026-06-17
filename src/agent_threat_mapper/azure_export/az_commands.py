"""Wrappers autour des commandes `az` individuelles : identité managée, role assignments, Key Vault, Storage, AI Search, diagnostic settings."""

import json
import subprocess
from typing import Any


def run_az(args: list[str]) -> Any:
    """Exécute une commande `az` et retourne sa sortie JSON parsée."""
    result = subprocess.run(
        ["az", *args, "--output", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None


def get_managed_identity(identity_id: str) -> dict:
    """Retourne les détails d'une identité managée (user-assigned) via son resource ID."""
    return run_az(["identity", "show", "--ids", identity_id])


def get_role_assignments(principal_id: str) -> list[dict]:
    """Liste les role assignments Azure RBAC pour un principal (ex. l'identité managée de l'agent)."""
    return run_az(["role", "assignment", "list", "--assignee", principal_id, "--all"])


def list_resource_group_resources(resource_group: str) -> list[dict]:
    """Liste toutes les ressources d'un resource group."""
    return run_az(["resource", "list", "--resource-group", resource_group])


def get_key_vault(name: str, resource_group: str) -> dict:
    """Retourne les détails d'un Key Vault, y compris ses network ACLs."""
    return run_az(["keyvault", "show", "--name", name, "--resource-group", resource_group])


def get_storage_account(name: str, resource_group: str) -> dict:
    """Retourne les détails d'un compte Storage, y compris ses règles réseau."""
    return run_az(["storage", "account", "show", "--name", name, "--resource-group", resource_group])


def get_ai_search_service(name: str, resource_group: str) -> dict:
    """Retourne les détails d'un service Azure AI Search."""
    return run_az(["search", "service", "show", "--name", name, "--resource-group", resource_group])


def list_resources_in_subscription(subscription_id: str) -> list[dict]:
    """Liste toutes les ressources d'une subscription Azure."""
    return run_az(["resource", "list", "--subscription", subscription_id])


def get_diagnostic_settings(resource_id: str) -> list[dict]:
    """Liste les diagnostic settings configurés pour une ressource."""
    result = run_az(["monitor", "diagnostic-settings", "list", "--resource", resource_id])
    return result.get("value", []) if result else []
