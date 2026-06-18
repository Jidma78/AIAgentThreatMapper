"""Interprétation des rôles built-in Azure les plus courants vers leurs permissions effectives.

CONNAISSANCE DOMAINE PURE (pas une règle de sécurité) : ce module ne produit aucun Finding et ne
consulte pas le ThreatModel. Il vit dans models/ pour être importé indifféremment par le builder
du stage 3 ET les règles du stage 4, sans inversion de dépendance (tous deux dépendent de models/).
Fonctions pures, déterministes, testables sans mock Azure.

LIMITES DE COUVERTURE (assumées) :
- Seuls les rôles built-in listés dans `_BUILTIN` sont interprétés. Un rôle custom (ou hors liste)
  retourne des permissions vides marquées `ambiguous=True`.
- Le chemin d'escalade Storage via régénération des clés de compte (Contributor → clés partagées
  → accès data-plane complet) N'EST PAS modélisé : Contributor sur Storage est traité comme
  management-plane seul, conformément au périmètre minimal.
- Le comportement Key Vault dépend du mode d'autorisation (`enableRbacAuthorization`) — voir
  `_contributor_keyvault` pour la résolution des trois cas (True / False / None).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from agent_threat_mapper.models.azure_resources import RoleAssignment
from agent_threat_mapper.models.threat_model import ResourceType


@dataclass(frozen=True)
class EffectivePermissions:
    """Permissions effectives d'un (ou plusieurs) rôle(s) sur une ressource."""

    can_read_data: bool = False        # lire les valeurs/contenus (blobs, valeurs de secrets, documents d'index)
    can_write_data: bool = False       # créer / modifier les données
    can_delete_data: bool = False      # supprimer les données
    can_list_metadata: bool = False    # énumérer noms/métadonnées (ex. lister les secrets) — vecteur de reconnaissance
    can_manage_resource: bool = False  # gestion ARM de la ressource (management-plane)
    ambiguous: bool = False            # effet data-plane dépendant du contexte (ex. Key Vault access-policy)
    notes: str = ""                    # explication (ambiguïté, limites)


_READER = EffectivePermissions(can_read_data=True, can_list_metadata=True)
_DATA_CONTRIBUTOR = EffectivePermissions(
    can_read_data=True, can_write_data=True, can_delete_data=True, can_list_metadata=True
)

# Table des rôles built-in couverts (clé = nom de rôle normalisé en minuscules).
_BUILTIN: dict[str, EffectivePermissions] = {
    # --- Storage (data-plane blobs) ---
    "storage blob data reader": _READER,
    "storage blob data contributor": _DATA_CONTRIBUTOR,
    "storage blob data owner": replace(
        _DATA_CONTRIBUTOR, notes="inclut la gestion des ACL POSIX sur les blobs"
    ),
    # --- Key Vault (data-plane secrets) ---
    "key vault secrets user": EffectivePermissions(can_read_data=True, can_list_metadata=True),
    "key vault secrets officer": _DATA_CONTRIBUTOR,
    "key vault reader": EffectivePermissions(
        can_list_metadata=True,  # liste les noms/métadonnées des secrets…
        can_read_data=False,     # …mais PAS leurs valeurs — vecteur de reconnaissance
        notes="métadonnées seulement (noms des secrets), pas les valeurs",
    ),
    # --- AI Search (data-plane index) ---
    "search index data reader": _READER,
    "search index data contributor": _DATA_CONTRIBUTOR,
    # --- Rôles larges (management-plane) ---
    "owner": EffectivePermissions(
        can_read_data=True, can_write_data=True, can_delete_data=True,
        can_list_metadata=True, can_manage_resource=True,
        notes="contrôle total : peut s'octroyer n'importe quel rôle data-plane (escalade)",
    ),
    "contributor": EffectivePermissions(
        can_manage_resource=True,
        notes="gestion ARM de la ressource, pas d'accès data-plane direct (hors cas Key Vault)",
    ),
}

_CONTRIBUTOR = "contributor"


def interpret_role(
    role_name: str,
    resource_type: Optional[ResourceType] = None,
    enable_rbac_authorization: Optional[bool] = None,
) -> EffectivePermissions:
    """Interprète un nom de rôle built-in vers ses permissions effectives.

    `resource_type` et `enable_rbac_authorization` ne sont consultés que pour lever l'ambiguïté
    Contributor sur Key Vault (mode RBAC vs access-policy)."""
    key = (role_name or "").strip().lower()

    if key == _CONTRIBUTOR and resource_type == ResourceType.KEY_VAULT:
        return _contributor_keyvault(enable_rbac_authorization)

    base = _BUILTIN.get(key)
    if base is None:
        return EffectivePermissions(
            ambiguous=True,
            notes=f"rôle non couvert (custom ou hors liste built-in) : {role_name!r}",
        )
    return base


def _contributor_keyvault(enable_rbac_authorization: Optional[bool]) -> EffectivePermissions:
    """Résout l'ambiguïté Contributor sur Key Vault selon le mode d'autorisation."""
    if enable_rbac_authorization is False:
        # Mode access-policy : Contributor peut s'octroyer des access policies → data-plane.
        return EffectivePermissions(
            can_read_data=True, can_write_data=True, can_delete_data=True,
            can_list_metadata=True, can_manage_resource=True, ambiguous=True,
            notes="Key Vault en mode access-policy : Contributor peut s'octroyer l'accès data-plane aux secrets",
        )
    if enable_rbac_authorization is True:
        # Mode RBAC : Contributor gère la ressource ; data-plane via rôles data explicites seulement.
        return EffectivePermissions(
            can_manage_resource=True,
            notes="Key Vault en mode RBAC : Contributor n'accède pas aux secrets sans rôle data explicite",
        )
    # Inconnu : conservateur — on signale l'ambiguïté sans présumer l'accès.
    return EffectivePermissions(
        can_manage_resource=True, ambiguous=True,
        notes="enableRbacAuthorization inconnu — Contributor pourrait accéder au data-plane si mode access-policy",
    )


def aggregate_permissions(
    roles: list[RoleAssignment],
    resource_type: Optional[ResourceType] = None,
    enable_rbac_authorization: Optional[bool] = None,
) -> EffectivePermissions:
    """Combine (OR booléen) les permissions effectives de tous les rôles applicables à une ressource."""
    interpreted = [
        interpret_role(r.role_definition_name, resource_type, enable_rbac_authorization)
        for r in roles
    ]
    notes = [p.notes for p in interpreted if p.notes]
    return EffectivePermissions(
        can_read_data=any(p.can_read_data for p in interpreted),
        can_write_data=any(p.can_write_data for p in interpreted),
        can_delete_data=any(p.can_delete_data for p in interpreted),
        can_list_metadata=any(p.can_list_metadata for p in interpreted),
        can_manage_resource=any(p.can_manage_resource for p in interpreted),
        ambiguous=any(p.ambiguous for p in interpreted),
        notes="; ".join(notes),
    )
