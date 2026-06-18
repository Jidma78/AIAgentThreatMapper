"""Tests de la construction du modèle de menace (flux, trust boundaries)."""

from __future__ import annotations

import pytest

from agent_threat_mapper.models.agent_intent import AgentIntent, AutonomyLevel
from agent_threat_mapper.models.azure_resources import (
    AgentContext,
    AISearch,
    DiagnosticSettings,
    KeyVault,
    ManagedIdentity,
    RoleAssignment,
    StorageAccount,
)
from agent_threat_mapper.models.threat_model import (
    AccessLevel,
    NodeKind,
    ResourceType,
    TrustZone,
)
from agent_threat_mapper.threat_model.builder import (
    _scope_covers,
    build_threat_model,
)

SUB = "cce3f0d7-5933-4838-a31e-4567cbc117d0"

# resource_id de l'identité avec casse minuscule "resourcegroups" (comme l'export réel)
STORAGE_ID = f"/subscriptions/{SUB}/resourcegroups/atm-test-rg/providers/Microsoft.Storage/storageAccounts/atmstore"
KV_ID = f"/subscriptions/{SUB}/resourcegroups/atm-test-rg/providers/Microsoft.KeyVault/vaults/atm-kv"
SEARCH_ID = f"/subscriptions/{SUB}/resourcegroups/atm-test-rg/providers/Microsoft.Search/searchServices/atm-search"

# scope du rôle avec casse mixte "resourceGroups"
RG_SCOPE = f"/subscriptions/{SUB}/resourceGroups/atm-test-rg"


def _identity() -> ManagedIdentity:
    return ManagedIdentity(
        principal_id="pid", client_id="cid", tenant_id="tid", object_id="pid",
        resource_id=f"/subscriptions/{SUB}/resourcegroups/atm-test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/atm-id",
    )


def _storage() -> StorageAccount:
    return StorageAccount(
        name="atmstore", resource_id=STORAGE_ID, resource_group="atm-test-rg",
        location="francecentral", allow_blob_public_access=False, https_only=True,
        network_acls_default_action="Allow", kind="StorageV2", sku_name="Standard_LRS",
    )


def _keyvault() -> KeyVault:
    return KeyVault(
        name="atm-kv", resource_id=KV_ID, resource_group="atm-test-rg", location="francecentral",
        network_acls_default_action="Allow", enabled_for_disk_encryption=False,
        soft_delete_enabled=True, purge_protection_enabled=False,
    )


def _search() -> AISearch:
    return AISearch(
        name="atm-search", resource_id=SEARCH_ID, resource_group="atm-test-rg",
        location="francecentral", sku_name="standard", public_network_access="Enabled", replica_count=1,
    )


def _role(scope: str = RG_SCOPE, name: str = "Contributor") -> RoleAssignment:
    return RoleAssignment(
        role_definition_name=name, role_definition_id="/rd/id", scope=scope,
        principal_id="pid", assignment_id="/ra/id",
    )


def _intent() -> AgentIntent:
    return AgentIntent(
        name="customer-support-assistant", autonomy_level=AutonomyLevel.SUPERVISED,
        allowed_actions=["lire la doc"], forbidden_actions=["écrire dans le stockage"],
    )


def _context(storage=None, keyvaults=None, searches=None, roles=None, diags=None) -> AgentContext:
    return AgentContext(
        managed_identity=_identity(),
        role_assignments=roles or [],
        key_vaults=keyvaults or [],
        storage_accounts=storage or [],
        ai_search_services=searches or [],
        diagnostic_settings=diags or [],
    )


# ---------------------------------------------------------------------------
# Squelette fixe
# ---------------------------------------------------------------------------

def test_fixed_skeleton_always_present():
    tm = build_threat_model(_context(), _intent())
    for node_id in ("user", "agent", "llm", "logs"):
        assert tm.get_node(node_id) is not None


def test_five_trust_boundaries():
    tm = build_threat_model(_context(), _intent())
    assert {b.id for b in tm.boundaries} == {"B1", "B2", "B3", "B4", "B5"}


def test_five_trust_zones_are_usable():
    tm = build_threat_model(
        _context(storage=[_storage()], searches=[_search()]), _intent()
    )
    zones = {n.trust_zone for n in tm.nodes}
    assert TrustZone.UNTRUSTED in zones
    assert TrustZone.SEMI_TRUSTED in zones        # rag
    assert TrustZone.AGENT_RUNTIME in zones
    assert TrustZone.CLOUD_PLATFORM in zones
    assert TrustZone.OBSERVABILITY in zones


def test_agent_node_carries_intent():
    intent = _intent()
    tm = build_threat_model(_context(), intent)
    assert tm.get_node("agent").metadata["intent"] is intent


# ---------------------------------------------------------------------------
# Points d'entrée non fiables
# ---------------------------------------------------------------------------

def test_user_is_always_untrusted_entry_without_rag():
    # baseline sans RAG : ni storage ni AI Search (key-vault-seul) → pas de nœud rag
    tm = build_threat_model(_context(keyvaults=[_keyvault()]), _intent())
    entries = {n.id for n in tm.untrusted_entry_points()}
    assert entries == {"user"}
    assert tm.get_node("rag") is None


def test_rag_entry_with_ai_search():
    tm = build_threat_model(_context(searches=[_search()]), _intent())
    entries = {n.id for n in tm.untrusted_entry_points()}
    assert entries == {"user", "rag"}
    assert tm.get_node("rag").trust_zone == TrustZone.SEMI_TRUSTED


# ---------------------------------------------------------------------------
# Instanciation dynamique des nœuds
# ---------------------------------------------------------------------------

def test_one_tool_per_storage_and_keyvault():
    tm = build_threat_model(_context(storage=[_storage()], keyvaults=[_keyvault()]), _intent())
    tools = tm.nodes_by_kind(NodeKind.TOOL)
    assert {t.id for t in tools} == {"tool:storage:atmstore", "tool:keyvault:atm-kv"}
    # llm → tool → resource pour le storage (le LLM décide de l'invocation, pas l'agent)
    assert "tool:storage:atmstore" in {n.id for n in tm.successors("llm")}
    assert "resource:storage:atmstore" in {n.id for n in tm.successors("tool:storage:atmstore")}


def test_resource_ref_points_to_dataclass():
    sa = _storage()
    tm = build_threat_model(_context(storage=[sa]), _intent())
    node = tm.get_node("resource:storage:atmstore")
    assert node.resource_ref is sa
    assert node.resource_type == ResourceType.STORAGE


def test_ai_search_routed_through_rag_no_tool():
    tm = build_threat_model(_context(searches=[_search()]), _intent())
    # pas de nœud tool pour AI Search
    assert tm.get_node("tool:aisearch:atm-search") is None
    # ai_search alimente la couche RAG
    assert "rag" in {n.id for n in tm.successors("resource:aisearch:atm-search")}


# ---------------------------------------------------------------------------
# applicable_roles : matching scope segment par segment, insensible à la casse
# ---------------------------------------------------------------------------

def test_scope_covers_case_insensitive_segments():
    # casse mixte : resourceGroups (scope) vs resourcegroups (resource_id)
    assert _scope_covers(RG_SCOPE, STORAGE_ID) is True


def test_scope_covers_subscription_level():
    assert _scope_covers(f"/subscriptions/{SUB}", STORAGE_ID) is True


def test_scope_does_not_match_partial_segment():
    # /rg/foo ne doit PAS couvrir /rg/foobar
    assert _scope_covers("/subscriptions/s/resourceGroups/foo", "/subscriptions/s/resourceGroups/foobar") is False


def test_scope_resource_level_exact_match():
    assert _scope_covers(STORAGE_ID, STORAGE_ID) is True


def test_applicable_roles_attached_to_resource_node():
    role = _role(scope=RG_SCOPE)
    tm = build_threat_model(_context(storage=[_storage()], roles=[role]), _intent())
    node = tm.get_node("resource:storage:atmstore")
    assert node.applicable_roles == [role]


def test_inapplicable_role_not_attached():
    other = _role(scope=f"/subscriptions/{SUB}/resourceGroups/other-rg")
    tm = build_threat_model(_context(storage=[_storage()], roles=[other]), _intent())
    node = tm.get_node("resource:storage:atmstore")
    assert node.applicable_roles == []


def test_resource_node_access_level_unresolved():
    # dette visible : l'interprétation rôle→permission effective est déléguée au stage 4
    tm = build_threat_model(
        _context(storage=[_storage()], keyvaults=[_keyvault()], searches=[_search()]), _intent()
    )
    for node in tm.resource_nodes():
        assert node.access_level == AccessLevel.UNRESOLVED


# ---------------------------------------------------------------------------
# Requête centrale : paths_from_untrusted_to
# ---------------------------------------------------------------------------

def test_user_path_to_storage_crosses_b1_b5_b3():
    # NB : un Storage seul crée maintenant un nœud RAG (config B) → 2 origines (user + rag).
    # On ne peut plus asserter len(paths) == 1 ; on filtre le chemin d'origine user.
    tm = build_threat_model(_context(storage=[_storage()]), _intent())
    paths = tm.paths_from_untrusted_to("resource:storage:atmstore")
    user_path = next(p for p in paths if p.origin.id == "user")
    assert [n.id for n in user_path.nodes] == [
        "user", "agent", "llm", "tool:storage:atmstore", "resource:storage:atmstore",
    ]
    assert {b.id for b in user_path.crossed_boundaries} == {"B1", "B5", "B3"}


def test_llm_is_in_series_on_attack_path():
    tm = build_threat_model(_context(storage=[_storage()]), _intent())
    user_path = next(
        p for p in tm.paths_from_untrusted_to("resource:storage:atmstore") if p.origin.id == "user"
    )
    # le LLM est traversé en série : aucun court-circuit user → agent → tool
    assert "llm" in [n.id for n in user_path.nodes]


def test_no_direct_agent_to_tool_edge():
    tm = build_threat_model(_context(storage=[_storage()], keyvaults=[_keyvault()]), _intent())
    agent_succ = {n.kind for n in tm.successors("agent")}
    assert NodeKind.TOOL not in agent_succ          # l'agent n'invoque pas directement d'outil
    llm_succ = {n.id for n in tm.successors("llm")}
    assert "tool:storage:atmstore" in llm_succ      # c'est le LLM qui le fait


def test_b5_crossed_on_every_untrusted_path_to_resource():
    tm = build_threat_model(_context(storage=[_storage()], keyvaults=[_keyvault()]), _intent())
    paths = tm.paths_from_untrusted_to("resource:keyvault:atm-kv")
    assert paths
    for p in paths:
        assert "B5" in {b.id for b in p.crossed_boundaries}


def test_rag_poisoning_path_to_storage_crosses_b2_b5_b3():
    tm = build_threat_model(_context(storage=[_storage()], searches=[_search()]), _intent())
    paths = tm.paths_from_untrusted_to("resource:storage:atmstore")
    origins = {p.origin.id for p in paths}
    assert origins == {"user", "rag"}
    rag_path = next(p for p in paths if p.origin.id == "rag")
    assert [n.id for n in rag_path.nodes] == [
        "rag", "agent", "llm", "tool:storage:atmstore", "resource:storage:atmstore",
    ]
    assert {b.id for b in rag_path.crossed_boundaries} == {"B2", "B5", "B3"}


def test_llm_is_reachable_from_user_entry():
    tm = build_threat_model(_context(keyvaults=[_keyvault()]), _intent())
    paths = tm.paths_from_untrusted_to("llm")
    assert any(p.origin.id == "user" for p in paths)


# ---------------------------------------------------------------------------
# Config B : RAG-sur-storage (sans AI Search) + anti-cycle
# ---------------------------------------------------------------------------

def test_rag_created_from_storage_without_ai_search():
    tm = build_threat_model(_context(storage=[_storage()]), _intent())
    rag = tm.get_node("rag")
    assert rag is not None
    assert rag.untrusted_entry is True
    # le storage alimente la couche RAG (source documentaire)
    assert "rag" in {n.id for n in tm.successors("resource:storage:atmstore")}
    assert {n.id for n in tm.untrusted_entry_points()} == {"user", "rag"}


def test_rag_poisoning_to_keyvault_via_storage_source():
    # storage (source RAG) + key vault (cible d'outil), sans AI Search
    tm = build_threat_model(_context(storage=[_storage()], keyvaults=[_keyvault()]), _intent())
    paths = tm.paths_from_untrusted_to("resource:keyvault:atm-kv")
    rag_path = next(p for p in paths if p.origin.id == "rag")
    assert [n.id for n in rag_path.nodes] == [
        "rag", "agent", "llm", "tool:keyvault:atm-kv", "resource:keyvault:atm-kv",
    ]
    assert {b.id for b in rag_path.crossed_boundaries} == {"B2", "B5", "B3"}


def test_no_returned_path_revisits_a_node():
    # config B introduit le cycle storage → rag → agent → llm → tool → storage ;
    # le visited set du DFS doit garantir des chemins simples (aucun nœud répété).
    tm = build_threat_model(_context(storage=[_storage()]), _intent())
    for p in tm.paths_from_untrusted_to("resource:storage:atmstore"):
        ids = [n.id for n in p.nodes]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# reaches_log_sink
# ---------------------------------------------------------------------------

def test_resource_with_diagnostics_reaches_log_sink():
    diag = DiagnosticSettings(
        resource_id=STORAGE_ID, name="diag", workspace_id="/ws", storage_account_id=None,
        log_categories=["StorageRead"], enabled=True,
    )
    tm = build_threat_model(_context(storage=[_storage()], diags=[diag]), _intent())
    assert tm.reaches_log_sink("resource:storage:atmstore") is True


def test_resource_without_diagnostics_does_not_reach_log_sink():
    tm = build_threat_model(_context(storage=[_storage()]), _intent())
    assert tm.reaches_log_sink("resource:storage:atmstore") is False


def test_diagnostics_match_is_case_insensitive():
    # diag.resource_id en casse différente du resource_id de la ressource
    diag = DiagnosticSettings(
        resource_id=STORAGE_ID.upper(), name="diag", workspace_id="/ws", storage_account_id=None,
        log_categories=["StorageRead"], enabled=True,
    )
    tm = build_threat_model(_context(storage=[_storage()], diags=[diag]), _intent())
    assert tm.reaches_log_sink("resource:storage:atmstore") is True


# ---------------------------------------------------------------------------
# Flux inter-storage (2 vecteurs distincts, déduits des permissions réelles)
# ---------------------------------------------------------------------------

_EXFIL_LABEL = "lecture/exfiltration ou copie inter-storage possible"
_RAG_WRITE_LABEL = "RAG poisoning → écriture inter-storage possible"


def _storage_named(name: str) -> StorageAccount:
    rid = f"/subscriptions/{SUB}/resourceGroups/atm-test-rg/providers/Microsoft.Storage/storageAccounts/{name}"
    return StorageAccount(
        name=name, resource_id=rid, resource_group="atm-test-rg", location="francecentral",
        allow_blob_public_access=False, https_only=True, network_acls_default_action="Allow",
        kind="StorageV2", sku_name="Standard_LRS",
    )


def _role_on(resource_id: str, role_name: str) -> RoleAssignment:
    return RoleAssignment(
        role_definition_name=role_name, role_definition_id="/rd", scope=resource_id,
        principal_id="pid", assignment_id="/ra",
    )


def _edge_triples(tm):
    return {(e.source_id, e.target_id, e.label) for e in tm.edges}


def _inter_resource_hops(tm, path) -> int:
    """Nombre d'arêtes latérales (source ET cible = AZURE_RESOURCE) dans un chemin."""
    count = 0
    for e in path.edges:
        src, tgt = tm.get_node(e.source_id), tm.get_node(e.target_id)
        if src.kind == NodeKind.AZURE_RESOURCE and tgt.kind == NodeKind.AZURE_RESOURCE:
            count += 1
    return count


def test_inter_storage_exfil_edge_is_directional():
    # A lisible, B inscriptible → arête A→B (flux 1). AI Search présent pour isoler le flux 1.
    a, b = _storage_named("store-a"), _storage_named("store-b")
    roles = [
        _role_on(a.resource_id, "Storage Blob Data Reader"),
        _role_on(b.resource_id, "Storage Blob Data Contributor"),
    ]
    tm = build_threat_model(_context(storage=[a, b], searches=[_search()], roles=roles), _intent())
    triples = _edge_triples(tm)
    assert ("resource:storage:store-a", "resource:storage:store-b", _EXFIL_LABEL) in triples
    # directionnel : pas de B→A (B lisible mais A non inscriptible)
    assert not any(
        s == "resource:storage:store-b" and t == "resource:storage:store-a" for s, t, _ in triples
    )


def test_no_inter_storage_edge_when_read_only():
    a, b = _storage_named("store-a"), _storage_named("store-b")
    roles = [
        _role_on(a.resource_id, "Storage Blob Data Reader"),
        _role_on(b.resource_id, "Storage Blob Data Reader"),
    ]
    tm = build_threat_model(_context(storage=[a, b], searches=[_search()], roles=roles), _intent())
    assert not any("inter-storage" in lbl for _, _, lbl in _edge_triples(tm))


def test_rag_poisoning_inter_storage_write_edge():
    # config B (sans AI Search) : X est source RAG (aucun rôle data), Y inscriptible.
    x, y = _storage_named("rag-store"), _storage_named("target-store")
    roles = [_role_on(y.resource_id, "Storage Blob Data Contributor")]
    tm = build_threat_model(_context(storage=[x, y], roles=roles), _intent())
    triples = _edge_triples(tm)
    assert ("resource:storage:rag-store", "resource:storage:target-store", _RAG_WRITE_LABEL) in triples
    # flux 1 absent : rag-store n'a aucun droit de lecture data
    assert not any(lbl == _EXFIL_LABEL for _, _, lbl in triples)


def test_no_rag_poisoning_edge_in_config_a():
    # AI Search présent → storage non source RAG → pas de flux 2
    x, y = _storage_named("rag-store"), _storage_named("target-store")
    roles = [_role_on(y.resource_id, "Storage Blob Data Contributor")]
    tm = build_threat_model(_context(storage=[x, y], searches=[_search()], roles=roles), _intent())
    assert not any(lbl == _RAG_WRITE_LABEL for _, _, lbl in _edge_triples(tm))


def test_path_to_target_storage_traverses_lateral_vector():
    x, y = _storage_named("rag-store"), _storage_named("target-store")
    roles = [_role_on(y.resource_id, "Storage Blob Data Contributor")]
    tm = build_threat_model(_context(storage=[x, y], roles=roles), _intent())
    paths = tm.paths_from_untrusted_to("resource:storage:target-store")

    # Aucun chemin ne dépasse un seul saut inter-ressource.
    assert all(_inter_resource_hops(tm, p) <= 1 for p in paths)
    # Catégorie 1 : chemin direct, sans saut latéral.
    assert any(_inter_resource_hops(tm, p) == 0 for p in paths)
    # Catégorie 2 : chemin latéral à exactement un saut, passant par rag-store.
    lateral = [p for p in paths if _inter_resource_hops(tm, p) == 1]
    assert lateral
    assert all("resource:storage:rag-store" in [n.id for n in p.nodes] for p in lateral)


def test_mutual_inter_storage_edges_do_not_create_revisiting_paths():
    # A et B mutuellement lisibles+inscriptibles → arêtes A→B et B→A (2-cycle).
    a, b = _storage_named("store-a"), _storage_named("store-b")
    roles = [
        _role_on(a.resource_id, "Storage Blob Data Contributor"),
        _role_on(b.resource_id, "Storage Blob Data Contributor"),
    ]
    tm = build_threat_model(_context(storage=[a, b], searches=[_search()], roles=roles), _intent())
    triples = _edge_triples(tm)
    assert ("resource:storage:store-a", "resource:storage:store-b", _EXFIL_LABEL) in triples
    assert ("resource:storage:store-b", "resource:storage:store-a", _EXFIL_LABEL) in triples
    paths = tm.paths_from_untrusted_to("resource:storage:store-b")
    for p in paths:
        ids = [n.id for n in p.nodes]
        assert len(ids) == len(set(ids))            # chemins simples (pas de nœud répété)
        assert _inter_resource_hops(tm, p) <= 1     # au plus un saut latéral malgré le 2-cycle


def test_three_writable_storages_no_combinatorial_explosion():
    # Cas signalé : 3 storages mutuellement inscriptibles. Sans la borne, la cible accumulait
    # des dizaines de variantes du même vecteur ; avec la borne, au plus 1 saut latéral par chemin.
    a, b, c = _storage_named("store-a"), _storage_named("store-b"), _storage_named("store-c")
    roles = [
        _role_on(a.resource_id, "Storage Blob Data Contributor"),
        _role_on(b.resource_id, "Storage Blob Data Contributor"),
        _role_on(c.resource_id, "Storage Blob Data Contributor"),
    ]
    tm = build_threat_model(_context(storage=[a, b, c], searches=[_search()], roles=roles), _intent())
    paths = tm.paths_from_untrusted_to("resource:storage:store-c")

    # Aucun chemin ne traverse deux ressources avant la cible.
    assert all(_inter_resource_hops(tm, p) <= 1 for p in paths)
    # Les chemins latéraux n'ont qu'une seule arête inter-ressource (…→ res_X → store-c).
    for p in paths:
        if _inter_resource_hops(tm, p) == 1:
            assert p.nodes[-1].id == "resource:storage:store-c"
            assert p.nodes[-2].kind == NodeKind.AZURE_RESOURCE


def test_two_lateral_paths_same_nodes_distinct_vectors():
    # rag-store : source RAG (config B) ET lisible → génère les DEUX arêtes parallèles vers
    # target-store (exfiltration via flux 1, RAG poisoning via flux 2).
    x, y = _storage_named("rag-store"), _storage_named("target-store")
    roles = [
        _role_on(x.resource_id, "Storage Blob Data Reader"),
        _role_on(y.resource_id, "Storage Blob Data Contributor"),
    ]
    tm = build_threat_model(_context(storage=[x, y], roles=roles), _intent())
    paths = tm.paths_from_untrusted_to("resource:storage:target-store")

    # Regroupe par séquence de nœuds : une même séquence doit porter les deux vecteurs distincts.
    by_sequence: dict[tuple, set] = {}
    for p in paths:
        seq = tuple(n.id for n in p.nodes)
        by_sequence.setdefault(seq, set()).add(p.lateral_vector_label())

    lateral_sequences = [
        labels for labels in by_sequence.values() if labels != {None}
    ]
    assert any(
        labels == {_EXFIL_LABEL, _RAG_WRITE_LABEL} for labels in lateral_sequences
    ), "une même séquence de nœuds doit exposer les deux vecteurs latéraux distincts"

    # Un chemin direct (sans saut latéral) renvoie None.
    assert any(p.lateral_vector_label() is None for p in paths)
