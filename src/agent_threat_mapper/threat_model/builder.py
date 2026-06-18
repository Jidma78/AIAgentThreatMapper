"""Construit le modèle de menace (graphe de flux, trust boundaries, points d'entrée non fiables) à partir des ressources Azure normalisées et de l'intention métier de l'agent."""

from __future__ import annotations

from agent_threat_mapper.models.agent_intent import AgentIntent
from agent_threat_mapper.models.azure_resources import AgentContext, RoleAssignment
from agent_threat_mapper.models.role_interpreter import aggregate_permissions
from agent_threat_mapper.models.threat_model import (
    AccessLevel,
    Edge,
    Node,
    NodeKind,
    ResourceType,
    ThreatModel,
    TrustBoundary,
    TrustZone,
)

# ---------------------------------------------------------------------------
# DEUX POINTS D'ENTRÉE NON FIABLES, AUX RÔLES DISTINCTS
# ---------------------------------------------------------------------------
# Le graphe possède deux sources de données non fiables, qui ne couvrent PAS le
# même vecteur d'analyse :
#
#   - `user`  : TOUJOURS présent. Porte la prompt injection et alimente l'analyse
#               d'excessive agency via les chemins  user → agent → tool → ressource.
#               C'est l'analyse PRINCIPALE de l'outil (entrée utilisateur → cloud) et
#               elle ne dépend en rien de la présence d'une source RAG.
#
#   - `rag`   : créé UNIQUEMENT si une source RAG (Azure AI Search) existe. Porte
#               l'analyse de RAG poisoning via  ai_search → rag → agent → tool → ressource.
#
# Conséquence assumée : seule la branche RAG poisoning dépend de la présence d'AI
# Search. Le threat modeling global (prompt injection + excessive agency du chemin
# utilisateur vers le cloud) reste complet même sans AI Search. C'est une limite
# acceptée de la version minimale pour le SEUL vecteur RAG, pas pour l'analyse globale.
# ---------------------------------------------------------------------------

# Identifiants des trust boundaries.
_B_USER = "B1"
_B_RAG = "B2"
_B_PRIVILEGE = "B3"
_B_LOGGING = "B4"
_B_LLM = "B5"


def _boundaries() -> list[TrustBoundary]:
    return [
        TrustBoundary(
            id=_B_USER,
            name="User → Agent",
            from_zone=TrustZone.UNTRUSTED,
            to_zone=TrustZone.AGENT_RUNTIME,
            description="Entrée utilisateur non fiable entrant dans le runtime de l'agent (prompt injection).",
        ),
        TrustBoundary(
            id=_B_RAG,
            name="Contenu RAG → Agent",
            from_zone=TrustZone.SEMI_TRUSTED,
            to_zone=TrustZone.AGENT_RUNTIME,
            description="Contenu récupéré potentiellement empoisonné entrant dans le contexte de l'agent (RAG poisoning).",
        ),
        TrustBoundary(
            id=_B_PRIVILEGE,
            name="Agent → Ressources Azure",
            from_zone=TrustZone.AGENT_RUNTIME,
            to_zone=TrustZone.CLOUD_PLATFORM,
            description="Franchissement de la frontière de privilège IAM : l'agent agit sur des ressources cloud.",
        ),
        TrustBoundary(
            id=_B_LOGGING,
            name="Azure → Logs",
            from_zone=TrustZone.CLOUD_PLATFORM,
            to_zone=TrustZone.OBSERVABILITY,
            description="Émission d'événements d'audit depuis une ressource vers l'observabilité.",
        ),
        TrustBoundary(
            id=_B_LLM,
            name="Décision LLM → invocation d'outil",
            # Frontière d'AGENCY (contrôle), intra-runtime et donc from_zone == to_zone, assumée
            # comme telle : elle n'est pas un franchissement de zone réseau mais le passage
            # « raisonnement LLM » → « actuation d'un outil ».
            from_zone=TrustZone.AGENT_RUNTIME,
            to_zone=TrustZone.AGENT_RUNTIME,
            description=(
                "La décision d'invoquer un outil est prise par le LLM, potentiellement sous "
                "l'influence d'une entrée non fiable (prompt injection / RAG poisoning). "
                "Frontière d'agency, distincte des frontières de zone B1–B4."
            ),
        ),
    ]


def _segments(resource_id: str) -> list[str]:
    """Découpe un resource ID Azure en segments normalisés en minuscules."""
    return [s.lower() for s in resource_id.strip("/").split("/") if s]


def _scope_covers(scope: str, resource_id: str) -> bool:
    """True si `scope` couvre `resource_id`, par comparaison segment par segment,
    insensible à la casse.

    Robuste à la casse mixte d'Azure (`resourcegroups` vs `resourceGroups`) et
    évite les faux positifs de préfixe brut : /rg/foo ne couvre PAS /rg/foobar
    (car le segment "foo" diffère du segment "foobar")."""
    scope_seg = _segments(scope)
    res_seg = _segments(resource_id)
    if len(scope_seg) > len(res_seg):
        return False
    return res_seg[: len(scope_seg)] == scope_seg


def _same_resource(a: str, b: str) -> bool:
    """Égalité de deux resource IDs, segment par segment, insensible à la casse."""
    return _segments(a) == _segments(b)


def _applicable_roles(resource_id: str, roles: list[RoleAssignment]) -> list[RoleAssignment]:
    return [r for r in roles if _scope_covers(r.scope, resource_id)]


def build_threat_model(context: AgentContext, intent: AgentIntent) -> ThreatModel:
    """Construit le modèle de menace à partir du contexte Azure et de l'intention métier.

    Topologie fixe (user → agent → LLM → RAG → tools → ressources Azure → logs) ;
    les nœuds ressources/outils (et le nœud RAG) sont instanciés depuis le contexte réel."""
    nodes: list[Node] = []
    edges: list[Edge] = []
    boundaries = _boundaries()

    roles = context.role_assignments

    # --- Squelette fixe : toujours présent --------------------------------
    user = Node(
        id="user",
        kind=NodeKind.USER,
        label="Utilisateur",
        trust_zone=TrustZone.UNTRUSTED,
        untrusted_entry=True,
    )
    agent = Node(
        id="agent",
        kind=NodeKind.AGENT,
        label=intent.name or "Agent",
        trust_zone=TrustZone.AGENT_RUNTIME,
        metadata={"intent": intent},
    )
    llm = Node(
        id="llm",
        kind=NodeKind.LLM,
        label="LLM",
        trust_zone=TrustZone.AGENT_RUNTIME,
    )
    logs = Node(
        id="logs",
        kind=NodeKind.LOG_SINK,
        label="Logs / diagnostics",
        trust_zone=TrustZone.OBSERVABILITY,
    )
    nodes.extend([user, agent, llm, logs])

    # LLM EN SÉRIE : l'agent transmet le contexte (input user + contenu RAG) au LLM, et c'est le
    # LLM — potentiellement manipulé par une prompt injection — qui décide d'invoquer un outil
    # (arête llm → tool, plus bas, franchissant B5). Le LLM n'est donc PAS une branche parallèle :
    # tout chemin d'attaque vers une ressource le traverse.
    edges.append(Edge("user", "agent", "prompt utilisateur", boundary_id=_B_USER))
    edges.append(Edge("agent", "llm", "transmission du contexte au LLM"))
    edges.append(Edge("agent", "logs", "log d'activité"))

    # --- Heuristique de création du nœud RAG ------------------------------
    # Le nœud RAG (point d'entrée non fiable, vecteur RAG poisoning) est créé si :
    #   - une source RAG managée (Azure AI Search) existe, OU
    #   - à défaut d'AI Search, au moins un Storage Account existe : un agent peut faire du RAG
    #     directement sur des blobs (source documentaire). Le stage 1 n'exportant que les
    #     ressources atteignables par les rôles de l'identité, tout Storage présent dans le
    #     contexte est déjà une source documentaire plausible et accessible.
    # LIMITE ASSUMÉE : on ne distingue pas un Storage réellement utilisé comme corpus RAG d'un
    # Storage purement applicatif — raffinement (inspection containers/usage) délégué à plus tard.
    has_ai_search = bool(context.ai_search_services)
    storage_rag_sources = context.storage_accounts if not has_ai_search else []
    has_rag = has_ai_search or bool(storage_rag_sources)
    if has_rag:
        rag = Node(
            id="rag",
            kind=NodeKind.RAG,
            label="Couche RAG (récupération)",
            trust_zone=TrustZone.SEMI_TRUSTED,
            untrusted_entry=True,
        )
        nodes.append(rag)
        edges.append(Edge("agent", "rag", "requête de récupération"))
        edges.append(Edge("rag", "agent", "contenu récupéré", boundary_id=_B_RAG))

    # --- Ressources accessibles via un outil : un TOOL par ressource ------
    # (storage + key vault : attribution des rôles et longueur de chemin par ressource)
    def _add_tooled_resource(name: str, resource_id: str, rtype: ResourceType, ref) -> None:
        res_node_id = f"resource:{rtype.value}:{name}"
        tool_node_id = f"tool:{rtype.value}:{name}"
        nodes.append(
            Node(
                id=res_node_id,
                kind=NodeKind.AZURE_RESOURCE,
                label=name,
                trust_zone=TrustZone.CLOUD_PLATFORM,
                resource_type=rtype,
                resource_ref=ref,
                applicable_roles=_applicable_roles(resource_id, roles),
                # access_level laissé à UNRESOLVED : interprétation rôle→permission déléguée au stage 4.
                access_level=AccessLevel.UNRESOLVED,
            )
        )
        nodes.append(
            Node(
                id=tool_node_id,
                kind=NodeKind.TOOL,
                label=f"Outil d'accès {rtype.value}: {name}",
                trust_zone=TrustZone.AGENT_RUNTIME,
            )
        )
        # La décision d'appeler l'outil naît du LLM (potentiellement sous injection) → B5.
        edges.append(Edge("llm", tool_node_id, "décision d'invocation d'outil", boundary_id=_B_LLM))
        edges.append(Edge(tool_node_id, res_node_id, "lecture/écriture", boundary_id=_B_PRIVILEGE))
        _link_logs(resource_id, res_node_id)

    def _link_logs(resource_id: str, res_node_id: str) -> None:
        if any(_same_resource(d.resource_id, resource_id) and d.enabled for d in context.diagnostic_settings):
            edges.append(Edge(res_node_id, "logs", "log d'audit", boundary_id=_B_LOGGING))

    for sa in context.storage_accounts:
        _add_tooled_resource(sa.name, sa.resource_id, ResourceType.STORAGE, sa)

    # DETTE KEY VAULT : tant que le stage 1 ne capture pas `enableRbacAuthorization`, on ne peut
    # pas savoir si le vault est gouverné par RBAC (donc par role_assignments) ou par access
    # policies. `applicable_roles` peut donc NE PAS refléter l'accès data-plane réel au vault.
    # À lever quand le stage 1 exportera ce champ ; l'interprétation effective reste au stage 4.
    for kv in context.key_vaults:
        _add_tooled_resource(kv.name, kv.resource_id, ResourceType.KEY_VAULT, kv)

    # Config B : sans AI Search, chaque Storage Account alimente la couche RAG (blobs = corpus
    # documentaire). Le Storage est alors à la fois source RAG (sortant → rag) et cible d'outil
    # (entrant tool → storage) ; le visited set du DFS casse le cycle storage → rag → … → storage.
    for sa in storage_rag_sources:
        edges.append(
            Edge(f"resource:{ResourceType.STORAGE.value}:{sa.name}", "rag", "source documentaire (blobs)")
        )

    # --- Ressources AI Search : routées via la couche RAG (source de taint)
    for ais in context.ai_search_services:
        res_node_id = f"resource:{ResourceType.AI_SEARCH.value}:{ais.name}"
        nodes.append(
            Node(
                id=res_node_id,
                kind=NodeKind.AZURE_RESOURCE,
                label=ais.name,
                trust_zone=TrustZone.CLOUD_PLATFORM,
                resource_type=ResourceType.AI_SEARCH,
                resource_ref=ais,
                applicable_roles=_applicable_roles(ais.resource_id, roles),
                access_level=AccessLevel.UNRESOLVED,
            )
        )
        # Le service de recherche alimente la couche RAG (contenu potentiellement empoisonné).
        edges.append(Edge(res_node_id, "rag", "alimente l'index"))
        _link_logs(ais.resource_id, res_node_id)

    # --- Flux inter-storage (latéraux, intra-CLOUD_PLATFORM → aucune nouvelle boundary) ----
    # Deux vecteurs DISTINCTS, aux labels distincts pour des findings différenciés au stage 4.
    # Permissions déduites des rôles réels via aggregate_permissions (pas d'heuristique aveugle).
    storage_nodes = [
        n for n in nodes
        if n.kind == NodeKind.AZURE_RESOURCE and n.resource_type == ResourceType.STORAGE
    ]
    perms = {
        n.id: aggregate_permissions(n.applicable_roles, ResourceType.STORAGE)
        for n in storage_nodes
    }
    rag_source_ids = {
        f"resource:{ResourceType.STORAGE.value}:{sa.name}" for sa in storage_rag_sources
    }

    for a in storage_nodes:
        for b in storage_nodes:
            if a.id == b.id:
                continue
            # Flux 1 — exfiltration / copie directe : lecture sur A ET écriture sur B (directionnel).
            if perms[a.id].can_read_data and perms[b.id].can_write_data:
                edges.append(
                    Edge(a.id, b.id, "lecture/exfiltration ou copie inter-storage possible")
                )
            # Flux 2 — RAG poisoning : A est une source RAG et B est accessible en écriture.
            # (arête parallèle possible avec le flux 1, label distinct, assumée.)
            if a.id in rag_source_ids and perms[b.id].can_write_data:
                edges.append(
                    Edge(a.id, b.id, "RAG poisoning → écriture inter-storage possible")
                )

    return ThreatModel(nodes=nodes, edges=edges, boundaries=boundaries)
