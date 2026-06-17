"""Dataclasses du graphe de flux de données : nodes (utilisateur, agent, LLM, RAG, tools, ressources Azure, logs), edges et trust boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from agent_threat_mapper.models.azure_resources import (
    AISearch,
    DiagnosticSettings,
    KeyVault,
    RoleAssignment,
    StorageAccount,
)

# Charge utile concrète portée par un nœud ressource (la dataclass normalisée du stage 2).
ResourceRef = Union[StorageAccount, KeyVault, AISearch, DiagnosticSettings]


class NodeKind(Enum):
    """Type d'un nœud du graphe de flux. La topologie reste fixe ; seuls les
    nœuds AZURE_RESOURCE / TOOL (et éventuellement RAG) sont instanciés dynamiquement."""

    USER = "user"
    AGENT = "agent"
    LLM = "llm"
    RAG = "rag"
    TOOL = "tool"
    AZURE_RESOURCE = "azure_resource"
    LOG_SINK = "log_sink"


class TrustZone(Enum):
    """Zone de confiance d'un nœud. Une trust boundary est franchie quand une
    arête relie deux nœuds de zones différentes."""

    UNTRUSTED = "untrusted"            # entrée externe directe : input utilisateur
    SEMI_TRUSTED = "semi_trusted"      # contenu RAG récupéré (potentiellement empoisonné)
    AGENT_RUNTIME = "agent_runtime"    # agent, LLM, outils — le runtime d'orchestration
    CLOUD_PLATFORM = "cloud_platform"  # ressources Azure derrière l'IAM
    OBSERVABILITY = "observability"    # logs / diagnostics


class ResourceType(Enum):
    """Sous-type d'un nœud AZURE_RESOURCE."""

    STORAGE = "storage"
    KEY_VAULT = "keyvault"
    AI_SEARCH = "aisearch"


class AccessLevel(Enum):
    """Niveau d'accès effectif de l'agent sur une ressource.

    DETTE ASSUMÉE : l'interprétation `applicable_roles → permission effective` (lecture seule,
    écriture, gestion…) n'est PAS calculée au stage 3. Tous les nœuds ressource sont marqués
    UNRESOLVED ; le calcul fin des permissions effectives est délégué au stage 4."""

    UNRESOLVED = "unresolved"


@dataclass
class Node:
    """Un nœud du graphe de flux de données."""

    id: str
    kind: NodeKind
    label: str
    trust_zone: TrustZone
    untrusted_entry: bool = False
    resource_type: Optional[ResourceType] = None
    resource_ref: Optional[ResourceRef] = None
    # Role assignments dont le scope couvre cette ressource (calculé par le builder).
    # NB : étiquette brute, sans interprétation du niveau d'accès — voir access_level ci-dessous.
    applicable_roles: list[RoleAssignment] = field(default_factory=list)
    # Permission effective de l'agent sur la ressource. Reste UNRESOLVED au stage 3 :
    # l'interprétation rôle→permission est déléguée au stage 4 (voir AccessLevel).
    access_level: AccessLevel = AccessLevel.UNRESOLVED
    metadata: dict = field(default_factory=dict)


@dataclass
class TrustBoundary:
    """Une frontière de confiance entre deux zones."""

    id: str
    name: str
    from_zone: TrustZone
    to_zone: TrustZone
    description: str


@dataclass
class Edge:
    """Une arête dirigée du graphe. `boundary_id` est renseigné si l'arête
    franchit une trust boundary."""

    source_id: str
    target_id: str
    label: str
    boundary_id: Optional[str] = None


@dataclass
class Path:
    """Un chemin dirigé du graphe, du point d'entrée (nodes[0]) vers la cible
    (nodes[-1]). `edges` a une longueur de len(nodes) - 1."""

    nodes: list[Node]
    edges: list[Edge]
    crossed_boundaries: list[TrustBoundary]

    @property
    def origin(self) -> Node:
        return self.nodes[0]

    @property
    def target(self) -> Node:
        return self.nodes[-1]

    def starts_untrusted(self) -> bool:
        return self.origin.untrusted_entry


@dataclass
class ThreatModel:
    """Le modèle de menace complet : nœuds, arêtes, trust boundaries, plus l'API
    de requête que le moteur de règles du stage 4 va parcourir."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    boundaries: list[TrustBoundary] = field(default_factory=list)

    # --- Accès aux nœuds -------------------------------------------------

    def get_node(self, node_id: str) -> Optional[Node]:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def nodes_by_kind(self, kind: NodeKind) -> list[Node]:
        return [n for n in self.nodes if n.kind == kind]

    def resource_nodes(self, resource_type: Optional[ResourceType] = None) -> list[Node]:
        nodes = self.nodes_by_kind(NodeKind.AZURE_RESOURCE)
        if resource_type is None:
            return nodes
        return [n for n in nodes if n.resource_type == resource_type]

    def untrusted_entry_points(self) -> list[Node]:
        return [n for n in self.nodes if n.untrusted_entry]

    # --- Adjacence -------------------------------------------------------

    def edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.source_id == node_id]

    def edges_to(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.target_id == node_id]

    def successors(self, node_id: str) -> list[Node]:
        return [n for e in self.edges_from(node_id) if (n := self.get_node(e.target_id))]

    def predecessors(self, node_id: str) -> list[Node]:
        return [n for e in self.edges_to(node_id) if (n := self.get_node(e.source_id))]

    # --- Requêtes pour le stage 4 ---------------------------------------

    def reaches_log_sink(self, node_id: str) -> bool:
        """True si ce nœud émet directement vers un LOG_SINK (ressource monitorée)."""
        return any(
            (target := self.get_node(e.target_id)) is not None
            and target.kind == NodeKind.LOG_SINK
            for e in self.edges_from(node_id)
        )

    def paths_from_untrusted_to(self, node_id: str) -> list[Path]:
        """Tous les chemins simples partant d'un point d'entrée non fiable et
        atteignant `node_id`, chacun portant les trust boundaries franchies.

        C'est la requête centrale : pour une ressource, elle révèle si un attaquant
        contrôlant une entrée non fiable (prompt utilisateur ou contenu RAG) peut
        l'atteindre, et à travers quelles frontières de privilège."""
        target = self.get_node(node_id)
        if target is None:
            return []

        boundary_by_id = {b.id: b for b in self.boundaries}
        out_edges: dict[str, list[Edge]] = {}
        for e in self.edges:
            out_edges.setdefault(e.source_id, []).append(e)

        results: list[Path] = []

        def dfs(current_id: str, visited: set[str], path_nodes: list[Node], path_edges: list[Edge]) -> None:
            if current_id == node_id:
                crossed = [
                    boundary_by_id[e.boundary_id]
                    for e in path_edges
                    if e.boundary_id and e.boundary_id in boundary_by_id
                ]
                results.append(Path(nodes=list(path_nodes), edges=list(path_edges), crossed_boundaries=crossed))
                return
            for e in out_edges.get(current_id, []):
                if e.target_id in visited:
                    continue
                nxt = self.get_node(e.target_id)
                if nxt is None:
                    continue
                visited.add(e.target_id)
                path_nodes.append(nxt)
                path_edges.append(e)
                dfs(e.target_id, visited, path_nodes, path_edges)
                path_nodes.pop()
                path_edges.pop()
                visited.discard(e.target_id)

        for entry in self.untrusted_entry_points():
            if entry.id == node_id:
                results.append(Path(nodes=[entry], edges=[], crossed_boundaries=[]))
                continue
            dfs(entry.id, {entry.id}, [entry], [])

        return results
