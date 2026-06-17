"""Dataclass(es) représentant le rôle métier déclaré de l'agent : actions autorisées, actions interdites, niveau d'autonomie."""

from dataclasses import dataclass
from enum import Enum


class AutonomyLevel(Enum):
    """Niveau d'autonomie déclaré de l'agent."""

    AUTONOMOUS = "autonomous"
    SUPERVISED = "supervised"
    HUMAN_IN_THE_LOOP = "human_in_the_loop"


@dataclass
class AgentIntent:
    """Intention métier de l'agent, telle que parsée depuis son fichier de rôle texte."""

    name: str
    autonomy_level: AutonomyLevel
    allowed_actions: list[str]
    forbidden_actions: list[str]
