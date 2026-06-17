"""Définit l'interface Rule et la dataclass Finding (titre, sévérité, explication, mitigation) communes à tous les modules de règles."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Sévérité d'un finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Résultat d'une règle : un risque identifié sur le modèle de menace."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    explanation: str
    mitigation: str
    affected_resources: list[str] = field(default_factory=list)
    owasp_ref: str | None = None
