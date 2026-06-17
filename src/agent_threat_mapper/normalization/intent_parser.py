"""Parse le fichier texte décrivant le rôle métier de l'agent vers la dataclass models.agent_intent."""

from __future__ import annotations

from pathlib import Path

from agent_threat_mapper.models.agent_intent import AgentIntent, AutonomyLevel

_AUTONOMY_MAP: dict[str, AutonomyLevel] = {
    "autonomous": AutonomyLevel.AUTONOMOUS,
    "supervised": AutonomyLevel.SUPERVISED,
    "human_in_the_loop": AutonomyLevel.HUMAN_IN_THE_LOOP,
    "human-in-the-loop": AutonomyLevel.HUMAN_IN_THE_LOOP,
}


def parse_intent(source: Path | str) -> AgentIntent:
    """Parse *source* (fichier ou chaîne texte) et retourne un AgentIntent.

    Format attendu ::

        name: <nom de l'agent>
        autonomy: autonomous|supervised|human_in_the_loop

        allowed:
        - <action>
        - <action>

        forbidden:
        - <action>
    """
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8")
    else:
        text = source

    name = ""
    autonomy_level = AutonomyLevel.SUPERVISED
    allowed: list[str] = []
    forbidden: list[str] = []

    current_section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        lower = line.lower()

        if lower.startswith("name:"):
            name = line[len("name:"):].strip()
            current_section = None
        elif lower.startswith("autonomy:"):
            value = line[len("autonomy:"):].strip().lower()
            autonomy_level = _AUTONOMY_MAP.get(value, AutonomyLevel.SUPERVISED)
            current_section = None
        elif lower.rstrip(":") == "allowed":
            current_section = "allowed"
        elif lower.rstrip(":") == "forbidden":
            current_section = "forbidden"
        elif line.startswith("-"):
            item = line[1:].strip()
            if current_section == "allowed":
                allowed.append(item)
            elif current_section == "forbidden":
                forbidden.append(item)

    if not name:
        raise ValueError("Le fichier de rôle ne contient pas de champ 'name:'.")

    return AgentIntent(
        name=name,
        autonomy_level=autonomy_level,
        allowed_actions=allowed,
        forbidden_actions=forbidden,
    )
