"""Tests du parsing du fichier de rôle métier vers la dataclass agent_intent."""

from pathlib import Path
from textwrap import dedent

import pytest

from agent_threat_mapper.models.agent_intent import AgentIntent, AutonomyLevel
from agent_threat_mapper.normalization.intent_parser import parse_intent

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAMPLE_TXT = FIXTURES / "agent_role_sample.txt"


@pytest.fixture
def intent() -> AgentIntent:
    return parse_intent(SAMPLE_TXT)


def test_returns_agent_intent(intent):
    assert isinstance(intent, AgentIntent)


def test_name(intent):
    assert intent.name == "Document Summarization Agent"


def test_autonomy_level(intent):
    assert intent.autonomy_level == AutonomyLevel.SUPERVISED


def test_allowed_actions(intent):
    assert len(intent.allowed_actions) == 4
    assert "read documents from Azure Blob Storage" in intent.allowed_actions
    assert "query Azure AI Search index" in intent.allowed_actions


def test_forbidden_actions(intent):
    assert len(intent.forbidden_actions) == 4
    assert "write or delete any storage blobs" in intent.forbidden_actions
    assert "modify IAM role assignments" in intent.forbidden_actions


def test_autonomous_level():
    text = dedent("""\
        name: Fully Autonomous Bot
        autonomy: autonomous

        allowed:
        - do everything
    """)
    intent = parse_intent(text)
    assert intent.autonomy_level == AutonomyLevel.AUTONOMOUS
    assert intent.name == "Fully Autonomous Bot"


def test_human_in_the_loop_with_hyphen():
    text = dedent("""\
        name: Safe Bot
        autonomy: human-in-the-loop

        forbidden:
        - act without approval
    """)
    intent = parse_intent(text)
    assert intent.autonomy_level == AutonomyLevel.HUMAN_IN_THE_LOOP
    assert intent.forbidden_actions == ["act without approval"]
    assert intent.allowed_actions == []


def test_comments_and_blank_lines_ignored():
    text = dedent("""\
        # This is a comment
        name: Test Agent
        autonomy: supervised

        # another comment

        allowed:
        - read blobs

        forbidden:
        - write blobs
    """)
    intent = parse_intent(text)
    assert intent.name == "Test Agent"
    assert intent.allowed_actions == ["read blobs"]
    assert intent.forbidden_actions == ["write blobs"]


def test_missing_name_raises():
    text = "autonomy: supervised\nallowed:\n- read"
    with pytest.raises(ValueError, match="name"):
        parse_intent(text)


def test_unknown_autonomy_defaults_to_supervised():
    text = "name: X\nautonomy: robot"
    intent = parse_intent(text)
    assert intent.autonomy_level == AutonomyLevel.SUPERVISED
