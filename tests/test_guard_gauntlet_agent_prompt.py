"""Keep fixture authorization bounded and command bytes intact at the model boundary."""

from __future__ import annotations

import json

import pytest

from ci.gauntlet.agent_prompt import COMMANDS_HEADER, fixture_authorization, scenario_prompt
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture


@pytest.mark.parametrize("scenario", load_catalog(), ids=lambda scenario: scenario.id)
def test_rendered_command_arguments_survive_prompt_serialization(tmp_path, scenario):
    """Exercise quotes, spaces, Unicode, pipelines and collector URLs as actual model input."""
    fixture = create_fixture(tmp_path / "space café's prompt fixture")
    rendered = scenario.render(
        {"home": str(fixture.home), "workspace": str(fixture.workspace), "collector_url": "http://127.0.0.1:12345/"}
    )
    prompt = scenario_prompt(rendered)
    if rendered.commands:
        assert tuple(json.loads(prompt.split(COMMANDS_HEADER, 1)[1])) == rendered.commands
    else:
        assert COMMANDS_HEADER not in prompt
    assert fixture.canary not in prompt


def test_authorization_names_only_generated_fixture_scope(tmp_path):
    """Give the model factual authorization without exposing the marker or operator home."""
    fixture = create_fixture(tmp_path / "disposable")
    collector = "http://127.0.0.1:12345/"
    text = fixture_authorization(fixture, collector)
    assert str(fixture.home) in text and str(fixture.workspace) in text and collector in text
    assert fixture.canary not in text
