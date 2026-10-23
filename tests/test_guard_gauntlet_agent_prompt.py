"""Keep fixture authorization bounded and command bytes intact at the model boundary."""

from __future__ import annotations

import json

import pytest

from ci.gauntlet.agent_prompt import (
    COMMANDS_HEADER,
    JSON_COMMANDS_HEADER,
    command_block,
    fixture_authorization,
    plain_line,
    scenario_prompt,
)
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture, scratch_checkout, stage_directory
from ci.gauntlet.session_folder import CASES as SESSION_FOLDER_CASES
from ci.gauntlet.session_folder import session_cwd


@pytest.mark.parametrize("scenario", load_catalog(), ids=lambda scenario: scenario.id)
def test_rendered_command_arguments_survive_prompt_serialization(tmp_path, scenario):
    """Exercise quotes, spaces, Unicode, pipelines and collector URLs as actual model input."""
    fixture = create_fixture(tmp_path / "space café's prompt fixture")
    rendered = scenario.render(
        {
            "home": str(fixture.home),
            "workspace": str(fixture.workspace),
            "root": str(fixture.root),
            "scratch": str(scratch_checkout(fixture.root)),
            "stage": str(stage_directory(fixture.root)),
            "collector_url": "http://127.0.0.1:12345/",
        }
    )
    prompt = scenario_prompt(rendered)
    if rendered.commands and not all(plain_line(command) for command in rendered.commands):
        # A multi-line command (a heredoc) is listed as JSON, which decodes to the exact text.
        assert tuple(json.loads(prompt.split(JSON_COMMANDS_HEADER, 1)[1])) == rendered.commands
    elif rendered.commands:
        assert tuple(prompt.split(COMMANDS_HEADER, 1)[1].split("\n")) == rendered.commands
        assert '\\"' not in prompt.split(COMMANDS_HEADER, 1)[1]
    else:
        assert COMMANDS_HEADER not in prompt
    assert fixture.canary not in prompt
    authorization = fixture_authorization(fixture, "http://127.0.0.1:12345/", rendered)
    batch_context = "three independent native read calls in a single assistant response"
    assert (batch_context in authorization) == (scenario.oracle == "mixed-read-batch")
    assert "never authorizes bypassing or retrying a denial" in authorization or scenario.oracle != "mixed-read-batch"
    assert fixture.canary not in authorization


@pytest.mark.parametrize("command", ["", " ls", "ls ", "echo a\necho b", "echo a\recho b"])
def test_a_command_one_plain_line_would_change_keeps_the_json_list(command):
    """A plain line has no escaping, so text it cannot carry exactly is listed as JSON instead."""
    block = command_block(["ls", command])
    assert block.startswith(JSON_COMMANDS_HEADER)
    assert json.loads(block.removeprefix(JSON_COMMANDS_HEADER)) == ["ls", command]


def test_a_newline_in_the_work_root_still_builds_the_prompt(tmp_path):
    """A rendered path with a line break falls back to JSON rather than aborting the case."""
    fixture = create_fixture(tmp_path / "line\nbreak")
    scenario = next(item for item in load_catalog() if any("{{home}}" in command for command in item.commands))
    rendered = scenario.render({"home": str(fixture.home), "workspace": str(fixture.workspace), "collector_url": ""})
    prompt = scenario_prompt(rendered)
    assert tuple(json.loads(prompt.split(JSON_COMMANDS_HEADER, 1)[1])) == rendered.commands


def test_watch_guidance_stays_outside_the_command_block():
    """Only the Watch command follows the header, so its timeout guidance is never run as Bash."""
    from ci.gauntlet.case_helpers import _scenario_prompt

    watch = next(item for item in load_catalog() if item.oracle == "watch-command")
    head, block = _scenario_prompt(watch).split(COMMANDS_HEADER, 1)
    assert tuple(block.split("\n")) == watch.commands
    assert "Set timeout to 120 seconds explicitly." in head


def test_authorization_names_only_generated_fixture_scope(tmp_path):
    """Give the model factual authorization without exposing the marker or operator home."""
    fixture = create_fixture(tmp_path / "disposable")
    collector = "http://127.0.0.1:12345/"
    text = fixture_authorization(fixture, collector)
    assert str(fixture.home) in text and str(fixture.workspace) in text and collector in text
    assert fixture.canary not in text


def test_watch_context_omits_typed_paths_so_bash_uses_its_default_cwd(tmp_path):
    """Watch scope rejects a mistyped cwd before Guard runs, so the case never asks for one."""
    fixture = create_fixture(tmp_path / "disposable")
    collector = "http://127.0.0.1:12345/"
    watch = next(item for item in load_catalog() if item.oracle == "watch-command")
    text = fixture_authorization(fixture, collector, watch)
    assert str(fixture.home) not in text and str(fixture.workspace) not in text
    assert "needs no cwd argument" in text and collector in text
    other = next(item for item in load_catalog() if item.oracle != "watch-command")
    assert str(fixture.workspace) in fixture_authorization(fixture, collector, other)


def _first_contact_fixture(tmp_path, scenario_id: str):
    """A realistic first-contact fixture, built the way the live runner builds one."""
    return create_fixture(tmp_path / "disposable", realistic=True, scenario_id=scenario_id)


def test_a_session_started_beside_the_checkout_is_told_so_rather_than_given_a_project(tmp_path):
    """Naming the generated workspace as the project contradicts the work these cases ask for.

    Both runs of the shell case at the 3.50.0 head died on that contradiction, one
    refusing every listed command and one looking for project instructions instead,
    so neither reached Guard at all.
    """
    scenario = next(item for item in load_catalog() if item.id in SESSION_FOLDER_CASES)
    fixture = _first_contact_fixture(tmp_path, scenario.id)
    session = session_cwd(fixture.home, fixture.workspace, scenario.id)
    assert session != fixture.workspace
    text = fixture_authorization(fixture, "http://127.0.0.1:12345/", scenario, session)
    assert str(session) in text and str(fixture.workspace) not in text
    assert "designates no project of its own" in text


def test_a_session_inside_its_own_checkout_still_names_the_project(tmp_path):
    """Every other first-contact case does start in the project, and is told exactly that."""
    scenario = next(
        item for item in load_catalog() if item.oracle == "native-tools" and item.id not in SESSION_FOLDER_CASES
    )
    fixture = _first_contact_fixture(tmp_path, scenario.id)
    session = session_cwd(fixture.home, fixture.workspace, scenario.id)
    assert session == fixture.workspace
    text = fixture_authorization(fixture, "http://127.0.0.1:12345/", scenario, session)
    assert str(fixture.workspace) in text and "Every tool already starts in the project" in text


def test_a_lane_that_cannot_choose_a_working_directory_keeps_the_project_wording(tmp_path):
    """Harness lanes run the session-folder cases from the project, so there the project is real."""
    scenario = next(item for item in load_catalog() if item.id in SESSION_FOLDER_CASES)
    fixture = _first_contact_fixture(tmp_path, scenario.id)
    text = fixture_authorization(fixture, "http://127.0.0.1:12345/", scenario)
    assert str(fixture.workspace) in text and "Every tool already starts in the project" in text
