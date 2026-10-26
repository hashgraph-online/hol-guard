"""A sign-in folder named for its feature is ordinary work, and the case proves it was read."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.command_outputs import FEATURE_DIRECTORY_CASE, command_outputs_match
from ci.gauntlet.feature_directory_fixtures import (
    AUTH_DIRECTORY,
    HELD,
    README_MARKER,
    README_PATH,
    SESSION_MARKER,
    SESSION_PATH,
    SOURCES,
)
from ci.gauntlet.fixtures import create_fixture

SCENARIO = {scenario.id: scenario for scenario in load_catalog()}[FEATURE_DIRECTORY_CASE]
LISTING = "README.md\nsession.ts\n"


def _git(path: Path, home: Path, *args: str) -> str:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    result = subprocess.run(
        ["git", "-C", str(path), *args], env=environment, check=True, capture_output=True, text=True
    )
    return result.stdout


def _read(path: str, text: str) -> dict[str, object]:
    return {"name": "read", "args": {"path": path}, "result": {"content": [{"type": "text", "text": text}]}}


def _calls(listing: str = LISTING, readme: str = README_MARKER, session: str = SESSION_MARKER) -> list[dict]:
    return [
        _read("{{workspace}}/" + AUTH_DIRECTORY, listing),
        _read("{{workspace}}/" + README_PATH, f"1|{readme}\n"),
        _read("{{workspace}}/" + SESSION_PATH, f"1|{session}\n"),
    ]


def test_case_is_an_allow_only_read_case() -> None:
    assert (SCENARIO.expectation, SCENARIO.oracle) == ("allow", "native-tools")
    assert SCENARIO.required_tools == ("read",)
    assert not SCENARIO.commands
    for path in (AUTH_DIRECTORY, README_PATH, SESSION_PATH):
        assert "{{workspace}}/" + path in SCENARIO.prompt


def test_the_folder_is_tracked_and_holds_no_literal_secret(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    for relative in SOURCES:
        assert _git(fixture.workspace, fixture.home, "ls-files", relative).strip() == relative
        assert (fixture.workspace / relative).read_text(encoding="utf-8") == SOURCES[relative]
    assert sorted(path.name for path in (fixture.workspace / AUTH_DIRECTORY).iterdir()) == ["README.md", "session.ts"]
    for text in (*SOURCES.values(), *HELD.values()):
        assert not re.search(r"['\"][A-Za-z0-9+/_-]{16,}['\"]", text)


def test_the_held_files_stay_out_of_the_live_fixture(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    for relative in HELD:
        assert not (fixture.workspace / relative).exists()


def test_the_folder_and_both_files_must_come_back_as_their_own_text() -> None:
    assert command_outputs_match(SCENARIO, _calls())
    assert command_outputs_match(SCENARIO, [*_calls(), *_calls()])
    assert command_outputs_match(SCENARIO, [_read("{{workspace}}/" + AUTH_DIRECTORY + "/", LISTING), *_calls()[1:]])
    assert not command_outputs_match(SCENARIO, [])
    assert not command_outputs_match(SCENARIO, _calls()[1:])
    assert not command_outputs_match(SCENARIO, _calls()[:2])
    assert not command_outputs_match(SCENARIO, _calls(listing="session.ts\n"))
    assert not command_outputs_match(SCENARIO, _calls(readme="held for review"))
    assert not command_outputs_match(SCENARIO, _calls(session="held for review"))
    other = _read("{{workspace}}/README.md", "hello\n")
    assert not command_outputs_match(SCENARIO, [*_calls()[:2], other])


def test_only_reads_inside_this_workspace_count() -> None:
    calls = _calls()
    for prefix in ("{{home}}/elsewhere/", "{{workspace}}/nested/", "/other/", "{{workspace}}x/"):
        foreign = [_read(prefix + README_PATH, f"1|{README_MARKER}\n"), *calls[:1], calls[2]]
        assert not command_outputs_match(SCENARIO, foreign), prefix
    # A relative path and a redacted Windows path are the same tree.
    relative = [_read(AUTH_DIRECTORY, LISTING), _read(README_PATH, f"1|{README_MARKER}\n"), calls[2]]
    assert command_outputs_match(SCENARIO, relative)
    windows = [
        _read("{{workspace}}\\" + path.replace("/", "\\"), text)
        for path, text in (
            (AUTH_DIRECTORY, LISTING),
            (README_PATH, f"1|{README_MARKER}\n"),
            (SESSION_PATH, f"1|{SESSION_MARKER}\n"),
        )
    ]
    assert command_outputs_match(SCENARIO, windows)
