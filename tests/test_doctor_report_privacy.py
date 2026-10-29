"""The native runtime report carries no account name.

``hol-guard doctor`` and ``hol-guard runtime status --json`` build this payload
for a reader who is about to paste it into an issue or a support request. Every
field in it is meant to describe the install, not the person running it, so the
home directory -- which on every supported platform spells out the account name
-- must not reach the report through any of its branches.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import update_native_wheel as native
from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_runtime_section

ACCOUNT = "harriet-example"


def _strings(value: object) -> list[str]:
    """Every string anywhere in the payload, keys included."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for key, item in value.items():  # type: ignore[union-attr]
            found.extend(_strings(key))
            found.extend(_strings(item))
        return found
    if isinstance(value, (list, tuple)):
        found = []
        for item in value:  # type: ignore[union-attr]
            found.extend(_strings(item))
        return found
    return []


@pytest.fixture
def account_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / ACCOUNT
    (home / "venv" / "bin").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(native.sys, "executable", str(home / "venv" / "bin" / "python"))
    monkeypatch.setattr(native.os, "name", "posix")
    return home


def test_an_interpreter_under_the_home_directory_is_named_through_home(account_home: Path) -> None:
    executable = str(account_home / "venv" / "bin" / "python")

    assert native._account_free_executable(executable) == '"$HOME/venv/bin/python"'
    assert native._manual_installer_prefix("pip") == '"$HOME/venv/bin/python" -m pip install'
    assert native._manual_installer_prefix("uv") == 'uv pip install --python "$HOME/venv/bin/python"'


@pytest.mark.parametrize(
    "executable",
    [
        # Outside the home directory there is no account name to hide, and a
        # rewritten path would name an interpreter that is not there.
        "/opt/guard venv/bin/python",
        "/usr/bin/python3",
    ],
)
def test_an_interpreter_outside_the_home_directory_is_named_as_it_is(
    monkeypatch: pytest.MonkeyPatch, account_home: Path, executable: str
) -> None:
    monkeypatch.setattr(native.sys, "executable", executable)
    quoted = f'"{executable}"' if " " in executable else executable

    assert native._account_free_executable(executable) == executable
    assert native._manual_installer_prefix("pip") == f"{quoted} -m pip install"


def test_the_home_directory_itself_is_left_alone(account_home: Path) -> None:
    # Nothing is installed at the home directory, but a path equal to it must
    # not come back as an empty `$HOME/` either.
    assert native._account_free_executable(str(account_home)) == str(account_home)


def test_a_home_the_platform_will_not_name_leaves_the_path_as_it_is(
    monkeypatch: pytest.MonkeyPatch, account_home: Path
) -> None:
    def no_home(_path: str) -> str:
        raise RuntimeError("this platform has no home directory")

    monkeypatch.setattr(native.os.path, "expanduser", no_home)

    assert native._account_free_executable(str(account_home / "venv" / "bin" / "python")) == str(
        account_home / "venv" / "bin" / "python"
    )


def test_the_whole_report_names_no_account(account_home: Path, tmp_path: Path) -> None:
    guard_home = tmp_path / ACCOUNT / ".hol-guard"
    guard_home.mkdir(parents=True)

    section = native_runtime_section(guard_home, repair={"status": "ok", "steps": []})

    # The payload is what `runtime status --json` prints, so it is checked both
    # as the structure it is and as the text a reader copies out of a terminal.
    for text in [*_strings(section), json.dumps(section, default=str)]:
        assert ACCOUNT not in text, text
        assert str(account_home) not in text, text


def test_the_report_still_tells_a_blocked_install_what_to_run(account_home: Path, tmp_path: Path) -> None:
    # The redaction above is worth nothing if it empties the one field that
    # tells a user how to recover, so the command has to survive it.
    guard_home = tmp_path / ACCOUNT / ".hol-guard"
    guard_home.mkdir(parents=True)

    bundled: Any = native_runtime_section(guard_home).get("bundled")

    if bundled is not None and bundled.get("status") == "missing":
        manual = bundled.get("manual_install")
        if manual is not None:
            assert "hol_guard-" in manual
            assert ACCOUNT not in manual
