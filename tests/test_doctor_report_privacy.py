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

from codex_plugin_scanner.guard.cli import update_commands
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


@pytest.fixture
def blocked_install(monkeypatch: pytest.MonkeyPatch, account_home: Path) -> Path:
    """An install whose native runtime is missing and recoverable by hand.

    The report only carries ``manual_install`` for a host that has no bundled
    runtime, runs on a platform the release publishes a wheel for, knows its
    own version, and is not managed by Desktop. A checkout that has the native
    binary built satisfies none of that, so without these inputs the privacy
    assertions below would pass over a report with nothing in it to redact.
    """

    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_commands, "native_platform_supported", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.58.0")
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(native, "_platform_tags", lambda: ["macosx_11_0_arm64"])
    return account_home


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


def test_a_shell_with_no_home_set_leaves_the_path_as_it_is(monkeypatch: pytest.MonkeyPatch, account_home: Path) -> None:
    # On POSIX the home lookup falls back to the password database when `HOME`
    # is unset, so it still answers with the account's directory -- but the
    # printed command expands `$HOME` in the reader's shell, where it is empty.
    # Rewriting against the fallback would name an interpreter under `/`.
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setattr(native.os.path, "expanduser", lambda _path: str(account_home))
    executable = str(account_home / "venv" / "bin" / "python")

    assert native._account_free_executable(executable) == executable


def test_an_empty_home_leaves_the_path_as_it_is(monkeypatch: pytest.MonkeyPatch, account_home: Path) -> None:
    # `HOME=/` rstrips to the empty string, which every absolute path starts
    # with; rewriting against it would turn the whole path into `$HOME/...`.
    monkeypatch.setenv("HOME", "/")
    executable = str(account_home / "venv" / "bin" / "python")

    assert native._account_free_executable(executable) == executable


def test_the_whole_report_names_no_account(blocked_install: Path, tmp_path: Path) -> None:
    guard_home = tmp_path / ACCOUNT / ".hol-guard"
    guard_home.mkdir(parents=True)

    section = native_runtime_section(guard_home, repair={"status": "ok", "steps": []})

    # The payload is what `runtime status --json` prints, so it is checked both
    # as the structure it is and as the text a reader copies out of a terminal.
    for text in [*_strings(section), json.dumps(section, default=str)]:
        assert ACCOUNT not in text, text
        assert str(blocked_install) not in text, text


def test_the_report_still_tells_a_blocked_install_what_to_run(blocked_install: Path, tmp_path: Path) -> None:
    # The redaction above is worth nothing if it empties the one field that
    # tells a user how to recover, so the command has to survive it.
    guard_home = tmp_path / ACCOUNT / ".hol-guard"
    guard_home.mkdir(parents=True)

    bundled: Any = native_runtime_section(guard_home).get("bundled")

    assert bundled is not None
    assert bundled.get("status") == "missing"
    manual = bundled["manual_install"]
    assert "hol_guard-" in manual
    assert ACCOUNT not in manual
    assert manual.startswith('"$HOME/venv/bin/python" -m pip install')
