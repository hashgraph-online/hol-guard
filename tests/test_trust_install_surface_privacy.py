"""The install-surface diagnostics carry no account name.

``hol-guard trust --json`` and ``hol-guard update --json`` print where the
running CLI was found and where its installer puts scripts. A reader pastes
those facts into an issue or a support request, and on every supported
platform a path under the home directory spells out the account name of
whoever ran the command. None of these fields is a command anyone runs, so
each one can name the home directory as ``~`` instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.trust_install_surface import _installed_trust_cli_payload

ACCOUNT = "harriet-example"


def _strings(value: object) -> list[str]:
    """Every string anywhere in the payload, keys included."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for key, item in value.items():
            found.extend(_strings(key))
            found.extend(_strings(item))
        return found
    if isinstance(value, (list, tuple)):
        found = []
        for item in value:
            found.extend(_strings(item))
        return found
    return []


@pytest.fixture
def account_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A pip install whose CLI, interpreter and script directory are all in the home."""

    home = tmp_path / ACCOUNT
    scripts = home / "venv" / "bin"
    scripts.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(update_commands.sys, "executable", str(scripts / "python"))
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.shutil, "which", lambda name: str(scripts / "hol-guard"))
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: str(scripts))
    return home


def test_the_install_surface_payload_names_no_account(account_home: Path) -> None:
    payload = update_commands.build_guard_install_surface_payload()

    assert ACCOUNT not in "\n".join(_strings(payload))


def test_the_diagnostics_still_say_where_the_cli_and_its_scripts_are(account_home: Path) -> None:
    diagnostics = update_commands.build_guard_install_surface_payload()["binary_diagnostics"]

    assert isinstance(diagnostics, dict)
    assert diagnostics["resolved_hol_guard"] == "~/venv/bin/hol-guard"
    assert diagnostics["installer_binary"] == "~/venv/bin/python"
    assert diagnostics["expected_script_dir"] == "~/venv/bin"
    # The install is still recognised as healthy: redaction happens after the
    # comparison that decides the status, not before it.
    assert diagnostics["path_status"] == "matches_installer"


def test_the_trust_payload_names_no_account(account_home: Path) -> None:
    payload = _installed_trust_cli_payload(resolve_distribution=_no_distribution)

    assert ACCOUNT not in "\n".join(_strings(payload))
    assert payload["active_command_path"] == "~/venv/bin/hol-guard"
    assert payload["expected_script_dir"] == "~/venv/bin"


def test_a_desktop_bundle_under_the_home_directory_names_no_account(
    monkeypatch: pytest.MonkeyPatch, account_home: Path
) -> None:
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)

    payload = update_commands.build_guard_install_surface_payload()

    assert ACCOUNT not in "\n".join(_strings(payload))


@pytest.mark.parametrize("installed", ["/usr/local/bin/hol-guard", "/opt/guard/bin/hol-guard"])
def test_a_path_outside_the_home_directory_is_named_as_it_is(
    monkeypatch: pytest.MonkeyPatch, account_home: Path, installed: str
) -> None:
    monkeypatch.setattr(update_commands.shutil, "which", lambda name: installed)

    diagnostics = update_commands.build_guard_install_surface_payload()["binary_diagnostics"]

    assert isinstance(diagnostics, dict)
    assert diagnostics["resolved_hol_guard"] == installed


def test_the_home_directory_itself_is_named_as_the_home(account_home: Path) -> None:
    assert update_commands._account_free_path(str(account_home)) == "~"


def test_a_host_that_will_not_name_a_home_leaves_the_path_as_it_is(
    monkeypatch: pytest.MonkeyPatch, account_home: Path
) -> None:
    def _no_home() -> Path:
        raise RuntimeError("no home directory")

    monkeypatch.setattr(update_commands.Path, "home", staticmethod(_no_home))
    installed = str(account_home / "venv" / "bin" / "hol-guard")

    assert update_commands._account_free_path(installed) == installed


def _no_distribution(name: str):
    raise update_commands.importlib.metadata.PackageNotFoundError(name)
