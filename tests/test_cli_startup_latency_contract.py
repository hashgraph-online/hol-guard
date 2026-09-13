"""Startup-latency contracts for short-lived hol-guard invocations.

Update flows and hook wrappers spawn the CLI repeatedly; each spawn must not
pay for the full Guard command surface. These tests pin the lazy-import
contracts that keep `--version` and multi-harness installs cheap.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import sys
from pathlib import Path

import pytest

import codex_plugin_scanner
from codex_plugin_scanner.guard.cli.install_targets import _resolve_targets
from codex_plugin_scanner.version import __version__

_COMMANDS_HUB = "codex_plugin_scanner.guard.cli.commands"
_CLI_MODULE = "codex_plugin_scanner.cli"
_COMMANDS_PARSER = "codex_plugin_scanner.guard.cli.commands_parser"
_COMMANDS_SUPPORT = "codex_plugin_scanner.guard.cli.commands_support"


def _run_as_hol_guard(argv: list[str]) -> tuple[int, str]:
    from codex_plugin_scanner.cli import main

    previous_argv = sys.argv
    sys.argv = ["hol-guard", *argv]
    try:
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main(argv)
        return code, captured.getvalue()
    finally:
        sys.argv = previous_argv


def test_hol_guard_version_answers_without_command_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, _COMMANDS_HUB, raising=False)
    monkeypatch.delitem(sys.modules, _CLI_MODULE, raising=False)
    # `import a.b as x` resolves through the parent attribute in addition to
    # sys.modules, so both must be restored for later tests to see one module.
    monkeypatch.delattr(codex_plugin_scanner, "cli", raising=False)

    code, output = _run_as_hol_guard(["--version"])

    assert code == 0
    assert output.strip() == f"hol-guard {__version__}"
    assert _COMMANDS_HUB not in sys.modules


def test_desktop_bootstrap_fast_path_argv_rejects_overrides() -> None:
    from codex_plugin_scanner.guard.cli.desktop_bootstrap import is_desktop_bootstrap_fast_path_argv

    assert is_desktop_bootstrap_fast_path_argv(["desktop", "bootstrap"]) is True
    assert is_desktop_bootstrap_fast_path_argv(["desktop", "bootstrap", "--json"]) is True
    assert is_desktop_bootstrap_fast_path_argv(["desktop", "bootstrap", "--help"]) is False
    assert is_desktop_bootstrap_fast_path_argv(["desktop", "bootstrap", "--guard-home", "other"]) is False
    assert is_desktop_bootstrap_fast_path_argv(["desktop", "dashboard-update"]) is False
    assert is_desktop_bootstrap_fast_path_argv(["status"]) is False


def test_hol_guard_desktop_bootstrap_json_skips_command_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import json

    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    monkeypatch.delitem(sys.modules, _COMMANDS_HUB, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_PARSER, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_SUPPORT, raising=False)
    monkeypatch.delitem(sys.modules, _CLI_MODULE, raising=False)
    monkeypatch.delattr(codex_plugin_scanner, "cli", raising=False)

    code, output = _run_as_hol_guard(["desktop", "bootstrap", "--json"])

    payload = json.loads(output)
    assert code == 0
    assert payload["schema"] == "guard-desktop-bootstrap.v1"
    assert _COMMANDS_HUB not in sys.modules
    assert _COMMANDS_PARSER not in sys.modules
    assert _COMMANDS_SUPPORT not in sys.modules


def test_hol_guard_desktop_bootstrap_fast_path_maps_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import desktop_bootstrap

    monkeypatch.setattr(
        desktop_bootstrap,
        "run_desktop_bootstrap_cli",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("desktop bootstrap failed")),
    )
    monkeypatch.delitem(sys.modules, _CLI_MODULE, raising=False)
    monkeypatch.delattr(codex_plugin_scanner, "cli", raising=False)

    previous_argv = sys.argv
    sys.argv = ["hol-guard", "desktop", "bootstrap", "--json"]
    try:
        captured_err = io.StringIO()
        with contextlib.redirect_stderr(captured_err), contextlib.redirect_stdout(io.StringIO()):
            from codex_plugin_scanner.cli import main

            code = main(["desktop", "bootstrap", "--json"])
    finally:
        sys.argv = previous_argv

    assert code == 1
    assert "desktop bootstrap failed" in captured_err.getvalue()


def test_resolve_targets_accepts_multiple_harnesses(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "current",
        guard_home=tmp_path / "guard-home",
    )

    targets = _resolve_targets("install", ["cursor", "codex", "cursor"], False, context, None)

    assert targets == ["cursor", "codex"]


def test_resolve_targets_keeps_single_harness_contract(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "current",
        guard_home=tmp_path / "guard-home",
    )

    targets = _resolve_targets("install", "cursor", False, context, None)

    assert targets == ["cursor"]


def test_install_list_argument_keeps_single_harness_helpers_working() -> None:
    from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import _command_subject
    from codex_plugin_scanner.guard.cli.commands_support_workspace import _requested_install_harness

    def _args(harness: object, *, all_flag: bool = False) -> argparse.Namespace:
        return argparse.Namespace(harness=harness, all=all_flag, guard_command="install")

    assert _requested_install_harness(_args("cursor")) == "cursor"
    assert _requested_install_harness(_args(["cursor"])) == "cursor"
    assert _requested_install_harness(_args(["cursor", "codex"])) is None
    assert _requested_install_harness(_args([])) is None
    assert _requested_install_harness(_args(None)) is None
    assert _command_subject(_args(["cursor"])) == "cursor"
    assert _command_subject(_args(["cursor", "codex"])) == "cursor,codex"
    assert _command_subject(_args(None)) == "detected"
    assert _command_subject(_args(None, all_flag=True)) == "all"


def test_install_dry_run_reports_every_requested_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setenv("HOL_GUARD_HOME", str(guard_home))

    code, output = _run_as_hol_guard(["install", "cursor", "codex", "--dry-run", "--json"])

    assert code == 0
    import json

    payload = json.loads(output)
    assert [plan.get("harness") for plan in payload.get("setup_plans", [])] == ["cursor", "codex"]
