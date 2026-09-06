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
