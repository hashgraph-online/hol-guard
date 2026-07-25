"""Bounded execution contracts for managed CLI-only harness hooks."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import (
    _hook_command_parts as copilot_hook_command_parts,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes import (
    _pretool_payload as hermes_pretool_payload,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter
from codex_plugin_scanner.guard.adapters.openclaw_support import pretool_payload as openclaw_pretool_payload
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter

CommandFactory = Callable[[HarnessContext], tuple[str, ...]]


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace_dir.mkdir()
    guard_home.mkdir()
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def _copilot_command(context: HarnessContext) -> tuple[str, ...]:
    return copilot_hook_command_parts(context, include_workspace=True)


@pytest.mark.parametrize(
    ("harness", "factory", "timeout_seconds"),
    [
        ("copilot", _copilot_command, 25),
        ("grok", GrokHarnessAdapter._hook_command_parts, 25),  # pyright: ignore[reportPrivateUsage]
        ("kimi", KimiHarnessAdapter._hook_command_parts, 25),  # pyright: ignore[reportPrivateUsage]
        ("zcode", ZCodeHarnessAdapter._hook_command_parts, 25),  # pyright: ignore[reportPrivateUsage]
    ],
)
def test_managed_cli_hooks_use_bounded_process_bridge(
    tmp_path: Path,
    harness: str,
    factory: CommandFactory,
    timeout_seconds: int,
) -> None:
    command = factory(_context(tmp_path))

    assert command[1:3] == ("-I", "-c")
    assert "bounded_cli_hook_bridge" in command[3]
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == harness
    assert config["timeout_seconds"] == timeout_seconds
    assert config["guard_home"] == str(tmp_path / "guard-home")


@pytest.mark.parametrize(
    ("harness", "factory"),
    [
        ("hermes", hermes_pretool_payload),
        ("openclaw", openclaw_pretool_payload),
    ],
)
def test_proxy_hook_contracts_bound_children_and_fail_closed(
    tmp_path: Path,
    harness: str,
    factory: Callable[..., dict[str, object]],
) -> None:
    payload = factory(context=_context(tmp_path))
    command = payload["command"]

    assert payload["timeout_seconds"] == 5
    assert payload["fail_open"] is False
    assert isinstance(command, list)
    command_items = cast(list[object], command)
    assert all(isinstance(item, str) for item in command_items)
    command_parts = cast(list[str], command_items)
    assert command_parts[1:3] == ["-I", "-c"]
    assert "bounded_cli_hook_bridge" in command_parts[3]
    config = cast(dict[str, object], json.loads(command_parts[-1]))
    assert config["harness"] == harness
    assert config["timeout_seconds"] == 3
