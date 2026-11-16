"""Bounded execution contracts for managed CLI-only harness hooks."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import (
    _hook_command_parts as copilot_hook_command_parts,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.adapters.hermes import (
    _pretool_payload as hermes_pretool_payload,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.adapters.native_harness import NativeHarnessAdapter

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


def _native_command(harness: str) -> CommandFactory:
    def command(context: HarnessContext) -> tuple[str, ...]:
        adapter = get_adapter(harness)
        assert isinstance(adapter, NativeHarnessAdapter)
        return tuple(adapter._hook_argv(context))  # pyright: ignore[reportPrivateUsage]

    return command


def openclaw_pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    prepared = get_adapter("openclaw").prepare_install(context)
    pretool = next(change for change in prepared.files if change.path.name == "pretool-hook.json")
    assert pretool.after is not None
    return cast(dict[str, object], json.loads(pretool.after))


@pytest.mark.parametrize(
    ("harness", "factory", "timeout_seconds"),
    [
        ("copilot", _copilot_command, 25),
        ("grok", _native_command("grok"), 85),
        ("kimi", _native_command("kimi"), 25),
        ("zcode", _native_command("zcode"), 25),
    ],
)
def test_managed_cli_hooks_use_bounded_process_bridge(
    tmp_path: Path,
    harness: str,
    factory: CommandFactory,
    timeout_seconds: int,
) -> None:
    context = _context(tmp_path)
    command = factory(context)

    # Without a runtime to wrap it, Grok registers the bridge like the others.
    assert command[1:3] == ("-I", "-c")
    assert "bounded_cli_hook_bridge" in command[3]
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == harness
    assert config["timeout_seconds"] == timeout_seconds
    assert config["guard_home"] == str(tmp_path / "guard-home")


@pytest.mark.parametrize(
    ("harness", "factory"),
    [
        ("copilot", _copilot_command),
        ("kimi", _native_command("kimi")),
        ("zcode", _native_command("zcode")),
    ],
)
def test_frozen_managed_cli_hooks_hand_off_to_the_runtime_not_a_stdlib_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
    factory: CommandFactory,
) -> None:
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge.isolated_cursor_hook_python",
        lambda: "/usr/bin/python3",
    )

    context = _context(tmp_path)
    command = factory(context)

    assert command[0] != "/usr/bin/python3"
    assert "__guard-bounded-hook" in command
    assert not (context.guard_home / "managed" / "bounded-hooks" / f"{harness}.py").exists()
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == harness


def test_frozen_grok_hook_without_a_runtime_registers_the_bridge_not_the_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The bare client fails closed on every deciding hook. The bridge form looks
    # the runtime up on each hook, so the install recovers once one appears.
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge.isolated_cursor_hook_python",
        lambda: "/usr/bin/python3",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge.native_bridge_executable",
        lambda *_args, **_kwargs: None,
    )

    command = _native_command("grok")(_context(tmp_path))

    assert command[0] != "/usr/bin/python3"
    assert command[1] == "__guard-bounded-hook"
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == "grok"


def test_frozen_grok_hook_with_a_runtime_wraps_its_isolated_constants_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge.isolated_cursor_hook_python",
        lambda: "/usr/bin/python3",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge.native_bridge_executable",
        lambda *_args, **_kwargs: runtime,
    )

    command = _native_command("grok")(_context(tmp_path))

    assert command[:4] == (str(runtime), "bounded-hook-bridge", "/usr/bin/python3", "-I")
    assert Path(command[4]).name == "grok.py"
    source = Path(command[4]).read_text(encoding="utf-8")
    assert 'HARNESS = "grok"' in source
    assert "daemon --serve" not in source


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
