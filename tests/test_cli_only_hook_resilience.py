"""Bounded execution contracts for managed CLI-only harness hooks."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_caller
from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import (
    _hook_fields as copilot_hook_fields,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.adapters.native_harness import NativeHarnessAdapter
from tests.native_bounded_runtime import use_bounded_runtime

CommandFactory = Callable[[HarnessContext], tuple[str, ...]]
_BRIDGE = "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge"


@pytest.fixture
def runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, path)
    return path


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
    return tuple(cast(list[str], copilot_hook_fields(context)["workspace_argv"]))


def _native_command(harness: str) -> CommandFactory:
    def command(context: HarnessContext) -> tuple[str, ...]:
        adapter = get_adapter(harness)
        assert isinstance(adapter, NativeHarnessAdapter)
        return tuple(adapter._hook_argv(context))  # pyright: ignore[reportPrivateUsage]

    return command


def _planned_pretool_payload(harness: str, context: HarnessContext) -> dict[str, object]:
    adapter = get_adapter(harness)
    assert isinstance(adapter, NativeHarnessAdapter)
    # Hermes refuses a bare plan; its install publishes the native plan directly.
    prepared = NativeHarnessAdapter.prepare_install(adapter, context)
    pretool = next(change for change in prepared.files if change.path.name == "pretool-hook.json")
    assert pretool.after is not None
    return cast(dict[str, object], json.loads(pretool.after))


def openclaw_pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    return _planned_pretool_payload("openclaw", context)


def hermes_pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    return _planned_pretool_payload("hermes", context)


@pytest.mark.parametrize(
    ("harness", "factory", "timeout_seconds"),
    [
        ("copilot", _copilot_command, 25),
        ("grok", _native_command("grok"), 85),
        ("kimi", _native_command("kimi"), 25),
        ("zcode", _native_command("zcode"), 25),
    ],
)
def test_managed_cli_hooks_run_the_native_runtime(
    tmp_path: Path,
    runtime: Path,
    harness: str,
    factory: CommandFactory,
    timeout_seconds: int,
) -> None:
    context = _context(tmp_path)
    command = factory(context)

    assert command[:2] == (str(runtime), "bounded-hook-bridge")
    assert len(command) == 3
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == harness
    assert config["timeout_seconds"] == timeout_seconds
    assert config["guard_home"] == str(tmp_path / "guard-home")


@pytest.mark.parametrize(
    ("harness", "factory"),
    [
        ("copilot", _copilot_command),
        ("grok", _native_command("grok")),
        ("kimi", _native_command("kimi")),
        ("zcode", _native_command("zcode")),
    ],
)
def test_frozen_managed_cli_hooks_run_the_durable_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Path,
    harness: str,
    factory: CommandFactory,
) -> None:
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr(f"{_BRIDGE}._trusted_desktop_hook_proxy_command", lambda *_args, **_kwargs: None)

    context = _context(tmp_path)
    command = factory(context)

    assert command[:2] == (str(runtime), "bounded-hook-bridge")
    assert not (context.guard_home / "managed" / "bounded-hooks" / f"{harness}.py").exists()
    config = cast(dict[str, object], json.loads(command[-1]))
    assert config["harness"] == harness
    assert config["frozen_launcher"] is True


@pytest.mark.parametrize("harness", ["copilot", "grok", "kimi", "zcode"])
def test_a_hook_install_without_a_runtime_asks_for_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    monkeypatch.setattr(f"{_BRIDGE}.native_bridge_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(native_caller, "_native_runtime", lambda: None)
    factory = _copilot_command if harness == "copilot" else _native_command(harness)

    with pytest.raises(RuntimeError, match="hol-guard repair"):
        factory(_context(tmp_path))


@pytest.mark.parametrize(
    ("harness", "factory"),
    [
        ("hermes", hermes_pretool_payload),
        ("openclaw", openclaw_pretool_payload),
    ],
)
def test_proxy_hook_contracts_bound_children_and_fail_closed(
    tmp_path: Path,
    runtime: Path,
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
    assert command_parts[:2] == [str(runtime), "bounded-hook-bridge"]
    config = cast(dict[str, object], json.loads(command_parts[-1]))
    assert config["harness"] == harness
    assert config["timeout_seconds"] == 3
