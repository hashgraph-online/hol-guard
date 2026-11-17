"""Shared Grok adapter fixtures."""

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "grok" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def grok_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    """The hook argv the native Grok adapter registers."""
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters.native_harness import NativeHarnessAdapter

    adapter = get_adapter("grok")
    assert isinstance(adapter, NativeHarnessAdapter)
    return tuple(adapter._hook_argv(context))  # pyright: ignore[reportPrivateUsage]


def grok_paths(context: HarnessContext) -> dict[str, Path]:
    """The managed config and hook files the native Grok adapter names."""
    from codex_plugin_scanner.guard.cli.native_install_checks import grok_protection

    protection = grok_protection(context)
    return {
        "config": Path(protection["config_path"]),
        "pretool": Path(protection["pretool_hook_path"]),
        "prompt": Path(protection["prompt_hook_path"]),
        "state": context.guard_home / "managed" / "grok" / "install.state.json",
    }


def prepare_user_config_text(
    existing_text: str, hook_command: str, *, previous_state: dict[str, object]
) -> tuple[str, dict[str, object]]:
    """Drive the native Grok user-config merge the way the adapter install does."""
    from codex_plugin_scanner.guard.cli.grok_hook_validation import is_missing_grok_hook_command
    from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority

    read: dict[str, object] = {"existing_text": existing_text, "previous_state": previous_state}
    commands = native_runner_authority("grok_user_config", {**read, "mode": "candidates"})["commands"]
    retired = [command for command in commands if is_missing_grok_hook_command(command, hook_command)]
    answer = native_runner_authority(
        "grok_user_config", {**read, "hook_command": hook_command, "mode": "merge", "retired_commands": retired}
    )
    return answer["merged"], answer["state"]
