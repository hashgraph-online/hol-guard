"""Changing Guard homes must not leave deleted clients blocking Grok."""

import json
from pathlib import Path

import pytest
import tomlkit

from codex_plugin_scanner.guard.adapters.base import _shell_command
from codex_plugin_scanner.guard.adapters.cursor_hook_config import isolated_cursor_hook_python
from codex_plugin_scanner.guard.adapters.grok_user_config import prepare_user_config_text
from codex_plugin_scanner.guard.cli.grok_hook_validation import is_missing_grok_hook_command


def command(home: Path, *, workspace: Path | None = None) -> str:
    args = ["guard", "hook", "--guard-home", str(home), "--harness", "grok"]
    if workspace is not None:
        args.extend(["--workspace", str(workspace)])
    config = {
        "harness": "grok",
        "guard_home": str(home),
        "package_root": str(home / "package"),
        "python_executable": str(home / "python"),
        "frozen_launcher": False,
        "timeout_seconds": 85,
        "cli_args": [*args, "--json"],
    }
    interpreter = isolated_cursor_hook_python()
    assert interpreter is not None
    return _shell_command((interpreter, "-I", str(home / "managed/bounded-hooks/grok.py"), json.dumps(config)))


def test_repair_removes_orphans_even_without_their_ownership_record(tmp_path: Path) -> None:
    stale = command(tmp_path / "deleted-verification-home")
    current = command(tmp_path / "durable-home")
    original, _ = prepare_user_config_text('# Keep user preferences\nmodel="example"\n', stale, previous_state={})
    script = tmp_path / "deleted-verification-home/managed/bounded-hooks/grok.py"
    script.parent.mkdir(parents=True)
    script.write_text("# original client\n")
    duplicated, state = prepare_user_config_text(original, current, previous_state={})
    script.unlink()
    repaired, state = prepare_user_config_text(duplicated, current, previous_state=state)
    repeated, _ = prepare_user_config_text(repaired, current, previous_state=state)
    assert stale not in repaired
    assert repeated == repaired
    assert "# Keep user preferences" in repaired
    for groups in tomlkit.parse(repaired)["hooks"].values():
        assert len(groups) == 1
        assert groups[0]["hooks"][0]["command"] == current


@pytest.mark.parametrize("variant", ["present", "home", "matcher", "multi", "shell", "path", "invalid"])
def test_repair_preserves_other_hooks(tmp_path: Path, variant: str) -> None:
    stale = command(tmp_path / "old")
    current = command(tmp_path / "new")
    if variant == "present":
        script = tmp_path / "old/managed/bounded-hooks/grok.py"
        script.parent.mkdir(parents=True)
        script.write_text("# existing client\n")
    if variant == "shell":
        stale += " ; echo other"
    if variant == "path":
        stale = stale.replace("bounded-hooks/grok.py", "bounded-hooks/user.py")
    if variant == "invalid":
        stale = stale.replace('"harness": "grok"', '"harness": "other"')
    if variant == "home":
        stale = stale.replace('["guard", "hook",', '["guard", "hook", "--home", ' + json.dumps(str(tmp_path)) + ",")
    original, _ = prepare_user_config_text("", stale, previous_state={})
    document = tomlkit.parse(original)
    for groups in document["hooks"].values():
        if variant == "matcher":
            groups[0]["matcher"] = "custom_tool"
        if variant == "multi":
            groups[0]["hooks"].append(tomlkit.item({"type": "command", "command": "custom-check"}))
    repaired, _ = prepare_user_config_text(tomlkit.dumps(document), current, previous_state={})
    for groups in tomlkit.parse(repaired)["hooks"].values():
        assert len(groups) == 2
        assert groups[0]["hooks"][0]["command"] == stale


def test_missing_client_is_not_operational_hook_evidence(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.grok_hook_validation import is_grok_hook_command

    stale = command(tmp_path / "deleted")
    assert is_missing_grok_hook_command(stale, command(tmp_path / "current"))
    assert not is_grok_hook_command(stale)


def test_workspace_fallback_changes_do_not_retain_missing_global_client(tmp_path: Path) -> None:
    assert is_missing_grok_hook_command(
        command(tmp_path / "old"), command(tmp_path / "new", workspace=tmp_path / "project")
    )
