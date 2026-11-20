"""Changing Guard homes must not leave deleted clients blocking Grok."""

import json
import sys
from pathlib import Path

import pytest
import tomlkit

from codex_plugin_scanner.guard.diagnostics_bridge import shell_command as _shell_command
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests.grok_test_support import prepare_user_config_text
from tests.native_bounded_runtime import hook_config_argv, use_bounded_runtime


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
    # Command recognition must not depend on a system isolated interpreter.
    return _shell_command((sys.executable, "-I", str(home / "managed/bounded-hooks/grok.py"), json.dumps(config)))


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


@pytest.mark.parametrize("frozen", [False, True])
def test_repair_replaces_an_orphaned_client_with_the_native_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen: bool
) -> None:
    stale = command(tmp_path / "old")
    monkeypatch.setattr("sys.frozen", frozen, raising=False)
    use_bounded_runtime(monkeypatch, tmp_path / "hol-guard-runtime")
    new_home = tmp_path / "new"
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=new_home)
    replacement = _shell_command(
        hook_config_argv(
            context,
            "grok",
            ["guard", "hook", "--guard-home", str(new_home), "--harness", "grok", "--json"],
            85,
        )
    )
    original, _ = prepare_user_config_text("", stale, previous_state={})
    repaired, _ = prepare_user_config_text(original, replacement, previous_state={})
    for groups in tomlkit.parse(repaired)["hooks"].values():
        assert len(groups) == 1
        assert groups[0]["hooks"][0]["command"] == replacement
