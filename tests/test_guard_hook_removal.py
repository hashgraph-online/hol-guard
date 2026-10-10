from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement
from codex_plugin_scanner.guard.codex_config import dump_toml, tomllib
from codex_plugin_scanner.guard.hook_removal import remove_all_guard_hooks
from codex_plugin_scanner.guard.hook_removal_presence import CONFIRMATION_PHRASE, require_typed_presence
from codex_plugin_scanner.guard.hook_removal_sweep import (
    is_guard_hook_command,
    prune_guard_hooks,
    sweep_config_file,
)
from codex_plugin_scanner.guard.store import GuardStore

GUARD_COMMAND = "hol-guard hook --harness claude-code --event PreToolUse"
USER_COMMAND = "/usr/local/bin/my-audit-hook --log"


def _claude_settings() -> dict[str, object]:
    return {
        "model": "opus",
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": GUARD_COMMAND}]},
                {"matcher": "Bash", "hooks": [{"type": "command", "command": USER_COMMAND}]},
            ],
            "Stop": [{"hooks": [{"type": "command", "command": GUARD_COMMAND}]}],
        },
    }


@pytest.mark.parametrize(
    "command",
    [
        GUARD_COMMAND,
        "/Users/x/.local/bin/hol-guard hook --harness codex",
        "python -m codex_plugin_scanner.cli guard hook --harness codex",
        "bash -c '/home/x/.hol-guard/managed/bounded-hooks/run.sh'",
        "HOL_GUARD_MANAGED=1 something",
    ],
)
def test_guard_signature_matches(command: str) -> None:
    assert is_guard_hook_command(command) or "HOL_GUARD_MANAGED" in command


@pytest.mark.parametrize("command", [USER_COMMAND, "echo guard", "git diff", "", None, 5])
def test_non_guard_commands_are_not_matched(command: object) -> None:
    assert not is_guard_hook_command(command)


def test_prune_removes_only_guard_handlers_and_empty_events() -> None:
    pruned, removed = prune_guard_hooks(_claude_settings())
    assert len(removed) == 2
    hooks = pruned["hooks"]
    assert isinstance(hooks, dict)
    assert "Stop" not in hooks
    remaining = hooks["PreToolUse"]
    assert len(remaining) == 1
    assert remaining[0]["hooks"][0]["command"] == USER_COMMAND
    assert pruned["model"] == "opus"


def test_sweep_dry_run_does_not_write_and_json_rewrite_preserves_other_keys(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(_claude_settings()))
    before = path.read_bytes()
    assert sweep_config_file(path, dry_run=True).removed == 2
    assert path.read_bytes() == before
    result = sweep_config_file(path, dry_run=False)
    assert result.wrote and result.removed == 2
    written = json.loads(path.read_text())
    assert written["model"] == "opus"
    assert GUARD_COMMAND not in path.read_text()
    assert USER_COMMAND in path.read_text()


def test_sweep_toml_is_lossless_or_refused(tmp_path: Path) -> None:
    payload = {
        "model": "gpt",
        "projects": {"/work": {"trust_level": "trusted"}},
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": GUARD_COMMAND}]}]},
    }
    path = tmp_path / "config.toml"
    path.write_text(dump_toml(payload))
    result = sweep_config_file(path, dry_run=False)
    assert result.removed == 1 and result.wrote
    reloaded = tomllib.loads(path.read_text())
    assert reloaded == {"model": "gpt", "projects": {"/work": {"trust_level": "trusted"}}}


def test_sweep_refuses_unparseable_files(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{not json")
    result = sweep_config_file(path, dry_run=False)
    assert result.removed == 0 and result.error == "unparseable"
    assert path.read_text() == "{not json"


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def test_remove_all_sweeps_unrecorded_hooks_with_backup(tmp_path: Path) -> None:
    context = _context(tmp_path)
    claude = context.home_dir / ".claude"
    claude.mkdir()
    settings = claude / "settings.json"
    settings.write_text(json.dumps(_claude_settings()))
    original = settings.read_bytes()
    store = GuardStore(context.guard_home)

    planned = remove_all_guard_hooks(context=context, store=store, dry_run=True)
    assert planned["status"] == "planned"
    assert settings.read_bytes() == original

    report = remove_all_guard_hooks(context=context, store=store)
    assert report["status"] == "removed"
    assert report["removed_hook_count"] == 2
    assert report["reinstall_command"] == "hol-guard install --all"
    assert GUARD_COMMAND not in settings.read_text()
    assert USER_COMMAND in settings.read_text()
    backups = report["backups"]
    assert isinstance(backups, list) and len(backups) == 1
    assert Path(str(backups[0]["backup_path"])).read_bytes() == original

    again = remove_all_guard_hooks(context=context, store=store)
    assert again["status"] == "nothing_to_remove"


def test_typed_presence_refuses_non_interactive_and_wrong_phrase() -> None:
    with pytest.raises(ApprovalGateError) as non_tty:
        require_typed_presence(affected="codex", isatty=lambda: False)
    assert non_tty.value.code == "approval_gate_interactive_required"
    with pytest.raises(ApprovalGateError):
        require_typed_presence(affected="codex", isatty=lambda: True, read_line=lambda _p: "yes")

    def eof(_prompt: str) -> str:
        raise EOFError

    with pytest.raises(ApprovalGateError):
        require_typed_presence(affected="codex", isatty=lambda: True, read_line=eof)
    require_typed_presence(
        affected="codex",
        isatty=lambda: True,
        read_line=lambda _p: f"  {CONFIRMATION_PHRASE.upper()} ",
    )


def test_lifecycle_gate_requires_step_up_for_hooks_remove_but_not_dry_run() -> None:
    import argparse

    live = argparse.Namespace(guard_command="hooks", hooks_command="remove", dry_run=False)
    requirement = lifecycle_gate_requirement(live)
    assert requirement is not None and requirement.action == "hooks.remove"
    dry = argparse.Namespace(guard_command="hooks", hooks_command="remove", dry_run=True)
    assert lifecycle_gate_requirement(dry) is None
    repair = argparse.Namespace(guard_command="repair", dry_run=False)
    assert lifecycle_gate_requirement(repair) is not None
    assert lifecycle_gate_requirement(argparse.Namespace(guard_command="repair", dry_run=True)) is None


def _write_settings(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    settings = home / ".claude" / "settings.json"
    settings.write_text(json.dumps(_claude_settings()))
    return home, tmp_path / "guard-home", settings


def _remove_args(home: Path, guard_home: Path, *extra: str) -> list[str]:
    return ["guard", "hooks", "remove", "--all", "--home", str(home), "--guard-home", str(guard_home), *extra]


def test_cli_hooks_remove_refuses_without_tty_when_no_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home, settings = _write_settings(tmp_path)
    original = settings.read_bytes()
    assert main(_remove_args(home, guard_home, "--json")) == 4
    assert settings.read_bytes() == original
    assert "approval_gate_interactive_required" in capsys.readouterr().out


def test_cli_hooks_remove_dry_run_changes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home, settings = _write_settings(tmp_path)
    original = settings.read_bytes()
    assert main(_remove_args(home, guard_home, "--dry-run", "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "planned" and payload["dry_run"] is True
    assert settings.read_bytes() == original


def test_cli_hooks_remove_with_typed_phrase_on_tty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home, settings = _write_settings(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda _prompt="": CONFIRMATION_PHRASE)
    assert main(_remove_args(home, guard_home, "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "removed"
    assert GUARD_COMMAND not in settings.read_text()
    assert USER_COMMAND in settings.read_text()
