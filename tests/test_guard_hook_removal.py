from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement
from codex_plugin_scanner.guard.codex_config import dump_toml, tomllib
from codex_plugin_scanner.guard.harness_disconnect_gate import disconnect_requires_fresh_authenticator
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


def test_prune_matches_claude_exec_form_args() -> None:
    exec_handler = {
        "type": "command",
        "command": "/opt/python/bin/python3",
        "args": ["-m", "codex_plugin_scanner.cli", "guard", "hook", "--harness", "claude-code"],
    }
    user_handler = {"type": "command", "command": "/usr/bin/python3", "args": ["-m", "my_audit"]}
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [exec_handler, user_handler]}]}}
    pruned, removed = prune_guard_hooks(settings)
    assert removed == ["PreToolUse"]
    hooks = pruned["hooks"]
    assert isinstance(hooks, dict)
    assert hooks["PreToolUse"][0]["hooks"] == [user_handler]


@pytest.mark.parametrize(
    "handler",
    [
        {"type": "command", "command": "/opt/guard bin/hol-guard", "args": ["hook", "--harness", "claude-code"]},
        {"type": "command", "command": "/bin/sh", "args": ["-c", "HOL_GUARD_HOOK_ARGV=1 exec guard-shim"]},
    ],
)
def test_prune_matches_exec_form_with_spaced_paths_and_markers(handler: dict[str, object]) -> None:
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [handler]}]}}
    _pruned, removed = prune_guard_hooks(settings)
    assert removed == ["PreToolUse"]


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


def test_remove_all_reports_hooks_behind_a_symlinked_config(tmp_path: Path) -> None:
    context = _context(tmp_path)
    dotfiles = context.home_dir / "dotfiles"
    dotfiles.mkdir()
    target = dotfiles / "claude-settings.json"
    target.write_text(json.dumps(_claude_settings()))
    claude = context.home_dir / ".claude"
    claude.mkdir()
    link = claude / "settings.json"
    link.symlink_to(target)
    store = GuardStore(context.guard_home)

    planned = remove_all_guard_hooks(context=context, store=store, dry_run=True)
    assert planned["status"] == "planned"

    report = remove_all_guard_hooks(context=context, store=store)
    assert report["status"] == "partial"
    assert report["remaining"] == [{"harness": "claude-code", "path": str(link), "hook_count": 2}]
    entry = next(item for item in report["harnesses"] if item["harness"] == "claude-code")
    assert entry["sweep_errors"] == ["settings.json:symlink_not_followed"]
    # The sweep never edits through the link, so the hooks stay and are reported.
    assert link.is_symlink()
    assert GUARD_COMMAND in target.read_text()


def test_remove_all_backs_up_before_editing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import hook_removal

    context = _context(tmp_path)
    claude = context.home_dir / ".claude"
    claude.mkdir()
    settings = claude / "settings.json"
    settings.write_text(json.dumps(_claude_settings()))
    original = settings.read_bytes()
    real_sweep = hook_removal.sweep_harness
    seen_backups: list[bytes] = []

    def sweep_after_backup_check(harness: str, ctx: HarnessContext, *, dry_run: bool):
        if not dry_run and harness == "claude-code":
            backup_root = context.guard_home / "backups"
            seen_backups.extend(path.read_bytes() for path in backup_root.rglob("claude-code-*"))
        return real_sweep(harness, ctx, dry_run=dry_run)

    monkeypatch.setattr(hook_removal, "sweep_harness", sweep_after_backup_check)
    report = remove_all_guard_hooks(context=context, store=GuardStore(context.guard_home))

    assert report["status"] == "removed"
    assert seen_backups == [original]


def test_remove_all_skips_harness_when_backup_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import hook_removal

    context = _context(tmp_path)
    claude = context.home_dir / ".claude"
    claude.mkdir()
    settings = claude / "settings.json"
    settings.write_text(json.dumps(_claude_settings()))
    original = settings.read_bytes()

    def refuse_backup_dir(_backup_dir: Path) -> None:
        raise PermissionError("backup directory is read-only")

    monkeypatch.setattr(hook_removal, "_private_backup_dir", refuse_backup_dir)
    report = remove_all_guard_hooks(context=context, store=GuardStore(context.guard_home))

    assert report["status"] == "partial"
    assert settings.read_bytes() == original
    harnesses = report["harnesses"]
    assert isinstance(harnesses, list)
    claude_entry = next(item for item in harnesses if item["harness"] == "claude-code")
    assert claude_entry["adapter_uninstall"] == "skipped"
    assert "PermissionError" in str(claude_entry["backup_error"])
    assert report["backup_dir"] is None


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
    # A recently verified authenticator code must not carry over to removing protection.
    assert disconnect_requires_fresh_authenticator(requirement.action)
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
