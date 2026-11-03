"""`cloud-actions ai-tools configure --apply` and `ai-tools restore`.

Applying writes exactly the previewed file, only while the file still holds
what the preview read, keeps a copy of the previous file, and puts it back if
the write does not read back. Applying twice changes nothing the second time.
Restoring puts the copy back only while the file still holds what Guard wrote.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import cloud_actions_host_apply
from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccessError
from codex_plugin_scanner.guard.cli.cloud_actions_host_apply import (
    HostConfigWriteError,
    apply_host_config,
    backups_dir,
    restore_host_config,
)
from codex_plugin_scanner.guard.cli.cloud_actions_host_config import (
    CLOUD_ACTIONS_SERVER_NAME,
    HostConfigPlan,
    plan_host_config,
)
from tests.cloud_actions_pairing_support import URL, WS, FakeCloud, entry, pair, wanted

LOCAL_URL = "http://127.0.0.1:3017/api/guard/gateway/mcp"
POSIX = os.name != "nt"

CODEX_SETTINGS = """# Hand-written; keep this comment.
model = "gpt-5"

[mcp_servers.docs]
command = "docs-mcp"
args = ["--stdio"]
"""

JSON_SETTINGS: dict[str, Any] = {
    "numStartups": 3,
    "mcpServers": {"docs": {"command": "docs-mcp", "args": ["--stdio"]}},
}

PATHS = {"claude-code": ".claude.json", "codex": ".codex/config.toml", "cursor": ".cursor/mcp.json"}


@pytest.fixture(autouse=True)
def cloud(monkeypatch: pytest.MonkeyPatch) -> FakeCloud:
    return pair(monkeypatch)


def _seed(home: Path, tool: str, *, mode: int = 0o640) -> Path:
    path = home / PATHS[tool]
    path.parent.mkdir(parents=True, exist_ok=True)
    text = CODEX_SETTINGS if tool == "codex" else json.dumps(JSON_SETTINGS, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")
    if POSIX:
        path.chmod(mode)
    return path


def _plan(tool: str, path: Path, guard_home: str = "/guard-home") -> HostConfigPlan:
    return plan_host_config(tool, path=path, entry=entry(tool, guard_home), url=URL)


def _main(*argv: str) -> int:
    try:
        return cli.main(["cloud-actions", *argv])
    except SystemExit as exit_:
        return int(exit_.code or 0)


def _run(capsys: pytest.CaptureFixture[str], home: Path, guard_home: Path, *argv: str) -> tuple[int, dict[str, Any]]:
    code = _main(*argv, "--home", str(home), "--guard-home", str(guard_home), "--json")
    return code, json.loads(capsys.readouterr().out)


def _apply(capsys: pytest.CaptureFixture[str], home: Path, guard_home: Path, tool: str) -> tuple[int, dict[str, Any]]:
    return _run(capsys, home, guard_home, "ai-tools", "configure", tool, "--cloud-workspace", WS, "--apply")


def _restore(capsys: pytest.CaptureFixture[str], home: Path, guard_home: Path, tool: str) -> tuple[int, dict[str, Any]]:
    return _run(capsys, home, guard_home, "ai-tools", "restore", tool)


def _records(guard_home: Path, tool: str) -> list[Path]:
    return sorted(backups_dir(guard_home, tool).glob("*.json"))


def _strays(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir() if ".guard-tmp" in path.name)


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_apply_writes_the_previewed_file_and_keeps_a_copy(
    tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, tool)
    before = path.read_bytes()
    preview = plan_host_config(tool, path=path, entry=entry(tool, guard_home), url=URL)

    code, payload = _apply(capsys, home, guard_home, tool)

    assert code == 0
    assert payload["state"] == "applied"
    assert payload["action"] == "add"
    assert payload["written"] is True
    assert path.read_bytes() == preview.after
    assert _strays(path.parent) == []
    [record] = _records(guard_home, tool)
    assert record.with_suffix(".before").read_bytes() == before
    if POSIX:
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
        assert stat.S_IMODE(record.stat().st_mode) == 0o600
        assert stat.S_IMODE(record.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_applying_again_changes_nothing(tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, tool)
    assert _apply(capsys, home, guard_home, tool)[0] == 0
    written = path.read_bytes()
    stamp = path.stat().st_mtime_ns

    code, payload = _apply(capsys, home, guard_home, tool)

    assert code == 0
    assert payload["state"] == "unchanged"
    assert payload["written"] is False
    assert path.read_bytes() == written
    assert path.stat().st_mtime_ns == stamp
    assert len(_records(guard_home, tool)) == 1


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_restore_puts_back_the_file_from_before(tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, tool)
    before = path.read_bytes()
    assert _apply(capsys, home, guard_home, tool)[0] == 0

    code, payload = _restore(capsys, home, guard_home, tool)

    assert code == 0
    assert payload["state"] == "restored"
    assert payload["removed_file"] is False
    assert path.read_bytes() == before
    if POSIX:
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert _records(guard_home, tool) == []
    assert _restore(capsys, home, guard_home, tool)[1]["state"] == "nothing_to_restore"
    assert path.read_bytes() == before


def test_apply_creates_a_private_file_and_restore_removes_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = home / PATHS["cursor"]

    code, payload = _apply(capsys, home, guard_home, "cursor")

    assert code == 0
    assert payload["action"] == "create_file"
    assert json.loads(path.read_bytes())["mcpServers"][CLOUD_ACTIONS_SERVER_NAME] == wanted("cursor", guard_home)
    if POSIX:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(backups_dir(guard_home, "cursor").glob("*.before")) == []

    code, payload = _restore(capsys, home, guard_home, "cursor")

    assert code == 0
    assert payload["removed_file"] is True
    assert not path.exists()


def test_apply_text_names_the_change_and_how_to_undo(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    hint = plan_host_config("codex", path=path, entry=entry("codex"), url=URL).reload_hint
    code = _main("ai-tools", "configure", "codex", "--apply", "--home", str(home), "--guard-home", str(guard_home))

    assert code == 0
    assert capsys.readouterr().out == (
        f"Set up Codex for Cloud actions in workspace {WS}.\n"
        f"Added the {CLOUD_ACTIONS_SERVER_NAME} entry in {path}. Everything else in the file stays as it is.\n"
        "Codex uses this computer's Guard Cloud connection; it does not sign in separately.\n"
        f"{hint}\n"
        "To undo, run `hol-guard cloud-actions ai-tools restore codex`.\n"
    )


def test_apply_gets_the_ai_tools_access_before_writing(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")

    assert _apply(capsys, home, guard_home, "codex")[0] == 0

    assert cloud.exchanged == ["codex"]
    assert "exchanged-access" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("reason", "code"),
    [("cloud_actions_not_allowed", 4), ("cloud_actions_off", 4), ("not_available", 3), ("cloud_unreachable", 3)],
)
def test_a_refused_access_writes_nothing(
    reason: str, code: int, cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "cursor")
    before = path.read_bytes()
    cloud.exchange_error = CloudActionsAccessError(reason, "Refused.")

    result, payload = _apply(capsys, home, guard_home, "cursor")

    assert (result, payload["reason"]) == (code, reason)
    assert path.read_bytes() == before
    assert _records(guard_home, "cursor") == []


def test_restore_ends_the_ai_tools_access(cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    _ = _seed(home, "codex")
    assert _apply(capsys, home, guard_home, "codex")[0] == 0

    code, payload = _restore(capsys, home, guard_home, "codex")

    assert (code, payload["access_ended"]) == (0, True)
    assert cloud.revoked == ["codex"]


def test_restore_changes_nothing_when_access_could_not_end(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    before = path.read_bytes()
    assert _apply(capsys, home, guard_home, "codex")[0] == 0
    cloud.revoke_error = CloudActionsAccessError("cloud_unreachable", "Guard Cloud could not be reached.")

    code, payload = _restore(capsys, home, guard_home, "codex")

    assert (code, payload["state"], payload["restored"]) == (3, "access_not_ended", False)
    assert path.read_bytes() != before
    assert len(_records(guard_home, "codex")) == 1


def test_a_change_after_the_preview_is_never_overwritten(tmp_path: Path) -> None:
    path = _seed(tmp_path, "claude-code")
    plan = plan_host_config("claude-code", path=path, entry=entry("claude-code"), url=URL)
    edited = path.read_bytes().replace(b'"numStartups": 3', b'"numStartups": 4')
    path.write_bytes(edited)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "changed_since_preview"
    assert path.read_bytes() == edited
    assert _records(tmp_path / "guard", "claude-code") == []


def test_a_change_just_before_the_move_is_never_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path, "claude-code")
    plan = plan_host_config("claude-code", path=path, entry=entry("claude-code"), url=URL)
    edited = path.read_bytes().replace(b'"numStartups": 3', b'"numStartups": 5')
    real = cloud_actions_host_apply._write_temporary  # pyright: ignore[reportPrivateUsage]

    def write_then_edit(target: Path, payload: bytes, mode: int) -> Path:
        temporary = real(target, payload, mode)
        target.write_bytes(edited)
        return temporary

    monkeypatch.setattr(cloud_actions_host_apply, "_write_temporary", write_then_edit)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "changed_since_preview"
    assert path.read_bytes() == edited
    assert _strays(path.parent) == []
    assert _records(tmp_path / "guard", "claude-code") == []


def test_a_file_created_after_the_preview_is_never_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / PATHS["cursor"]
    plan = plan_host_config("cursor", path=path, entry=entry("cursor"), url=URL)
    assert plan.action == "create_file"
    real = cloud_actions_host_apply._read  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def read_then_create(target: Path) -> bytes | None:
        nonlocal calls
        calls += 1
        result = real(target)
        if calls == 2:
            target.write_bytes(b'{"mcpServers": {}}\n')
        return result

    monkeypatch.setattr(cloud_actions_host_apply, "_read", read_then_create)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "changed_since_preview"
    assert path.read_bytes() == b'{"mcpServers": {}}\n'
    assert _strays(path.parent) == []


def test_a_write_that_does_not_read_back_is_undone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path, "codex")
    before = path.read_bytes()
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file
    damaged = False

    def replace_then_damage(source: Path, destination: Path) -> None:
        nonlocal damaged
        real(source, destination)
        if destination == path and not damaged:
            damaged = True
            with destination.open("ab") as handle:
                _ = handle.write(b"damaged = true\n")

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", replace_then_damage)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "write_not_verified"
    assert path.read_bytes() == before
    if POSIX:
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert _records(tmp_path / "guard", "codex") == []


def test_a_write_that_cannot_be_put_back_keeps_the_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path, "codex")
    before = path.read_bytes()
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file
    calls = 0

    def damage_then_refuse(source: Path, destination: Path) -> None:
        nonlocal calls
        if destination != path:
            real(source, destination)
            return
        calls += 1
        if calls > 1:
            raise PermissionError(13, "Permission denied")
        real(source, destination)
        with destination.open("ab") as handle:
            _ = handle.write(b"damaged = true\n")

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", damage_then_refuse)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "put_back_failed"
    assert "restore codex" in str(error.value)
    [record] = _records(tmp_path / "guard", "codex")
    assert record.with_suffix(".before").read_bytes() == before

    # Following the message brings the earlier file back whole, damage included.
    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", real)
    result = restore_host_config("codex", path=path, guard_home=tmp_path / "guard")

    assert result is not None
    assert result.scope == "file"
    assert path.read_bytes() == before
    assert _records(tmp_path / "guard", "codex") == []


def test_a_failed_write_that_removed_the_file_is_restored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path, "codex")
    before = path.read_bytes()
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file
    calls = 0

    def remove_then_refuse(source: Path, destination: Path) -> None:
        nonlocal calls
        if destination != path:
            real(source, destination)
            return
        calls += 1
        if calls > 1:
            raise PermissionError(13, "Permission denied")
        destination.unlink()

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", remove_then_refuse)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")
    assert error.value.reason == "put_back_failed"
    assert not path.exists()

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", real)
    result = restore_host_config("codex", path=path, guard_home=tmp_path / "guard")

    assert result is not None
    assert result.scope == "file"
    assert path.read_bytes() == before


def test_nothing_is_created_without_hard_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / PATHS["cursor"]
    plan = plan_host_config("cursor", path=path, entry=entry("cursor"), url=URL)
    assert plan.action == "create_file"

    def no_links(source: object, destination: object) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(cloud_actions_host_apply.os, "link", no_links)

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "write_failed"
    assert not path.exists()
    assert _strays(path.parent) == []
    assert _records(tmp_path / "guard", "cursor") == []


def test_nothing_is_written_when_no_copy_can_be_kept(tmp_path: Path) -> None:
    path = _seed(tmp_path, "codex")
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    blocker = backups_dir(guard_home, "codex")
    blocker.parent.mkdir(parents=True)
    blocker.write_text("not a folder", encoding="utf-8")

    with pytest.raises(HostConfigWriteError) as error:
        _ = apply_host_config(
            plan_host_config("codex", path=path, entry=entry("codex"), url=URL), guard_home=guard_home
        )

    assert error.value.reason == "backup_failed"
    assert path.read_bytes() == before


@pytest.mark.skipif(not POSIX, reason="creating links needs extra rights on Windows")
def test_a_linked_settings_file_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    target = _seed(tmp_path / "elsewhere", "codex")
    before = target.read_bytes()
    link = home / PATHS["codex"]
    link.parent.mkdir(parents=True)
    link.symlink_to(target)

    code, payload = _apply(capsys, home, guard_home, "codex")

    assert code == 1
    assert payload["reason"] == "settings_file_is_link"
    assert link.is_symlink()
    assert target.read_bytes() == before


def test_restore_after_later_edits_removes_only_guards_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    assert _apply(capsys, home, guard_home, "codex")[0] == 0
    path.write_bytes(path.read_bytes() + b'\n[mcp_servers.notes]\ncommand = "notes-mcp"\n')

    code, payload = _restore(capsys, home, guard_home, "codex")

    assert code == 0
    assert payload["scope"] == "entry"
    assert payload["entry_removed"] is True
    text = path.read_text(encoding="utf-8")
    assert text.startswith(CODEX_SETTINGS)
    assert CLOUD_ACTIONS_SERVER_NAME not in text
    assert '[mcp_servers.notes]\ncommand = "notes-mcp"\n' in text
    assert _records(guard_home, "codex") == []


def test_restore_keeps_what_the_ai_tool_rewrote(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Claude Code rewrites its settings file while it runs.
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "claude-code")
    assert _apply(capsys, home, guard_home, "claude-code")[0] == 0
    rewritten = json.loads(path.read_bytes())
    rewritten["numStartups"] = 4
    path.write_text(json.dumps(rewritten, indent=2) + "\n", encoding="utf-8")

    code, payload = _restore(capsys, home, guard_home, "claude-code")

    assert code == 0
    assert payload["scope"] == "entry"
    assert path.read_text(encoding="utf-8") == json.dumps({**JSON_SETTINGS, "numStartups": 4}, indent=2) + "\n"


def test_restore_after_later_edits_puts_back_the_earlier_address(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = home / PATHS["cursor"]
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"mcpServers": {CLOUD_ACTIONS_SERVER_NAME: {"url": LOCAL_URL}}}) + "\n", encoding="utf-8"
    )
    code, payload = _apply(capsys, home, guard_home, "cursor")
    assert (code, payload["action"]) == (0, "update")
    document = json.loads(path.read_bytes())
    document["mcpServers"]["notes"] = {"command": "notes-mcp"}
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    code, payload = _restore(capsys, home, guard_home, "cursor")

    assert code == 0
    assert (payload["scope"], payload["entry_removed"]) == ("entry", False)
    assert json.loads(path.read_bytes()) == {
        "mcpServers": {CLOUD_ACTIONS_SERVER_NAME: {"url": LOCAL_URL}, "notes": {"command": "notes-mcp"}}
    }


def test_restore_keeps_a_created_file_that_was_edited_since(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = home / PATHS["cursor"]
    assert _apply(capsys, home, guard_home, "cursor")[1]["action"] == "create_file"
    document = json.loads(path.read_bytes())
    document["mcpServers"]["notes"] = {"command": "notes-mcp"}
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    code, payload = _restore(capsys, home, guard_home, "cursor")

    assert code == 0
    assert payload["removed_file"] is False
    assert json.loads(path.read_bytes()) == {"mcpServers": {"notes": {"command": "notes-mcp"}}}


@pytest.mark.parametrize("change", ["address", "removed", "file_removed"])
def test_restore_leaves_guards_entry_alone_once_someone_changed_it(
    change: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "cursor")
    assert _apply(capsys, home, guard_home, "cursor")[0] == 0
    document = json.loads(path.read_bytes())
    if change == "address":
        document["mcpServers"][CLOUD_ACTIONS_SERVER_NAME]["args"][-1] = "/elsewhere"
    else:
        del document["mcpServers"][CLOUD_ACTIONS_SERVER_NAME]
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if change == "file_removed":
        path.unlink()
    edited = path.read_bytes() if path.exists() else None

    code, payload = _restore(capsys, home, guard_home, "cursor")

    assert code == 1
    assert payload["reason"] == "changed_since_apply"
    assert (path.read_bytes() if path.exists() else None) == edited
    assert len(_records(guard_home, "cursor")) == 1


def test_restore_refuses_a_damaged_copy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    assert _apply(capsys, home, guard_home, "codex")[0] == 0
    written = path.read_bytes()
    [record] = _records(guard_home, "codex")
    record.with_suffix(".before").write_bytes(b"model = 'other'\n")

    code, payload = _restore(capsys, home, guard_home, "codex")

    assert code == 1
    assert payload["reason"] == "backup_unreadable"
    assert path.read_bytes() == written


def test_restore_reports_a_damaged_newer_record(tmp_path: Path) -> None:
    path = _seed(tmp_path, "codex")
    guard_home = tmp_path / "guard"
    _ = apply_host_config(_plan("codex", path), guard_home=guard_home)
    written = path.read_bytes()
    (backups_dir(guard_home, "codex") / f"{'9' * 20}-1.json").write_bytes(b'{"format": "guard.cloud')

    with pytest.raises(HostConfigWriteError) as error:
        _ = restore_host_config("codex", path=path, guard_home=guard_home)

    assert error.value.reason == "backup_unreadable"
    assert path.read_bytes() == written


def test_restore_finds_the_copy_through_another_spelling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path / "home", "codex")
    original = path.read_bytes()
    monkeypatch.chdir(tmp_path)
    relative = Path("home") / PATHS["codex"]
    _ = apply_host_config(
        plan_host_config("codex", path=relative, entry=entry("codex"), url=URL), guard_home=tmp_path / "guard"
    )

    assert restore_host_config("codex", path=path, guard_home=tmp_path / "guard") is not None
    assert path.read_bytes() == original


def test_restore_steps_back_through_each_apply(tmp_path: Path) -> None:
    path = _seed(tmp_path, "codex")
    original = path.read_bytes()
    guard_home = tmp_path / "guard"
    _ = apply_host_config(_plan("codex", path), guard_home=guard_home)
    first = path.read_bytes()
    _ = apply_host_config(
        plan_host_config("codex", path=path, entry=entry("codex", "/other-guard-home"), url=URL), guard_home=guard_home
    )

    assert restore_host_config("codex", path=path, guard_home=guard_home) is not None
    assert path.read_bytes() == first
    assert restore_host_config("codex", path=path, guard_home=guard_home) is not None
    assert path.read_bytes() == original
    assert restore_host_config("codex", path=path, guard_home=guard_home) is None


def test_only_the_latest_copies_are_kept(tmp_path: Path) -> None:
    path = _seed(tmp_path, "codex")
    guard_home = tmp_path / "guard"
    for index in range(12):
        fields = entry("codex", f"/guard-home-{index % 2}")
        _ = apply_host_config(plan_host_config("codex", path=path, entry=fields, url=URL), guard_home=guard_home)

    directory = backups_dir(guard_home, "codex")
    assert len(_records(guard_home, "codex")) == 10
    assert len(list(directory.glob("*.before"))) == 10


def test_copies_stay_under_the_given_home(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _ = _seed(home, "codex")
    code = _main("ai-tools", "configure", "codex", "--cloud-workspace", WS, "--apply", "--home", str(home), "--json")

    assert code == 0
    assert json.loads(capsys.readouterr().out)["state"] == "applied"
    assert len(list(home.glob(".hol-guard/cloud-actions/settings-backups/codex/*.json"))) == 1
