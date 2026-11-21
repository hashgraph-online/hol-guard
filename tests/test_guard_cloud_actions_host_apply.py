"""`cloud-actions ai-tools configure --apply` and `ai-tools restore`.

Guard's native runtime does the writing, so these tests check the command
around it: what it prints and returns, the access it asks for first, and that a
file really changes and changes back. How the write is made safe (a change after
the preview, an interrupt, a failed put-back, a restore after later edits) is
tested in `cloud_actions_host_apply_*tests.rs`.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccessError
from codex_plugin_scanner.guard.cli.cloud_actions_host_apply import HostConfigWriteError, apply_host_config
from codex_plugin_scanner.guard.cli.cloud_actions_host_config import (
    CLOUD_ACTIONS_SERVER_NAME,
    plan_host_config,
)
from tests.cloud_actions_pairing_support import URL, WS, FakeCloud, backups_dir, entry, pair, wanted

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


def test_apply_refuses_another_workspace_when_the_pairing_names_none(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    before = path.read_bytes()
    cloud.workspace_id = None
    other = "22222222-2222-4222-8222-222222222222"

    result, payload = _run(
        capsys, home, guard_home, "ai-tools", "configure", "codex", "--cloud-workspace", other, "--apply"
    )

    assert result != 0
    assert (payload["reason"], payload["written"], payload["paired_workspace"]) == ("workspace_mismatch", False, WS)
    assert path.read_bytes() == before
    assert _records(guard_home, "codex") == []


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


def test_restore_puts_the_file_back_when_the_pairing_has_expired(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, "codex")
    before = path.read_bytes()
    assert _apply(capsys, home, guard_home, "codex")[0] == 0
    cloud.revoke_error = CloudActionsAccessError("pairing_expired", "This computer's Guard Cloud connection expired.")

    code, payload = _restore(capsys, home, guard_home, "codex")

    assert (code, payload["state"], payload["access_ended"]) == (0, "restored", False)
    assert path.read_bytes() == before
    assert payload["pairing"] == "expired"


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


def test_copies_stay_under_the_given_home(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _ = _seed(home, "codex")
    code = _main("ai-tools", "configure", "codex", "--cloud-workspace", WS, "--apply", "--home", str(home), "--json")

    assert code == 0
    assert json.loads(capsys.readouterr().out)["state"] == "applied"
    assert len(list(home.glob(".hol-guard/cloud-actions/settings-backups/codex/*.json"))) == 1


def test_apply_without_the_native_runtime_leaves_the_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path, "codex")
    before = path.read_bytes()
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", lambda *args, **kwargs: None)

    with pytest.raises(HostConfigWriteError) as error:
        apply_host_config(plan, guard_home=tmp_path / "guard")

    assert error.value.reason == "native_unavailable"
    assert path.read_bytes() == before
    assert not backups_dir(tmp_path / "guard", "codex").exists()
