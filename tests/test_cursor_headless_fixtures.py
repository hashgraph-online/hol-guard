"""Headless Cursor hook tests against shared guard-red-team fixtures."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import install_cursor_hooks
from codex_plugin_scanner.guard.cli import commands as guard_commands_module

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cursor-hooks"
RED_TEAM_DIR = Path(__file__).parent / "fixtures" / "guard-red-team"
EXPECTED_PATH = FIXTURES_DIR / "expected-permissions.json"
_BLOCKED_PERMISSIONS = frozenset({"deny", "ask"})


def _load_expected_cases() -> list[tuple[str, dict[str, object]]]:
    manifest = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    cases = manifest["cases"]
    if not isinstance(cases, dict):
        raise AssertionError("expected-permissions.json must contain a cases object")
    loaded: list[tuple[str, dict[str, object]]] = []
    for fixture_name, meta in sorted(cases.items()):
        if not isinstance(meta, dict):
            raise AssertionError(f"{fixture_name}: case metadata must be an object")
        loaded.append((fixture_name, meta))
    return loaded


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir()
    home.mkdir()
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'approval_wait_timeout_seconds = 0\nsecurity_level = "balanced"\n',
        encoding="utf-8",
    )
    (workspace / ".env").write_text("HOL_FAKE_SECRET=hol-fake-env-token\n", encoding="utf-8")
    (home / ".env").write_text("HOL_FAKE_SECRET=hol-fake-env-token\n", encoding="utf-8")
    aws_dir = home / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("[default]\naws_access_key_id=HOLFKE123\n", encoding="utf-8")
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _substitute_placeholders(payload: dict[str, object], *, workspace: Path, home: Path) -> dict[str, object]:
    encoded = json.dumps(payload)
    encoded = encoded.replace("$WORKSPACE", str(workspace.resolve()))
    encoded = encoded.replace("$HOME", str(home.resolve()))
    substituted = json.loads(encoded)
    if not isinstance(substituted, dict):
        raise AssertionError("fixture payload must decode to an object")
    return substituted


def _run_hook_script(
    hook_script: Path,
    payload: dict[str, object],
    *,
    workspace: Path,
    home: Path,
) -> tuple[int, dict[str, object]]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["HOME"] = str(home)
    env["CURSOR_PROJECT_DIR"] = str(workspace)
    completed = subprocess.run(
        [sys.executable, str(hook_script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert completed.stdout.strip(), completed.stderr or "hook produced no stdout"
    response = json.loads(completed.stdout)
    assert isinstance(response, dict)
    return completed.returncode, response


@pytest.fixture(autouse=True)
def _stub_guard_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")


@pytest.fixture(name="cursor_hook_env")
def _cursor_hook_env(tmp_path: Path) -> tuple[HarnessContext, Path]:
    context = _context(tmp_path)
    manifest = install_cursor_hooks(context)
    hook_script = Path(str(manifest["managed_hook_script_path"]))
    assert hook_script.is_file()
    source = hook_script.read_text(encoding="utf-8")
    assert "GUARD_CLI" in source
    assert "GUARD_PYTHON" not in source
    return context, hook_script


class TestCursorHeadlessFixtureManifest:
    def test_expected_permissions_manifest_matches_disk(self) -> None:
        manifest_names = {name for name, _ in _load_expected_cases()}
        disk_names = {path.name for path in FIXTURES_DIR.glob("*.json") if path.name != EXPECTED_PATH.name}
        assert manifest_names == disk_names

    @pytest.mark.parametrize(
        ("fixture_name", "meta"),
        _load_expected_cases(),
        ids=[name for name, _ in _load_expected_cases()],
    )
    def test_red_team_fixture_reference_exists(self, fixture_name: str, meta: dict[str, object]) -> None:
        del fixture_name
        red_team_fixture = meta.get("red_team_fixture")
        if red_team_fixture is None:
            return
        path = RED_TEAM_DIR / str(red_team_fixture)
        assert path.is_file(), f"missing red-team fixture: {red_team_fixture}"


class TestCursorHeadlessHookExecution:
    @pytest.mark.parametrize(
        ("fixture_name", "meta"),
        _load_expected_cases(),
        ids=[name for name, _ in _load_expected_cases()],
    )
    def test_cursor_hook_fixture_permission(
        self,
        cursor_hook_env: tuple[HarnessContext, Path],
        fixture_name: str,
        meta: dict[str, object],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context, hook_script = cursor_hook_env
        assert context.workspace_dir is not None
        monkeypatch.chdir(context.workspace_dir)
        assert context.home_dir is not None
        payload = _substitute_placeholders(
            json.loads((FIXTURES_DIR / fixture_name).read_text(encoding="utf-8")),
            workspace=context.workspace_dir,
            home=context.home_dir,
        )
        exit_code, response = _run_hook_script(
            hook_script,
            payload,
            workspace=context.workspace_dir,
            home=context.home_dir,
        )
        permission = str(response.get("permission") or "")
        expected = str(meta.get("permission") or "")
        if expected == "allow":
            assert permission == "allow", response
            assert exit_code == 0, response
            return
        if expected == "blocked":
            assert permission in _BLOCKED_PERMISSIONS, response
            if permission == "deny":
                assert exit_code == 2
            return
        raise AssertionError(f"unsupported expected permission label: {expected}")
