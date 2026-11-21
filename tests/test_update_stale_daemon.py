from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_native_wheel, update_stale_daemon
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests.update_context_test_support import build_legacy_status_distribution, build_legacy_update_context

CURRENT = "2.0.830"


def _no_newer_daemon(*_args: object, **_kwargs: object) -> None:
    return None


def _no_shim_refresh(**_kwargs: object) -> tuple[None, None]:
    return None, None


def _no_harness_repair(**_kwargs: object) -> tuple[list[object], list[str]]:
    return [], []


class _FakeLock:
    def __init__(self) -> None:
        self.active: bool = True

    def publish_runtime_digest(self, executable: Path) -> str:
        del executable
        return "digest"

    def release(self) -> None:
        self.active = False


def _already_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    daemon_version: str | None,
    refresh_result: dict[str, object] | None,
) -> tuple[HarnessContext, list[str | None]]:
    @contextmanager
    def hold(_guard_home: Path, *, initial_executable: Path) -> Generator[_FakeLock]:
        del initial_executable
        yield _FakeLock()

    refreshed: list[str | None] = []

    def refresh(
        _context: HarnessContext, *, update_context: object = None, minimum_version: str | None = None
    ) -> tuple[dict[str, object] | None, str | None]:
        del update_context
        refreshed.append(minimum_version)
        return refresh_result, "daemon refresh note"

    def manage(op: str, _guard_home: Path, **kwargs: object) -> dict[str, object] | None:
        assert op == "live_identity"
        deadline = kwargs.get("deadline")
        assert isinstance(deadline, float)
        assert deadline - time.monotonic() <= 5.0
        if daemon_version is None:
            return {"reason": "service_unresponsive"}
        return {"reason": "healthy", "identity": {"package_version": daemon_version}}

    runtime = tmp_path / "runtime"
    _ = runtime.write_bytes(b"test-runtime")
    runtime.chmod(0o700)
    monkeypatch.setattr(update_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(update_commands, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_native_wheel, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
    monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
    monkeypatch.setattr(update_commands, "_current_version", lambda: CURRENT)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: CURRENT)
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(update_commands, "_verified_newer_guard_daemon", _no_newer_daemon)
    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", _no_shim_refresh)
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", _no_harness_repair)
    monkeypatch.setattr(update_commands, "refresh_guard_daemon_after_update", refresh)
    monkeypatch.setattr(update_stale_daemon, "_daemon_manage", manage)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "daemon-state.json").write_text("{}", encoding="utf-8")
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=guard_home)
    return context, refreshed


def test_already_current_update_restarts_a_daemon_left_on_an_older_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restarted: dict[str, object] = {"status": "restarted", "runtime_verified": True}
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=restarted)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert refreshed == [CURRENT]
    assert payload["status"] == "current"
    assert payload["changed"] is True
    assert payload["daemon_refresh"] == restarted


def test_already_current_update_fails_when_the_older_daemon_cannot_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=None)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 1
    assert refreshed == [CURRENT]
    assert payload["status"] == "failed"
    assert payload["reason_code"] == "update_daemon_refresh_failed"


def test_already_current_update_keeps_a_desktop_owned_older_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained: dict[str, object] = {"status": "retained_desktop_owner", "runtime_verified": True}
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=retained)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert refreshed == [CURRENT]
    assert payload["status"] == "current"
    assert payload["changed"] is False


@pytest.mark.parametrize("daemon_version", [CURRENT, "2.0.831", None, "not-a-version"])
def test_already_current_update_leaves_a_current_or_unknown_daemon_alone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    daemon_version: str | None,
) -> None:
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version=daemon_version, refresh_result=None)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert refreshed == []
    assert payload["status"] == "current"
    assert "daemon_refresh" not in payload


def test_an_explicit_guard_home_still_restarts_the_context_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restarted: dict[str, object] = {"status": "restarted", "runtime_verified": True}
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=restarted)
    override = tmp_path / "override-home"
    override.mkdir()

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context, guard_home=override)

    assert exit_code == 0, payload
    assert refreshed == [CURRENT]


def test_no_daemon_state_skips_the_live_daemon_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=None)
    (context.guard_home / "daemon-state.json").unlink()

    def no_probe(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("probed a daemon without daemon state")

    monkeypatch.setattr(update_stale_daemon, "_daemon_manage", no_probe)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert refreshed == []


def test_a_newer_runtime_found_by_the_restart_keeps_its_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained: dict[str, object] = {"status": "retained_newer_runtime", "runtime_verified": True}
    context, refreshed = _already_current(tmp_path, monkeypatch, daemon_version="2.0.829", refresh_result=retained)
    repaired: list[str] = []

    def shims(**_kwargs: object) -> tuple[None, None]:
        repaired.append("shims")
        return None, None

    def harnesses(**_kwargs: object) -> tuple[list[object], list[str]]:
        repaired.append("harnesses")
        return [], []

    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", shims)
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", harnesses)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert refreshed == [CURRENT]
    assert payload["runtime_artifact_owner"] == "newer_runtime"
    assert repaired == []
