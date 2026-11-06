from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands, update_native_wheel
from codex_plugin_scanner.guard.cli.update_resident_barrier import (
    release_before_post_update_repair,
    subprocess_failure_summary,
)
from codex_plugin_scanner.guard.native_resident_update_lock import NativeResidentUpdateLockError
from tests.update_context_test_support import build_legacy_status_distribution, build_legacy_update_context


class _FakeLock:
    def __init__(self, *, publish_error: bool = False) -> None:
        self.active: bool = True
        self.published: list[Path] = []
        self._publish_error: bool = publish_error

    def publish_runtime_digest(self, executable: Path) -> str:
        if self._publish_error:
            raise NativeResidentUpdateLockError("update_native_resident_lock_finalize_failed")
        self.published.append(executable)
        return "digest"

    def release(self) -> None:
        self.active = False


def test_release_publishes_the_runtime_before_releasing(tmp_path: Path) -> None:
    lock = _FakeLock()

    release_before_post_update_repair(lock, tmp_path / "runtime")  # pyright: ignore[reportArgumentType]

    assert lock.published == [tmp_path / "runtime"]
    assert lock.active is False


def test_release_still_releases_when_the_digest_cannot_be_published(tmp_path: Path) -> None:
    lock = _FakeLock(publish_error=True)

    release_before_post_update_repair(lock, tmp_path / "runtime")  # pyright: ignore[reportArgumentType]

    assert lock.active is False


def test_failure_summary_keeps_only_the_final_line() -> None:
    traceback = (
        "Traceback (most recent call last):\n"
        '  File "<string>", line 21, in <module>\n'
        "NativeShimAdminError: native_resident_update_in_progress\n"
    )

    assert subprocess_failure_summary(traceback) == "NativeShimAdminError: native_resident_update_in_progress"
    assert subprocess_failure_summary("\n  \n") == ""


def test_already_current_update_repairs_after_releasing_the_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = _FakeLock()

    @contextmanager
    def hold(_guard_home: Path, *, initial_executable: Path) -> Generator[_FakeLock]:
        del initial_executable
        yield lock

    barrier_held_during_repair: list[bool] = []

    def refresh_shims(**_kwargs: object) -> tuple[None, None]:
        barrier_held_during_repair.append(lock.active)
        return None, None

    def repair_harnesses(**_kwargs: object) -> tuple[list[object], list[str]]:
        barrier_held_during_repair.append(lock.active)
        return [], []

    runtime = tmp_path / "runtime"
    _ = runtime.write_bytes(b"test-runtime")
    runtime.chmod(0o700)
    monkeypatch.setattr(update_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(update_commands, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_native_wheel, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
    monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", refresh_shims)
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", repair_harnesses)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=tmp_path / "guard-home")

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0, payload
    assert payload["status"] == "current"
    assert barrier_held_during_repair == [False, False]
    assert lock.published == [runtime]
