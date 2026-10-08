from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.opencode_config_lock import opencode_config_lock


def test_lock_excludes_other_processes_and_releases_after_error(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent("""
                from pathlib import Path
                import sys
                from codex_plugin_scanner.guard.adapters.opencode_config_lock import opencode_config_lock
                with opencode_config_lock(Path(sys.argv[1])):
                    print('locked', flush=True)
                    sys.stdin.readline()
            """),
            str(tmp_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(TimeoutError, match="Another Guard operation"), opencode_config_lock(tmp_path, timeout=0.1):
            pytest.fail("entered another process's critical section")
    finally:
        assert child.stdin is not None
        child.stdin.write("release\n")
        child.stdin.flush()
        child.communicate(timeout=10)
    assert child.returncode == 0
    with pytest.raises(RuntimeError, match="transaction failed"), opencode_config_lock(tmp_path):
        raise RuntimeError("transaction failed")
    with opencode_config_lock(tmp_path, timeout=0.1):
        pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink support")
def test_lock_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    lock_path = tmp_path / ".config" / "opencode" / ".hol-guard-config.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"), opencode_config_lock(tmp_path):
        pytest.fail("entered symlink lock")
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_install_cleanup_and_refresh_read_under_same_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters import opencode, opencode_proxy_refresh
    from tests.test_opencode_pretool import _ctx

    context = _ctx(tmp_path)
    adapter = opencode.OpenCodeHarnessAdapter()

    class ReachedReadError(Exception):
        pass

    def checked_read(*args: object, **kwargs: object) -> None:
        with pytest.raises(TimeoutError), opencode_config_lock(context.home_dir, timeout=0):
            pytest.fail("config reader ran without the shared lock")
        raise ReachedReadError

    monkeypatch.setattr(opencode, "load_opencode_install_snapshot", checked_read)
    monkeypatch.setattr(adapter, "_state_entry", checked_read)
    monkeypatch.setattr(opencode_proxy_refresh, "config_paths", checked_read)
    for operation in (adapter.install, adapter.uninstall, opencode_proxy_refresh.refresh_opencode_proxy_launchers):
        with pytest.raises(ReachedReadError):
            operation(context)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink fixture exercises the no-O_NOFOLLOW fallback")
def test_lock_rejects_symlink_swapped_during_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "untouched"
    target.write_text("unchanged", encoding="utf-8")
    original_open = os.open

    def swapped_open(path: Path, flags: int, mode: int) -> int:
        path.symlink_to(target)
        return original_open(path, flags & ~getattr(os, "O_NOFOLLOW", 0), mode)

    monkeypatch.setattr(os, "open", swapped_open)
    with pytest.raises(ValueError, match="lock path changed"), opencode_config_lock(tmp_path):
        pytest.fail("entered substituted lock")
    assert target.read_text(encoding="utf-8") == "unchanged"
