from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import harness_ops_support as harness_support
from tests.opencode_test_support import refresh_opencode_proxy_launchers

LOCK = Path(".config") / "opencode" / ".hol-guard-config.lock"


@pytest.fixture(autouse=True)
def _skip_codex_owner_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # The install owner check runs before the native call; the lock is what is under test.
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_owned.require_codex_install_owner",
        lambda *_args, **_kwargs: None,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock")
def test_install_cleanup_and_refresh_wait_for_another_process_holding_the_lock(tmp_path: Path) -> None:
    from tests.test_opencode_pretool import _ctx

    context = _ctx(tmp_path)
    lock_path = context.home_dir / LOCK
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent("""
                import fcntl, sys
                with open(sys.argv[1], "a+") as handle:
                    fcntl.flock(handle, fcntl.LOCK_EX)
                    print("locked", flush=True)
                    sys.stdin.readline()
            """),
            str(lock_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "locked"
        for operation in (
            lambda ctx: harness_support.install("opencode", ctx),
            lambda ctx: harness_support.uninstall("opencode", ctx),
            refresh_opencode_proxy_launchers,
        ):
            with pytest.raises(RuntimeError, match="Another Guard operation"):
                operation(context)
    finally:
        assert child.stdin is not None
        child.stdin.write("release\n")
        child.stdin.flush()
        child.communicate(timeout=10)
    assert child.returncode == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink support")
def test_install_refuses_a_symlinked_lock_without_touching_its_target(tmp_path: Path) -> None:
    from tests.test_opencode_pretool import _ctx

    context = _ctx(tmp_path)
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    lock_path = context.home_dir / LOCK
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.symlink_to(target)
    with pytest.raises(ValueError):
        harness_support.install("opencode", context)
    assert target.read_text(encoding="utf-8") == "unchanged"
