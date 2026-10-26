from __future__ import annotations

import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.manager import (
    ensure_guard_daemon_auth_token,
    load_guard_daemon_auth_token,
    write_guard_daemon_state,
)


def _guard_home(tmp_path: Path) -> Path:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir(mode=0o700)
    return guard_home


def test_first_daemon_creates_the_token_once(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)

    token = ensure_guard_daemon_auth_token(guard_home)

    assert len(token) == 32
    assert load_guard_daemon_auth_token(guard_home) == token
    assert ensure_guard_daemon_auth_token(guard_home) == token
    if os.name != "nt":
        mode = stat.S_IMODE((guard_home / "daemon-auth-token").stat().st_mode)
        assert mode & 0o077 == 0


def test_later_daemon_reuses_the_existing_token(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    write_guard_daemon_state(guard_home, 5474, "existing-daemon-token", pid=os.getpid())

    assert ensure_guard_daemon_auth_token(guard_home) == "existing-daemon-token"


def test_concurrent_daemon_starts_share_one_token(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    tokens: list[str] = []
    barrier = threading.Barrier(8)

    def start() -> None:
        barrier.wait()
        tokens.append(ensure_guard_daemon_auth_token(guard_home))

    threads = [threading.Thread(target=start) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(set(tokens)) == 1
    assert load_guard_daemon_auth_token(guard_home) == tokens[0]


def test_empty_token_file_is_replaced(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text("", encoding="utf-8")
    token_path.chmod(0o600)

    token = ensure_guard_daemon_auth_token(guard_home)

    assert token
    assert load_guard_daemon_auth_token(guard_home) == token


@pytest.mark.parametrize("port", [5474, 5475])
def test_republishing_state_keeps_the_token_file(tmp_path: Path, port: int) -> None:
    guard_home = _guard_home(tmp_path)
    token = ensure_guard_daemon_auth_token(guard_home)
    token_path = guard_home / "daemon-auth-token"
    before = token_path.stat().st_mtime_ns

    write_guard_daemon_state(guard_home, port, token, pid=os.getpid(), write_auth_token=False)

    assert token_path.stat().st_mtime_ns == before
    assert load_guard_daemon_auth_token(guard_home) == token


def test_republishing_restores_a_missing_token_without_replacing_another(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    token = ensure_guard_daemon_auth_token(guard_home)
    (guard_home / "daemon-auth-token").unlink()

    write_guard_daemon_state(guard_home, 5474, token, pid=os.getpid(), write_auth_token=False)
    assert load_guard_daemon_auth_token(guard_home) == token

    write_guard_daemon_state(guard_home, 5475, "other-daemon-token", pid=os.getpid(), write_auth_token=False)
    assert load_guard_daemon_auth_token(guard_home) == token


def test_concurrent_daemon_processes_share_one_token(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from codex_plugin_scanner.guard.daemon.manager import ensure_guard_daemon_auth_token\n"
        "print(ensure_guard_daemon_auth_token(Path(sys.argv[1])))\n"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(guard_home)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(6)
    ]
    tokens = set()
    for process in processes:
        stdout, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, stderr
        tokens.add(stdout.strip())

    assert tokens == {load_guard_daemon_auth_token(guard_home)}
