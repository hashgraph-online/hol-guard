from __future__ import annotations

import multiprocessing
import os
import socket
import stat
import tempfile
from pathlib import Path
from typing import Protocol

import pytest
from resident_test_support import fake_runtime as _fake_runtime
from resident_test_support import socket_replacing_fake_runtime as _socket_replacing_fake_runtime

from codex_plugin_scanner.guard import native_runtime_resident as resident

pytestmark = pytest.mark.skipif(os.name == "nt", reason="resident runtime currently uses owner-only Unix sockets")


class _ResultQueue(Protocol):
    def put(self, value: bool) -> None: ...


class _ReleaseEvent(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...


def _resident_process_worker(
    executable: str,
    guard_home: str,
    identity: str,
    result_queue: _ResultQueue,
    release_event: _ReleaseEvent,
    start_timeout_seconds: float,
) -> None:
    resident._START_TIMEOUT_SECONDS = start_timeout_seconds  # pyright: ignore[reportPrivateUsage]
    service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
        executable=Path(executable),
        identity_sha256=identity,
        guard_home=Path(guard_home),
        environment={"HOME": str(Path(guard_home).parent)},
    )
    try:
        response = service.request(b"{}", timeout_seconds=start_timeout_seconds + 1.0)
        result_queue.put(response is not None)
        release_event.wait(5.0)
    finally:
        service.close()


def test_independent_supervisors_do_not_replace_one_live_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 5.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        starts_path = root / "starts.log"
        executable = _socket_replacing_fake_runtime(root, starts_path)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "c" * 64
        environment = {"HOME": str(root)}
        first = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment=environment,
        )
        second = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment=environment,
        )
        assert first.socket_path is not None
        stale_credential = first.socket_path.with_name(f"{first.socket_path.name}.stale.auth")
        stale_credential.write_bytes(b"stale")
        stale_credential.chmod(0o600)
        try:
            assert first.request(b"{}", timeout_seconds=6.0) is not None
            assert not stale_credential.exists()
            credential_paths = list((guard_home / "native-runtime").glob("*.auth"))
            assert len(credential_paths) == 1
            assert stat.S_IMODE(credential_paths[0].stat().st_mode) == 0o600
            credential_paths[0].chmod(0o644)
            assert second.request(b"{}", timeout_seconds=6.0) is None
            credential_paths[0].chmod(0o600)
            assert second.request(b"{}", timeout_seconds=6.0) is not None
            assert len(starts_path.read_text(encoding="utf-8").splitlines()) == 1

            second.close()
            socket_path = resident._resident_socket_path(  # pyright: ignore[reportPrivateUsage]
                guard_home,
                identity,
            )
            assert socket_path is not None and socket_path.exists()
        finally:
            second.close()
            first.close()

        assert not any((guard_home / "native-runtime").glob("*.sock"))
        assert not any((guard_home / "native-runtime").glob("*.auth"))


def test_spawned_supervisors_share_one_resident_owner() -> None:
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        starts_path = root / "starts.log"
        executable = _socket_replacing_fake_runtime(root, starts_path)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "e" * 64
        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue()
        release_event = context.Event()
        processes = [
            context.Process(
                target=_resident_process_worker,
                args=(str(executable), str(guard_home), identity, result_queue, release_event, 5.0),
            )
            for _ in range(4)
        ]
        try:
            for process in processes:
                process.start()
            results = [result_queue.get(timeout=10.0) for _ in processes]

            assert results == [True] * 4
            assert len(starts_path.read_text(encoding="utf-8").splitlines()) == 1
            credential_paths = list((guard_home / "native-runtime").glob("*.auth"))
            assert len(credential_paths) == 1
            assert stat.S_IMODE(credential_paths[0].stat().st_mode) == 0o600
        finally:
            release_event.set()
            for process in processes:
                process.join(timeout=5.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1.0)
            result_queue.close()
            result_queue.join_thread()

        assert all(process.exitcode == 0 for process in processes)
        assert not any((guard_home / "native-runtime").glob("*.sock"))
        assert not any((guard_home / "native-runtime").glob("*.auth"))


def test_resident_close_preserves_replacement_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 5.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        executable = _fake_runtime(root)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "d" * 64
        service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment={"HOME": str(root)},
        )
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        owned_path = root / "owned.sock"
        try:
            assert service.request(b"{}", timeout_seconds=6.0) is not None
            socket_path = service.socket_path
            assert socket_path is not None
            socket_path.rename(owned_path)
            replacement.bind(str(socket_path))
            replacement.listen(1)

            service.close()

            assert socket_path.is_socket()
        finally:
            service.close()
            replacement.close()
            for path in (owned_path, service.socket_path):
                if path is not None:
                    path.unlink(missing_ok=True)
