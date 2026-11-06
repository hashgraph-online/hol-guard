"""Overlap may fan out to several streams; ones left idle past the TTL are retired."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_resident_client
from codex_plugin_scanner.guard.native_resident_client import (
    _PersistentNativeClient,
    _PersistentNativeClientPool,
)


def _pool(tmp_path: Path) -> _PersistentNativeClientPool:
    return _PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )


def _spawning_request(
    monkeypatch: pytest.MonkeyPatch,
    spawned: list[subprocess.Popen[bytes]],
    overlap: threading.Barrier | None,
) -> None:
    """Give each stream a real child so the production close path must reap it."""

    def fake_request(client: _PersistentNativeClient, payload: bytes, *, deadline_monotonic: float) -> bytes:
        del deadline_monotonic
        if client._process is None:  # pyright: ignore[reportPrivateUsage]
            process = subprocess.Popen(
                (sys.executable, "-c", "import sys; sys.stdin.read()"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            client._process = process  # pyright: ignore[reportPrivateUsage]
            spawned.append(process)
        if overlap is not None:
            overlap.wait(timeout=5)
        return payload

    monkeypatch.setattr(_PersistentNativeClient, "request", fake_request)


def _overlap_two_requests(pool: _PersistentNativeClientPool) -> list[bytes | None]:
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(pool.request, f"request-{index}".encode(), deadline_monotonic=time.monotonic() + 5)
            for index in range(2)
        ]
        return [future.result(timeout=10) for future in futures]


def _wait_for(condition: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def test_a_stream_idle_past_the_ttl_is_reaped_and_the_newest_stays_parked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_resident_client, "_IDLE_STREAM_TTL_SECONDS", 0.05)
    spawned: list[subprocess.Popen[bytes]] = []
    _spawning_request(monkeypatch, spawned, threading.Barrier(2))
    pool = _pool(tmp_path)
    try:
        assert _overlap_two_requests(pool) == [b"request-0", b"request-1"]
        assert len(spawned) == 2, "overlapping requests must each get their own stream"
        assert _wait_for(lambda: len(pool._clients) == 1)  # pyright: ignore[reportPrivateUsage]
        assert len(pool._idle) == 1  # pyright: ignore[reportPrivateUsage]
        assert not pool._retiring  # pyright: ignore[reportPrivateUsage]
        assert pool._trim_timer is None  # pyright: ignore[reportPrivateUsage]
        parked = pool._idle[0]._process  # pyright: ignore[reportPrivateUsage]
        assert parked is not None and parked.poll() is None
        (surplus,) = [process for process in spawned if process is not parked]
        # wait() inside the close path collected the exit status: no zombie.
        assert surplus.returncode is not None

        _spawning_request(monkeypatch, spawned, None)
        assert pool.request(b"single", deadline_monotonic=time.monotonic() + 5) == b"single"
        assert len(spawned) == 2, "a lone request must reuse the parked stream"
        assert pool._idle[0]._process is parked  # pyright: ignore[reportPrivateUsage]
    finally:
        assert pool.close() is True
    assert all(process.returncode is not None for process in spawned)


def test_streams_used_within_the_ttl_stay_parked_for_the_next_burst(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    _spawning_request(monkeypatch, spawned, threading.Barrier(2))
    pool = _pool(tmp_path)
    try:
        assert _overlap_two_requests(pool) == [b"request-0", b"request-1"]
        assert _overlap_two_requests(pool) == [b"request-0", b"request-1"]
        assert len(spawned) == 2, "a second burst must reuse both parked streams"
        assert len(pool._idle) == 2  # pyright: ignore[reportPrivateUsage]
        assert all(process.poll() is None for process in spawned)
    finally:
        assert pool.close() is True
    assert pool._trim_timer is None  # pyright: ignore[reportPrivateUsage]
    assert all(process.returncode is not None for process in spawned)


def test_closing_the_pool_cancels_a_pending_trim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    _spawning_request(monkeypatch, spawned, threading.Barrier(2))
    pool = _pool(tmp_path)
    try:
        assert _overlap_two_requests(pool) == [b"request-0", b"request-1"]
        timer = pool._trim_timer  # pyright: ignore[reportPrivateUsage]
        assert timer is not None
    finally:
        assert pool.close() is True
    timer.join(timeout=5)
    assert not timer.is_alive()
    assert pool._trim_timer is None  # pyright: ignore[reportPrivateUsage]
    assert all(process.returncode is not None for process in spawned)
