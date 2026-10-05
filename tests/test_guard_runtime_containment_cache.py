"""Containment health refresh must not stall concurrent runtime readers."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon.server import cached_containment_health


def _server(**overrides: object) -> SimpleNamespace:
    server = SimpleNamespace(
        containment_health_cache=None,
        containment_health_cache_monotonic=0.0,
        containment_health_cache_lock=threading.Lock(),
        containment_health_refreshing=False,
        containment_health_refresh_event=threading.Event(),
        containment_health_generation=0,
        containment_health_completed_generation=0,
    )
    for key, value in overrides.items():
        setattr(server, key, value)
    return server


def test_fresh_containment_cache_skips_the_probe() -> None:
    calls: list[str] = []

    def probe() -> dict[str, object]:
        calls.append("probe")
        return {"status": "new"}

    payload = cached_containment_health(
        _server(
            containment_health_cache={"status": "cached"},
            containment_health_cache_monotonic=time.monotonic(),
        ),
        force_refresh=False,
        probe=probe,
    )
    assert payload == {"status": "cached"}
    assert calls == []


def test_stale_refresh_is_single_flight_and_readers_keep_the_previous_payload() -> None:
    server = _server(
        containment_health_cache={"status": "old"},
        containment_health_cache_monotonic=time.monotonic() - 11,
    )
    started = threading.Barrier(8)
    release_probe = threading.Event()
    calls: list[int] = []
    call_lock = threading.Lock()

    def probe() -> dict[str, object]:
        with call_lock:
            calls.append(1)
        assert release_probe.wait(timeout=2)
        return {"status": "new"}

    results: list[dict[str, object] | None] = []
    result_lock = threading.Lock()

    def reader() -> None:
        started.wait()
        payload = cached_containment_health(server, force_refresh=False, probe=probe)
        with result_lock:
            results.append(payload)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with result_lock:
            if len(results) >= 7:
                break
        time.sleep(0.01)
    with result_lock:
        early = list(results)
    release_probe.set()
    for thread in threads:
        thread.join(timeout=2)
    assert [thread.is_alive() for thread in threads] == [False] * 8
    assert len(calls) == 1
    assert early == [{"status": "old"}] * len(early)
    assert len(early) >= 7
    assert {"status": "new"} in results
    assert all(payload in ({"status": "old"}, {"status": "new"}) for payload in results)


def test_cold_callers_share_one_probe() -> None:
    server = _server()
    started = threading.Barrier(4)
    calls: list[int] = []

    def probe() -> dict[str, object]:
        calls.append(1)
        time.sleep(0.2)
        return {"status": "ready"}

    results: list[dict[str, object] | None] = []
    result_lock = threading.Lock()

    def reader() -> None:
        started.wait()
        payload = cached_containment_health(server, force_refresh=False, probe=probe)
        with result_lock:
            results.append(payload)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert [thread.is_alive() for thread in threads] == [False] * 4
    assert len(calls) == 1
    assert results == [{"status": "ready"}] * 4


def test_forced_refresh_does_not_reuse_a_probe_that_was_already_running() -> None:
    server = _server(
        containment_health_cache={"status": "stale"},
        containment_health_cache_monotonic=time.monotonic() - 11,
    )
    release_first = threading.Event()
    first_started = threading.Event()
    probes: list[str] = []

    def probe() -> dict[str, object]:
        probes.append("run")
        if len(probes) == 1:
            first_started.set()
            assert release_first.wait(timeout=2)
            return {"status": "first"}
        return {"status": "second"}

    forced: dict[str, dict[str, object] | None] = {}

    def force() -> None:
        forced["value"] = cached_containment_health(server, force_refresh=True, probe=probe)

    holder = threading.Thread(target=lambda: cached_containment_health(server, force_refresh=False, probe=probe))
    forcer = threading.Thread(target=force)
    holder.start()
    assert first_started.wait(timeout=2)
    forcer.start()
    assert forcer.is_alive()
    assert probes == ["run"]
    release_first.set()
    holder.join(timeout=2)
    forcer.join(timeout=2)
    assert holder.is_alive() is False
    assert forcer.is_alive() is False
    assert forced["value"] == {"status": "second"}
    assert probes == ["run", "run"]


def test_probe_failure_releases_the_refresh_and_clears_the_cache() -> None:
    server = _server(containment_health_cache={"status": "old"})

    def probe() -> dict[str, object]:
        raise OSError("probe failed")

    assert cached_containment_health(server, force_refresh=True, probe=probe) is None
    assert server.containment_health_refreshing is False
    assert server.containment_health_cache is None

    def unexpected() -> dict[str, object]:
        raise KeyError("probe crashed")

    server.containment_health_cache = {"status": "previous"}
    server.containment_health_cache_monotonic = time.monotonic()
    try:
        cached_containment_health(server, force_refresh=True, probe=unexpected)
    except KeyError:
        pass
    else:
        raise AssertionError("unexpected probe error was swallowed")
    assert server.containment_health_refreshing is False
    assert server.containment_health_cache is None
