"""Soak the daemon's transport and prove it gives back everything it borrows.

The chaos gate next door asks whether a hostile shape is refused. This file
asks the question only volume can answer: after a hundred thousand requests the
daemon must hold no more memory, threads, descriptors, sockets or processes
than it held at the start, and a token retired along the way must never open a
door again.

A leak of a few kilobytes or one descriptor per request is invisible in a
handful of requests and fatal in a daemon that runs for weeks, so each
measurement is taken twice: once after a warm-up that lets caches, pools and
allocator arenas reach their working size, and once after the measured phase.
Growth between those two readings is the daemon keeping something, not the
process settling in.

``HOL_GUARD_DAEMON_SOAK=full`` runs the full hundred thousand requests and the
full rotation ladder. A pull request runs a fraction of each, so every change
exercises this code and the volume is paid for once a night.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.error
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.auth_token import auth_token_path
from codex_plugin_scanner.guard.daemon.bounded_http import (
    _DEFAULT_SOCKET_TIMEOUT_SECONDS,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from tests.coverage_ci import under_coverage_scale

# The transport helpers are shared with the chaos gate deliberately. Both files
# drive the same daemon over the same framing, and a second copy of the request
# builders would drift away from the shapes the daemon actually answers.
from tests.test_guard_daemon_chaos_gate import (
    MALFORMED_SHAPES,
    PRETOOL_PAYLOAD,
    _authenticated_hook,
    _chaos_daemon,
    _daemon_subprocess,
    _drain,
    _exchange,
    _frame,
    _healthy,
    _hook_query,
    _saturated_hook_queue,
    _started_daemon,
    _status_code,
    _watch_handler_errors,
)

if sys.platform == "win32":  # pragma: no cover - the resident-size reading is POSIX-only
    resource: Any = None
else:
    import resource

_FULL_SCALE = os.environ.get("HOL_GUARD_DAEMON_SOAK") == "full"

SOAK_REQUESTS = 100_000 if _FULL_SCALE else 1_200
WARMUP_REQUESTS = 4_000 if _FULL_SCALE else 240
ROTATION_GENERATIONS = 16 if _FULL_SCALE else 8
ROTATION_REQUESTS = 400 if _FULL_SCALE else 32
#: How much of the soak is driven while the hook scheduler refuses.
#:
#: A refused hook runs a different piece of code from an admitted one and
#: allocates its own answer, so the soak drives both. The bulk of the volume
#: goes through admission, since that is the path a daemon spends its life
#: on, and a bounded burst covers the refusal.
REFUSAL_REQUESTS = 2_000 if _FULL_SCALE else 160
WORKER_THREADS = 8

#: Peak resident growth the measured phase may add over the warm-up's peak.
#:
#: ``ru_maxrss`` reports a high-water mark, so this is not a reading of what the
#: daemon holds now; it answers "did the measured phase ever need more than the
#: warm-up did". A per-request leak over tens of thousands of requests clears
#: this by orders of magnitude, while ordinary variation in arena reuse and
#: interpreter caches stays well inside it.
RSS_HEADROOM_BYTES = 64 * 1024 * 1024
LEAK_HEADROOM = WORKER_THREADS
#: How much a rotation ladder may gain without being called a leak.
#:
#: The record store keeps a small cache of open database handles, and which
#: generation widens it depends on which thread serves a request, so the count
#: can step up once part way along. A leak does not step once, it steps every
#: generation, so the slack stays well below the number of generations measured
#: against it.
ROTATION_SLACK = 2

#: How long the daemon has to give a thread or descriptor back after draining.
SETTLE_SECONDS = 30.0
# A connection the server has answered keeps its handler thread until the
# socket times out, so a count holds still for that long while the daemon is
# still giving threads back. The window outlasts that timeout, otherwise the
# plateau in the middle of the hand-back reads as the end of it.
QUIET_SECONDS = _DEFAULT_SOCKET_TIMEOUT_SECONDS + 2.0

#: How long a count must hold still once the daemon has been stopped.
#:
#: Stopping closes the listener and the sockets it was holding, so no connection
#: is waiting out its timeout and only the unwinding itself has to finish.
QUIET_AFTER_STOP_SECONDS = 2.0

#: How long one soak worker may take before the case calls it wedged.
WORKER_DEADLINE_SECONDS = 1800.0


def _peak_rss_bytes() -> int | None:
    if resource is None:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _open_descriptor_count() -> int | None:
    """Count this process's open descriptors, or report that it cannot.

    Linux publishes them under ``/proc/self/fd`` and macOS under ``/dev/fd``.
    Windows publishes neither, and a platform that cannot be measured says so
    rather than returning a number that means nothing.
    """

    for root in ("/proc/self/fd", "/dev/fd"):
        if not os.path.isdir(root):
            continue
        with suppress(OSError):
            return len([name for name in os.listdir(root) if name.isdigit()])
    return None


def _quiesced(
    reading: Callable[[], int | None],
    *,
    stable_seconds: float = QUIET_SECONDS,
    deadline_seconds: float = SETTLE_SECONDS,
) -> int | None:
    """Report ``reading`` once it stops moving.

    The daemon answers each connection on its own thread and then holds the
    socket open for the keep-alive timeout, so a count taken the instant a
    burst ends includes threads and descriptors that are already on their way
    out. Waiting for the number to hold still reads what the daemon kept rather
    than what it is still putting down. The wait is bounded, because a leak
    must fail the case rather than hang it, and a reading that never settles is
    reported as it last stood.
    """

    # The window is longer than the server's keep-alive timeout on purpose:
    # while idle connections are still being timed out the count sits on a
    # plateau, and a shorter window would read that plateau as the end state.
    current = reading()
    if current is None:
        return None
    deadline = time.monotonic() + deadline_seconds
    steady_from = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(0.25)
        latest = reading()
        if latest != current:
            current = latest
            steady_from = time.monotonic()
            continue
        if time.monotonic() - steady_from >= stable_seconds:
            return current
    return current


def _press(
    port: int,
    token: str,
    query: str,
    daemon: GuardDaemonServer,
    index: int,
    *,
    hooks_refused: bool,
) -> str:
    """Send one request of the shape ``index`` selects and name what it was.

    Each shape leaves the daemon somewhere different: a health check never
    reaches authentication, a forged token stops there, a malformed frame never
    reaches a handler, and a hook runs the whole way to an answer. A soak that
    drove only one of them would leave the other three paths unmeasured.

    ``hooks_refused`` says which answer the hook shape must produce. Under a
    full queue the scheduler turns the hook away before it reaches a review,
    which is the fallback's own code rather than the review's; otherwise the
    hook is admitted and runs the path the daemon spends its life on.
    """

    shape = index % 4
    if shape == 0:
        assert _healthy(port, timeout=10.0 * under_coverage_scale(4.0))
        return "health"
    if shape == 1:
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
        forged = f"forged-{index:08d}-{'c' * 24}"
        assert _status_code(_exchange(port, _frame(forged, headers, body))) == 401
        return "forged"
    if shape == 2:
        malformed_headers, malformed_body, expected = MALFORMED_SHAPES[index % len(MALFORMED_SHAPES)]
        assert _status_code(_exchange(port, _frame(token, malformed_headers, malformed_body))) == expected
        return "malformed"
    answer = _authenticated_hook(daemon, query, timeout=30.0 * under_coverage_scale(4.0))
    if hooks_refused:
        assert answer["decision"] == "deny"
        assert answer["reason_code"] == "daemon_hook_queue_capacity"
        return "refused"
    # Whatever the review decides, the scheduler must have let it run: a
    # capacity refusal here would mean the soak never reached the hook path it
    # is meant to be measuring.
    assert answer.get("reason_code") != "daemon_hook_queue_capacity"
    assert answer["decision"] in {"allow", "ask", "deny"}
    return "hook"


def _press_range(
    port: int,
    token: str,
    query: str,
    daemon: GuardDaemonServer,
    start: int,
    count: int,
    *,
    hooks_refused: bool,
) -> list[str]:
    return [
        _press(port, token, query, daemon, index, hooks_refused=hooks_refused) for index in range(start, start + count)
    ]


def _press_concurrently(
    port: int,
    token: str,
    query: str,
    daemon: GuardDaemonServer,
    start: int,
    count: int,
    *,
    hooks_refused: bool,
) -> list[str]:
    """Drive ``count`` requests from ``WORKER_THREADS`` threads.

    Plain threads over contiguous slices, rather than a pool mapped over one
    task per request, because a hundred thousand futures and their results
    would themselves occupy the memory this file is measuring.
    """

    shapes: list[list[str]] = [[] for _ in range(WORKER_THREADS)]
    sizes = [count // WORKER_THREADS] * WORKER_THREADS
    for extra in range(count % WORKER_THREADS):
        sizes[extra] += 1

    offsets: list[int] = []
    running = start
    for size in sizes:
        offsets.append(running)
        running += size

    errors: list[BaseException] = []

    def drive(worker: int) -> None:
        try:
            shapes[worker] = _press_range(
                port,
                token,
                query,
                daemon,
                offsets[worker],
                sizes[worker],
                hooks_refused=hooks_refused,
            )
        except BaseException as error:  # re-raised on the test's thread
            errors.append(error)

    # The workers are daemon threads so that one which never finishes cannot
    # keep the interpreter alive past the failure it caused.
    threads = [threading.Thread(target=drive, args=(worker,), daemon=True) for worker in range(WORKER_THREADS)]
    for thread in threads:
        thread.start()
    # One deadline for the group rather than one apiece: joining each worker
    # for the full span in turn would let a stalled soak take as long as the
    # number of workers to report, and the deadline is meant to bound the wait.
    deadline = time.monotonic() + WORKER_DEADLINE_SECONDS
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    # A request that failed is raised here, on the thread running the test, so
    # the failure names the request rather than the short result it left behind.
    if errors:
        raise errors[0]
    for thread in threads:
        assert not thread.is_alive(), "a soak worker never finished"
    return [shape for worker_shapes in shapes for shape in worker_shapes]


@pytest.mark.security_critical
def test_a_long_soak_returns_every_thread_descriptor_and_page_it_borrowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        port = daemon.port
        token = daemon._server.auth_token
        query = _hook_query(daemon, tmp_path)

        warmup = _press_concurrently(port, token, query, daemon, 0, WARMUP_REQUESTS, hooks_refused=False)
        assert _drain(daemon) == 0
        baseline_threads = _quiesced(threading.active_count)
        baseline_descriptors = _quiesced(_open_descriptor_count)
        baseline_rss = _peak_rss_bytes()

        measured = _press_concurrently(port, token, query, daemon, WARMUP_REQUESTS, SOAK_REQUESTS, hooks_refused=False)
        # The refusal the scheduler produces under a full queue allocates an
        # answer of its own without reaching a review, so it is driven inside
        # the same measured window instead of being left to the chaos gate.
        with _saturated_hook_queue(daemon):
            refused = _press_concurrently(
                port,
                token,
                query,
                daemon,
                WARMUP_REQUESTS + SOAK_REQUESTS,
                REFUSAL_REQUESTS,
                hooks_refused=True,
            )
        remaining = _drain(daemon, deadline_seconds=SETTLE_SECONDS)

        settled_threads = _quiesced(threading.active_count)
        settled_descriptors = _quiesced(_open_descriptor_count)
        settled_rss = _peak_rss_bytes()
        still_serving = _healthy(port)

    assert len(warmup) == WARMUP_REQUESTS
    assert len(measured) == SOAK_REQUESTS
    assert set(measured) == {"health", "forged", "malformed", "hook"}
    assert len(refused) == REFUSAL_REQUESTS
    assert set(refused) == {"health", "forged", "malformed", "refused"}
    assert handler_errors == []
    assert remaining == 0
    assert still_serving
    # A leak scales with the work. At this volume a thread or descriptor kept
    # per request would show as hundreds of them, so the headroom absorbs the
    # connection threads still unwinding when the wait above gives up under a
    # loaded host without being able to absorb a leak.
    assert SOAK_REQUESTS >= 100 * LEAK_HEADROOM, "the headroom only holds when the volume dwarfs it"
    assert REFUSAL_REQUESTS >= 4 * WORKER_THREADS, "every worker must reach every shape in the burst"
    assert baseline_threads is not None and settled_threads is not None
    assert settled_threads <= baseline_threads + LEAK_HEADROOM
    if baseline_descriptors is not None and settled_descriptors is not None:
        assert settled_descriptors <= baseline_descriptors + LEAK_HEADROOM
    if baseline_rss is not None and settled_rss is not None:
        assert settled_rss - baseline_rss <= RSS_HEADROOM_BYTES


@pytest.mark.security_critical
def test_every_rotation_retires_its_token_and_gives_back_what_it_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotate under load and prove no retired token still opens the door.

    One generation's token becomes the next generation's forged token, which is
    what makes this a rotation test rather than an assertion that two random
    strings differ: the 401 a retired token earns is checked against the real
    token the daemon issued a moment earlier. Rotation is a deletion because
    the daemon mints a token only when its guard home has none, so removing the
    file is the whole of what an operator rotating a daemon does.
    """

    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    guard_home = tmp_path / "guard-home"
    body = json.dumps(PRETOOL_PAYLOAD).encode()
    headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()

    issued: list[str] = []
    refusals: list[int] = []
    thread_counts: list[int | None] = []
    descriptor_counts: list[int | None] = []

    for generation in range(ROTATION_GENERATIONS):
        daemon = _started_daemon(guard_home)
        try:
            token = daemon._server.auth_token
            query = _hook_query(daemon, tmp_path)
            with _saturated_hook_queue(daemon):
                # This ladder asks what a retired generation leaves behind, so
                # it keeps the queue full and the hook cheap; the soak above
                # carries the volume through an admitted review.
                shapes = _press_range(
                    daemon.port,
                    token,
                    query,
                    daemon,
                    generation * ROTATION_REQUESTS,
                    ROTATION_REQUESTS,
                    hooks_refused=True,
                )
                assert set(shapes) == {"health", "forged", "malformed", "refused"}
                for retired in issued:
                    refusals.append(_status_code(_exchange(daemon.port, _frame(retired, headers, body))))
            issued.append(token)
            assert _drain(daemon, deadline_seconds=SETTLE_SECONDS) == 0
        finally:
            daemon.stop()
        auth_token_path(guard_home).unlink()
        # Each generation is read once the process holds still, so the number
        # recorded is what the retired daemon left behind rather than what it
        # was still unwinding. The daemon is already stopped here, so nothing is
        # waiting out a keep-alive timeout and a short window is enough.
        thread_counts.append(_quiesced(threading.active_count, stable_seconds=QUIET_AFTER_STOP_SECONDS))
        descriptor_counts.append(_quiesced(_open_descriptor_count, stable_seconds=QUIET_AFTER_STOP_SECONDS))

    assert len(issued) == ROTATION_GENERATIONS
    assert len(set(issued)) == ROTATION_GENERATIONS
    assert refusals and set(refusals) == {401}
    # A leak keeps taking: rotate often enough and the count climbs with every
    # generation. Shared resources the daemon acquires once do not climb, they
    # arrive and then sit still, so the test asks whether the second half of
    # the ladder stayed where the first half stood rather than whether the very
    # first generation cost nothing, and allows the bounded step a cache may
    # take part way along.
    settled = ROTATION_GENERATIONS // 2
    assert ROTATION_GENERATIONS - settled > ROTATION_SLACK, (
        "a leak costing one handle a generation must outgrow the slack over the generations measured"
    )
    assert all(count is not None for count in thread_counts)
    assert max(thread_counts[settled:]) <= max(thread_counts[:settled]) + ROTATION_SLACK  # type: ignore[type-var]
    if descriptor_counts[0] is not None:
        assert all(count is not None for count in descriptor_counts)
        assert max(descriptor_counts[settled:]) <= max(descriptor_counts[:settled]) + ROTATION_SLACK  # type: ignore[type-var]


@pytest.mark.security_critical
def test_a_soaked_daemon_process_exits_and_leaves_its_port_closed(tmp_path: Path) -> None:
    """A daemon that has carried load must still die when it is told to.

    Threads and descriptors are measured above inside one process. This asks
    what only a separate process can answer: once the daemon has carried
    traffic, does ending it actually end it, and does the listening socket go
    with it.
    """

    guard_home = tmp_path / "guard-home"
    with _daemon_subprocess(guard_home) as (process, port, _token):
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
        for index in range(ROTATION_REQUESTS):
            forged = f"forged-{index:08d}-{'d' * 24}"
            assert _status_code(_exchange(port, _frame(forged, headers, body))) == 401
        assert _healthy(port)
        assert process.poll() is None
        process.terminate()
        exit_status = process.wait(timeout=60)

    assert exit_status is not None
    deadline = time.monotonic() + SETTLE_SECONDS
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1.0).close()
        except OSError:
            break
        time.sleep(0.05)
    else:  # pragma: no cover - only reached when the port never closes
        pytest.fail("the daemon's port still accepted a connection after the process exited")

    with pytest.raises((urllib.error.URLError, OSError)):
        _healthy(port, timeout=2.0)
