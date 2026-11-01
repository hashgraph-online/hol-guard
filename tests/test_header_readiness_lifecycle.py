"""Owned readiness descriptors close/restart and retain bounded fallback."""

from __future__ import annotations

import socket
import threading
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import header_readiness
from codex_plugin_scanner.guard.daemon.header_readiness import HeaderWatchdog


def owner(request=None):
    return SimpleNamespace(
        unclassified_connections_lock=threading.Lock(),
        unclassified_connections={id(request): (request, 123)} if request is not None else {},
        pending_classifications={id(request): (("127.0.0.1", 1), 123)} if request is not None else {},
        saturation_probes={},
        _buffered_request_headers_complete=lambda *_args, **_options: False,
    )


def test_stop_closes_owned_pair_and_restart_uses_fresh_endpoints():
    watcher = HeaderWatchdog(owner())
    try:
        watcher.clear()
        reader, writer = watcher._reader, watcher._writer
        watcher.notify()
        assert watcher.wait(5) is False
        assert not watcher.is_set()
        watcher.close()
        assert reader.fileno() == writer.fileno() == -1
        watcher.clear()
        assert watcher._reader is not reader and watcher._writer is not writer
        assert not watcher.is_set()
        watcher.set()
        assert watcher.wait(5) is True
    finally:
        watcher.close()


def test_stop_wakes_a_blocked_wait_with_an_unread_socket():
    request, peer = socket.socketpair()
    watcher = HeaderWatchdog(owner(request))
    watcher.clear()
    entered = threading.Event()
    result = []

    def wait():
        entered.set()
        result.append(watcher.wait(5))

    thread = threading.Thread(target=wait, daemon=True)
    try:
        thread.start()
        assert entered.wait(1)
        watcher.set()
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert result == [True]
    finally:
        watcher.close()
        thread.join(timeout=1)
        request.close()
        peer.close()


def test_selector_failure_retains_the_original_periodic_wait(monkeypatch):
    watcher = HeaderWatchdog(owner())
    watcher.clear()
    waited = []
    original = watcher._stop.wait

    def unavailable():
        raise OSError("owned selector capacity fixture")

    def wait(timeout):
        waited.append(timeout)
        return original(timeout)

    monkeypatch.setattr(header_readiness.selectors, "DefaultSelector", unavailable)
    monkeypatch.setattr(watcher._stop, "wait", wait)
    try:
        assert watcher.wait(0.01) is False
        assert waited == [0.01]
        watcher.set()
        assert watcher.wait(5) is True
    finally:
        watcher.close()


def test_closed_pending_socket_is_left_to_its_existing_owner():
    request, peer = socket.socketpair()
    state = owner(request)
    watcher = HeaderWatchdog(state)
    watcher.clear()
    try:
        request.close()
        watcher.notify()
        assert watcher.wait(5) is False
        assert id(request) in state.pending_classifications
        assert not watcher.is_set()
    finally:
        watcher.close()
        request.close()
        peer.close()
