"""Background cache maintenance must survive a security-proof outage."""

import os
import threading
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import active_security, cache_io, discovery
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer


@pytest.mark.parametrize("outage", [False, True])
def test_periodic_cleanup_runs_after_security_observation(monkeypatch, tmp_path, outage):
    waits = iter((False, True))
    calls = []
    store = SimpleNamespace(guard_home=tmp_path)

    def observe(value):
        assert value is store
        calls.append("observe")
        if outage:
            raise OSError("isolated publication outage")

    def cleanup(value):
        assert value is store
        calls.append("cleanup")

    monkeypatch.setattr(active_security, "observe", observe)
    monkeypatch.setattr(cache_io, "cleanup", cleanup)
    monkeypatch.setattr(discovery, "request_refresh", lambda home, *, store: calls.append("discovery"))
    daemon = SimpleNamespace(
        _shutdown_started=SimpleNamespace(wait=lambda interval: next(waits)),
        _extension_control_refresh_interval_seconds=1,
        _server=SimpleNamespace(
            store=store,
            refresh_extension_control_runtime=lambda: calls.append("refresh"),
            extension_control_api=SimpleNamespace(expire_prepared_cache_leases=lambda: None),
        ),
    )
    GuardDaemonServer._refresh_extension_control_loop(daemon)
    assert calls == (["observe", "discovery", "cleanup"] if outage else ["observe", "discovery", "refresh", "cleanup"])


def test_expired_previews_release_only_native_selected_leases(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle
    from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
    from tests.native_activation_support import native

    monkeypatch.setattr(lifecycle, "invoke", native)
    expired = cache_io.Lease(tmp_path / "expired")
    active = cache_io.Lease(tmp_path / "active")
    old = SimpleNamespace(expires_at=0.0, draft=SimpleNamespace(_cache_lease=expired))
    current = SimpleNamespace(expires_at=time.monotonic() + 300.0, draft=SimpleNamespace(_cache_lease=active))
    service = SimpleNamespace(
        _preview_lock=threading.Lock(),
        _apply_lock=threading.Lock(),
        _proof_lock=threading.Lock(),
        _candidates=SimpleNamespace(values={"old": old, "current": current}),
        _pending_proofs={"retained-proof": SimpleNamespace(candidate=old), "other": SimpleNamespace(candidate=None)},
    )
    try:
        ExtensionControlApiService.expire_prepared_cache_leases(service)
        assert expired.fd is None and active.fd is not None
        assert service._pending_proofs["retained-proof"].candidate is old
        assert service._candidates.values["current"] is current
    finally:
        expired.close()
        active.close()


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
def test_cache_lease_reuses_private_file_io_validation_without_writing_aliases(tmp_path, kind):
    if kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable on this platform")
    cache = tmp_path / "cache"
    cache.mkdir()
    victim = tmp_path / "outside"
    victim.write_bytes(b"")
    path = cache / ".cache-lease"
    if kind == "hardlink":
        os.link(victim, path)
    else:
        os.mkfifo(path, 0o600)
    with pytest.raises(RuntimeError, match="authority_path_invalid"):
        cache_io.Lease(cache)
    assert victim.read_bytes() == b""
