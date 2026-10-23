"""Real timer + native security protocol; synthetic publisher/credential/SQL IO.

Executable compiler/factory/enable coverage lives in the companion refresh
test. These small security fixtures isolate the independent observation lane.
"""

import threading
from types import SimpleNamespace

from codex_plugin_scanner.guard.catalog_delivery import (
    active_security,
    cache_io,
    current_refresh,
    discovery,
    transport,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_native_active_pack_security import device as device
from tests.test_native_active_pack_security import publication


def test_real_revocation_observation_runs_while_complete_view_is_blocked(device, delivery, monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import preparation_authority

    for field, value in dict(_home=None, _refresh_worker=None, _refresh_after=0.0, _handle=None).items():
        monkeypatch.setattr(discovery, field, value)
    entered, release = threading.Event(), threading.Event()

    def blocked(store):
        entered.set()
        assert release.wait(30)
        raise OSError("synthetic metadata outage")

    monkeypatch.setattr(current_refresh, "refresh", blocked)
    monkeypatch.setattr(cache_io, "cleanup", lambda _store: {"evicted": 0})
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: None)
    verified = publication(delivery)
    monkeypatch.setattr(transport, "fetch_root", lambda **kw: verified)
    monkeypatch.setattr(transport, "fetch_object", delivery.fetch)

    class Stop:
        count = 0

        def wait(self, seconds):
            self.count += 1
            return self.count > 1

    def tick():
        daemon = SimpleNamespace(
            _shutdown_started=Stop(),
            _extension_control_refresh_interval_seconds=0.1,
            _server=SimpleNamespace(
                store=device,
                refresh_extension_control_runtime=lambda: None,
                extension_control_api=SimpleNamespace(expire_prepared_cache_leases=lambda: None),
            ),
        )
        GuardDaemonServer._refresh_extension_control_loop(daemon)

    discovery.request_refresh(device.guard_home, store=device)
    worker = discovery._refresh_worker
    try:
        assert entered.wait(5)
        tick()
        result = active_security.invoke("read", device, record=active_security.read(device))
        assert not result["pending"] and result["quarantine"] == ["command.core"]
        with device._connect() as connection:
            assert [tuple(row) for row in connection.execute("select artifact_hash,action from policy_decisions")] == [
                ("retained-exact-action", "allow")
            ]
        retained = active_security.read(device)
        monkeypatch.setattr(transport, "fetch_root", lambda **kw: delivery.verified())
        tick()
        assert active_security.read(device) == retained
    finally:
        release.set()
        worker.join(30)
    assert not worker.is_alive()
