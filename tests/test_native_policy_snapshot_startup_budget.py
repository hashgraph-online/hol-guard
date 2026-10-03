"""Cold publication must not truncate the authenticated resident startup."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _PUBLISH_STARTUP_TIMEOUT_SECONDS,
    _PUBLISH_TIMEOUT_SECONDS,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _publish_snapshot_v3
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _config, _status


@pytest.mark.parametrize("cold,replacement", [(True, False), (False, False), (False, True)])
def test_publication_budget_matches_cold_or_warm_resident(
    tmp_path: Path, cold: bool, replacement: bool
) -> None:
    status = _status()
    publisher = SimpleNamespace(
        guard_home=tmp_path / "guard-home",
        _snapshot=None if cold else {"generation": 1},
        _wall_clock=time.time,
        _monotonic_clock=time.monotonic,
    )
    expected = _PUBLISH_STARTUP_TIMEOUT_SECONDS if cold or replacement else _PUBLISH_TIMEOUT_SECONDS
    calls = []

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        envelope = json.loads(payload)
        assert envelope["deadline_budget_ms"] == int(expected * 1000)
        deadline = kwargs["deadline_monotonic"]
        assert isinstance(deadline, float)
        remaining = deadline - time.monotonic()
        assert expected - 0.5 < remaining <= expected
        calls.append(payload)
        return _ack(payload)

    authority = NativePolicySnapshotPublisher(store=GuardStore(publisher.guard_home), status_provider=_status)
    try:
        controls = authority._compiled_command_extensions()
        if replacement:
            authority._snapshot = {"generation": 1}
            authority._resident_startup_required = False
            authority._input_fingerprint = ((), (("old-generation.json", 1, 1),))
            authority._accept_resident_fingerprint(((), (("new-generation.json", 1, 1),)))
            assert authority._resident_startup_required
            assert authority._renewal_after_generation is None
            publisher = authority
        elif not cold:
            authority._snapshot = {"generation": 1}
            authority._resident_startup_required = False
            authority.request_publish()
            assert not authority._resident_startup_required
            publisher = authority
    finally:
        authority.close()
    snapshot, generation = _publish_snapshot_v3(
        publisher=publisher,
        identity=status.identity,
        capabilities=status.capabilities,
        config=_config(),
        command_extensions=controls,
        master_key=b"k" * 32,
        client=client,
        renew_after_generation=None,
    )
    assert snapshot["generation"] > 0
    assert generation == 1
    assert len(calls) == 1
