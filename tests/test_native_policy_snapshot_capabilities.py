"""Runtime feature rejection must withdraw an earlier publication ACK."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock, _status


@pytest.mark.parametrize("extra_feature", [None, "unrelated-future-feature"])
def test_missing_required_feature_rejects_incomparable_runtime_capabilities(
    tmp_path: Path,
    extra_feature: str | None,
) -> None:
    status = _status()
    features = set(status.capabilities.features) - {"policy-snapshot-v3"}
    if extra_feature is not None:
        features.add(extra_feature)
    status.capabilities.features = tuple(features)
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        status_provider=lambda: status,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._snapshot = {"expires_at_ms": int(clock.wall * 1_000) + 60_000, "generation": 1}
    publisher._acked = True
    try:
        assert publisher.is_ready()
        assert publisher._publication_context() is None
        assert publisher.last_error == "native_policy_snapshot_protocol_unsupported"
        assert not publisher.is_ready()
    finally:
        publisher.close()
