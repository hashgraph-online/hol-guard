from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane as direct_lane
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_LANE_ACK_LEASE_MS,
    NativePolicySnapshotDirectLaneAck,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the direct lane is Unix-only")


class _Publisher(NativePolicySnapshotDirectLaneAck):
    def __init__(self, guard_home: Path, generation: int) -> None:
        self.guard_home = guard_home
        self._acked = True
        self._publish_direct_lane_ack({"generation": generation, "policy_digest": f"{generation:x}" * 64})


@pytest.fixture
def clock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    (tmp_path / "native-runtime").mkdir(mode=0o700)
    now = [1_000_000]
    monkeypatch.setattr(direct_lane, "_now_ms", lambda: now[0])
    return now


def _ack(publisher: _Publisher) -> dict[str, object]:
    return json.loads(publisher._direct_lane_ack_path().read_bytes())


def test_superseded_publisher_leaves_the_newer_ack_alone(tmp_path: Path, clock: list[int]) -> None:
    # Two daemon processes publish for one Guard home; the resident binds the newer one.
    stale = _Publisher(tmp_path, 3)
    current = _Publisher(tmp_path, 5)

    clock[0] += DIRECT_LANE_ACK_LEASE_MS
    stale._renew_direct_lane_ack()
    assert _ack(stale)["generation"] == 5

    current._renew_direct_lane_ack()
    assert _ack(current)["generation"] == 5
    assert _ack(current)["lease_expires_at_ms"] == clock[0] + DIRECT_LANE_ACK_LEASE_MS


def test_a_newer_generation_never_acknowledged_keeps_the_lease(tmp_path: Path, clock: list[int]) -> None:
    # Another publisher built generation 5 and exited before the resident acknowledged it.
    live = _Publisher(tmp_path, 3)
    (tmp_path / "native-policy-snapshot-generation-v3.json").write_text(json.dumps({"generation": 5}))

    clock[0] += DIRECT_LANE_ACK_LEASE_MS
    live._renew_direct_lane_ack()
    assert _ack(live)["generation"] == 3
    assert _ack(live)["lease_expires_at_ms"] == clock[0] + DIRECT_LANE_ACK_LEASE_MS


def test_a_missing_ack_is_rewritten_by_its_owner(tmp_path: Path, clock: list[int]) -> None:
    live = _Publisher(tmp_path, 3)
    live._direct_lane_ack_path().unlink()

    clock[0] += DIRECT_LANE_ACK_LEASE_MS
    live._renew_direct_lane_ack()
    assert _ack(live)["generation"] == 3
