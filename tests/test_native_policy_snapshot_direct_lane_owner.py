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


def test_an_ack_removed_by_another_publisher_is_rewritten_before_the_lease_runs_down(
    tmp_path: Path, clock: list[int]
) -> None:
    # A one-shot hook's publisher shares the ACK path and removes it on exit.
    live = _Publisher(tmp_path, 3)
    expires = _ack(live)["lease_expires_at_ms"]
    live._direct_lane_ack_path().unlink()

    clock[0] += 100
    live._renew_direct_lane_ack()
    assert _ack(live)["generation"] == 3

    # A present ACK with lease to spare is left as it is.
    live._renew_direct_lane_ack()
    assert _ack(live)["lease_expires_at_ms"] == clock[0] + DIRECT_LANE_ACK_LEASE_MS
    assert _ack(live)["lease_expires_at_ms"] != expires


def test_restoring_a_removed_ack_never_replaces_one_a_newer_publisher_wrote(tmp_path: Path, clock: list[int]) -> None:
    # Publishers in other processes share the ACK. One holds the file lock
    # while it writes generation 5; the older publisher restoring its removed
    # ACK must wait for it and then leave the newer ACK alone.
    import fcntl
    import threading

    stale = _Publisher(tmp_path, 3)
    path = stale._direct_lane_ack_path()
    path.unlink()
    lock = os.open(path.with_name(f".{path.name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        clock[0] += 100
        restore = threading.Thread(target=stale._renew_direct_lane_ack)
        restore.start()
        restore.join(0.2)
        assert restore.is_alive()
        newer = {
            "schema": direct_lane.DIRECT_LANE_ACK_SCHEMA,
            "generation": 5,
            "policy_digest": "5" * 64,
            "lease_expires_at_ms": clock[0] + DIRECT_LANE_ACK_LEASE_MS,
        }
        path.write_text(json.dumps(newer))
    finally:
        os.close(lock)
    restore.join(5)
    assert not restore.is_alive()
    assert _ack(stale)["generation"] == 5
