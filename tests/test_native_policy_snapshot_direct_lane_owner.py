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


def test_a_new_publisher_withdraws_an_ack_only_once_its_writer_process_exits(tmp_path: Path) -> None:
    # The kernel releases the writer's liveness lock when its process ends.
    import subprocess
    import sys

    (tmp_path / "native-runtime").mkdir(mode=0o700)
    writer = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys, time; from pathlib import Path\n"
            "from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import "
            "NativePolicySnapshotDirectLaneAck as Ack\n"
            "p = Ack(); p.guard_home = Path(sys.argv[1]); p._acked = True\n"
            "p._publish_direct_lane_ack({'generation': 7, 'policy_digest': '7' * 64})\n"
            "print('ready', flush=True); sys.stdin.read()\n",
            str(tmp_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert writer.stdout is not None
        assert writer.stdout.readline().strip() == "ready"
        ack = tmp_path / "native-runtime" / "direct-lane" / "ack.json"

        peer = NativePolicySnapshotDirectLaneAck()
        peer.guard_home = tmp_path
        peer._withdraw_abandoned_direct_lane_ack()
        assert json.loads(ack.read_bytes())["generation"] == 7
    finally:
        writer.kill()
        writer.wait(5)

    peer._withdraw_abandoned_direct_lane_ack()
    assert not ack.exists()


def test_a_live_superseded_publisher_does_not_keep_a_dead_writers_ack(tmp_path: Path, clock: list[int]) -> None:
    # Publisher A wrote generation 3 and is still alive. B wrote generation 5
    # over it and then exited, leaving its ACK behind.
    stale = _Publisher(tmp_path, 3)
    gone = _Publisher(tmp_path, 5)
    ack = gone._direct_lane_ack_path()
    gone._release_direct_lane_liveness()
    assert _ack(stale)["generation"] == 5

    peer = NativePolicySnapshotDirectLaneAck()
    peer.guard_home = tmp_path
    peer._withdraw_abandoned_direct_lane_ack()
    assert not ack.exists()
    # The dead writer's lock file is pruned; the live publisher's stays.
    assert sorted(entry.name for entry in ack.parent.iterdir()) == sorted([f".{ack.name}.lock", f".{ack.name}.3.live"])


def test_a_live_writer_keeps_its_ack_after_moving_to_a_new_generation(tmp_path: Path, clock: list[int]) -> None:
    live = _Publisher(tmp_path, 3)
    live._publish_direct_lane_ack({"generation": 4, "policy_digest": "4" * 64})
    ack = live._direct_lane_ack_path()

    peer = NativePolicySnapshotDirectLaneAck()
    peer.guard_home = tmp_path
    peer._withdraw_abandoned_direct_lane_ack()
    assert _ack(live)["generation"] == 4
    assert sorted(entry.name for entry in ack.parent.iterdir()) == sorted(
        [ack.name, f".{ack.name}.lock", f".{ack.name}.4.live"]
    )
