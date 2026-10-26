from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane as direct_lane
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_LANE_ACK_LEASE_MS,
    DIRECT_LANE_ACK_SCHEMA,
    NativePolicySnapshotDirectLaneAck,
    direct_lane_binding,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="the Windows direct-lane ACK writer")

DIGEST = "a" * 64


class _Publisher(NativePolicySnapshotDirectLaneAck):
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self._acked = False


def test_windows_binding_keeps_the_cpython_stat_identity(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("x", encoding="utf-8")
    observed = policy.stat()
    identity = (observed.st_mtime_ns, observed.st_size, observed.st_ino, observed.st_ctime_ns)

    binding = direct_lane_binding(inputs=((str(policy), identity),), workspaces=(tmp_path,))

    assert binding is not None
    mtime_ns, size, ino, ctime_ns = identity
    assert binding["inputs"] == [
        {"path": str(policy), "stat": {"mtime_ns": mtime_ns, "size": size, "ino": ino, "ctime_ns": ctime_ns}}
    ]


def test_windows_ack_is_written_privately_and_withdrawn(tmp_path: Path) -> None:
    publisher = _Publisher(tmp_path / "guard-home")
    ack = publisher._direct_lane_ack_path()

    publisher._acked = True
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})

    body = json.loads(ack.read_bytes())
    assert body["schema"] == DIRECT_LANE_ACK_SCHEMA
    assert (body["generation"], body["policy_digest"]) == (3, DIGEST)
    assert 0 < body["lease_expires_at_ms"] - direct_lane._now_ms() <= DIRECT_LANE_ACK_LEASE_MS
    assert [entry.name for entry in ack.parent.iterdir()] == [ack.name]

    publisher._acked = False
    publisher._renew_direct_lane_ack()
    assert not ack.exists()
    # A second withdrawal finds nothing to delete and stays quiet.
    publisher._renew_direct_lane_ack()
    assert not ack.exists()


def test_windows_ack_withdrawal_failure_closes_the_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = _Publisher(tmp_path / "guard-home")
    publisher._acked = True
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    assert publisher._direct_lane_lease_expires_at_ms > 0

    def refuse(_path: Path) -> None:
        raise NativePolicySnapshotError("native_policy_windows_temporary_cleanup_failed")

    monkeypatch.setattr(direct_lane, "unlink_windows_ack", refuse)
    publisher._acked = False

    assert publisher._direct_lane_ack_target is None
    assert publisher._direct_lane_lease_expires_at_ms == 0
