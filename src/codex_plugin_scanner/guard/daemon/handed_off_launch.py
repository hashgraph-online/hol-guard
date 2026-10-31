"""Resolve a launch receipt whose daemon already published its handoff.

A launcher tombstones its receipt only when it sees the handoff itself. When the
launcher stops waiting first, for example because an updated Core took longer
to load than the post-update start window, the daemon still comes up and signs
state that binds the launch nonce, but nothing clears the receipt. Retirement
and later starts then refuse to touch the home until that daemon exits, which
wedges every later update.

The same proof the launcher would have used closes that gap: the signed state
carries the receipt's nonce, port, owner and generation, and its process is the
launch root or one of its descendants. The runtime fingerprint is not compared,
because a launcher may start another executable by design.
"""

from __future__ import annotations

from pathlib import Path


def resolve_handed_off_guard_daemon_pending_launch(guard_home: Path, pending: dict[str, object] | None) -> bool:
    """Tombstone a pending launch only when its live signed state binds it."""

    from . import manager

    if pending is None or not manager._guard_daemon_pending_launch_is_generation_bound(pending):
        return False
    pid = pending.get("pid")
    launch_nonce = pending.get("launch_nonce")
    marker = pending.get("process_start_marker")
    if type(pid) is not int or not isinstance(launch_nonce, str) or not isinstance(marker, str):
        return False
    if not manager._guard_daemon_handoff_matches_launch(
        guard_home,
        launch_nonce=launch_nonce,
        expected_pid=pid,
        require_same_runtime=False,
    ):
        return False
    creation_time = pending.get("process_creation_time")
    return manager._clear_guard_daemon_pending_launch_if_current(
        guard_home,
        pid=pid,
        creation_time=creation_time if type(creation_time) is int else None,
        launch_nonce=launch_nonce,
        process_start_marker=marker,
    )
