"""Windows direct-lane ACK file I/O through verified private handles."""

from __future__ import annotations

from pathlib import Path

# Mirrors DIRECT_LANE_ACK_MAX_BYTES, the most the resident reads.
ACK_MAX_BYTES = 1024


def write_windows_ack(guard_home: Path, path: Path, body: bytes) -> None:
    """Commit the ACK through the runtime's private, DACL-checked Windows writer."""

    from .native_policy_snapshot_windows_atomic import _windows_write_private_file_atomic

    _windows_write_private_file_atomic(
        directory=path.parent,
        name=path.name,
        payload=body,
        maximum_bytes=ACK_MAX_BYTES,
        private_root=guard_home,
    )


def unlink_windows_ack(guard_home: Path, path: Path) -> None:
    """Withdraw the ACK through its verified, owner-checked file handle.

    A pathname unlink could follow a directory swapped after publication;
    the runtime deletes through the held parent and verified file handles.
    """

    from .native_policy_snapshot_windows_atomic import _windows_delete_private_child

    _windows_delete_private_child(directory=path.parent, name=path.name, private_root=guard_home)
