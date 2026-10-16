"""Windows direct-lane ACK file I/O through verified private handles."""

from __future__ import annotations

import os
import threading
from pathlib import Path

# Mirrors DIRECT_LANE_ACK_MAX_BYTES, the most the resident reads.
ACK_MAX_BYTES = 1024


def write_windows_ack(guard_home: Path, path: Path, body: bytes) -> None:
    """Commit the ACK through the private, DACL-checked Windows writer."""

    from .native_policy_snapshot_windows_atomic import _windows_write_private_file_atomic
    from .native_policy_snapshot_windows_state import (
        _windows_ensure_private_directory,
        _windows_private_directory_binding,
    )

    for directory in (guard_home, path.parent.parent, path.parent):
        _windows_ensure_private_directory(directory)
    with _windows_private_directory_binding(path.parent) as binding:
        _windows_write_private_file_atomic(
            parent_path=binding.path,
            parent_handle=binding.handle,
            directory_handles=binding.handles,
            temporary_name=f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp",
            destination_name=path.name,
            payload=body,
            maximum_bytes=ACK_MAX_BYTES,
            kind="direct_lane_ack",
        )


def unlink_windows_ack(path: Path) -> None:
    """Withdraw the ACK through the bound, owner-checked ACK directory.

    A pathname unlink could follow a directory swapped after publication;
    deleting through the verified parent and file handles cannot.
    """

    from .native_policy_snapshot_windows_atomic import _windows_delete_private_child
    from .native_policy_snapshot_windows_state import _windows_private_directory_binding

    with _windows_private_directory_binding(path.parent) as binding:
        _windows_delete_private_child(parent_path=binding.path, parent_handle=binding.handle, name=path.name)
