"""Owner-private Windows state files, kept by the native runtime.

The runtime's ``windows-private-state`` command reads, replaces and deletes
each file through held directory handles and checks its owner and DACL; these
wrappers only encode the request and raise its failure code.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_BYTES, NativePolicySnapshotError

_PRIVATE_STATE_FEATURE = "native-windows-private-state-v1"
_PRIVATE_STATE_COMMAND = "windows-private-state"
_PRIVATE_STATE_SCHEMA = "windows-private-state.v1"
_PRIVATE_STATE_TIMEOUT_SECONDS = 10.0
_PRIVATE_STATE_ANSWER_OVERHEAD = 4096


def _private_state_answer(request: dict[str, object], *, output_limit: int) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _PRIVATE_STATE_FEATURE,
        _PRIVATE_STATE_COMMAND,
        {"schema": _PRIVATE_STATE_SCHEMA, **request},
        output_limit=output_limit,
        timeout_seconds=_PRIVATE_STATE_TIMEOUT_SECONDS,
    )


def _private_state(
    op: str,
    field: str,
    *,
    directory: Path,
    name: str,
    private_root: Path | None,
    output_limit: int = _PRIVATE_STATE_ANSWER_OVERHEAD,
    **request: object,
) -> object:
    """The runtime's `field` answer for one file, or its failure code raised."""

    body: dict[str, object] = {"op": op, "directory": str(directory), "name": name, **request}
    if private_root is not None:
        body["private_root"] = str(private_root)
    answer = _private_state_answer(body, output_limit=output_limit)
    if answer is None:
        raise NativePolicySnapshotError("native_windows_private_state_unavailable")
    error = answer.get("error")
    if isinstance(error, str) and error:
        raise NativePolicySnapshotError(error)
    if field not in answer:
        raise NativePolicySnapshotError("native_windows_private_state_unavailable")
    return answer[field]


def _windows_read_private_file(
    directory: Path,
    name: str,
    *,
    maximum_bytes: int,
    private_root: Path | None = None,
) -> bytes | None:
    """One owner-private file of at most `maximum_bytes`, or ``None`` when missing.

    With `private_root` the directories below it are created or repaired
    first, as a writer's are; without one the directory is only held.
    """

    encoded = _private_state(
        "read",
        "content_b64",
        directory=directory,
        name=name,
        private_root=private_root,
        output_limit=(maximum_bytes + 2) // 3 * 4 + _PRIVATE_STATE_ANSWER_OVERHEAD,
        maximum_bytes=maximum_bytes,
    )
    if encoded is None:
        return None
    if not isinstance(encoded, str):
        raise NativePolicySnapshotError("native_windows_private_state_invalid")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise NativePolicySnapshotError("native_windows_private_state_invalid") from error
    if not content or len(content) > maximum_bytes:
        raise NativePolicySnapshotError("native_windows_private_state_invalid")
    return content


def _windows_read_snapshot_bytes(
    path: Path,
    *,
    maximum_bytes: int = POLICY_SNAPSHOT_MAX_BYTES,
) -> bytes | None:
    """Read one owner-private state file while its directory is held."""

    return _windows_read_private_file(path.parent, path.name, maximum_bytes=maximum_bytes)


def _windows_write_private_file_atomic(
    *,
    directory: Path,
    name: str,
    payload: bytes,
    maximum_bytes: int,
    private_root: Path | None = None,
) -> None:
    """Replace one owner-private file so readers see old or new content, never a partial one.

    The directories from `private_root` (`directory` itself by default) down
    are created or repaired first.
    """

    if not payload or len(payload) > maximum_bytes:
        raise NativePolicySnapshotError("native_policy_windows_write_too_large")
    _private_state(
        "write",
        "written",
        directory=directory,
        name=name,
        private_root=private_root,
        maximum_bytes=maximum_bytes,
        content_b64=base64.b64encode(payload).decode("ascii"),
    )


def _windows_delete_private_child(
    *,
    directory: Path,
    name: str,
    private_root: Path | None = None,
) -> bool:
    """Delete one owner-private file through its verified handle; whether it existed."""

    return (
        _private_state(
            "delete",
            "deleted",
            directory=directory,
            name=name,
            private_root=private_root,
        )
        is True
    )


__all__ = [
    "_windows_delete_private_child",
    "_windows_read_private_file",
    "_windows_read_snapshot_bytes",
    "_windows_write_private_file_atomic",
]
