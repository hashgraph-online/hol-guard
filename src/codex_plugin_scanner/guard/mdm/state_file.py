"""Private files in the machine state root, read and written by the native runtime.

The runtime opens without following links, trusts only a private regular file
of the state owner that held still while read, and writes through a synced
private temporary file. Without it every read and write fails closed.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Literal, cast

HEALTH_LEASE_STATE_FEATURE = "native-health-lease-state-v1"
MACHINE_STATE_FILES_FEATURE = "native-machine-state-files-v1"
STATE_FILE_COMMAND = "health-lease-state"
STATE_FILE_SCHEMA = "health-lease-state.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_UNAVAILABLE: dict[str, str] = {
    "outbox": "health_lease_state_native_unavailable",
    "ack": "health_lease_state_native_unavailable",
    "continuity": "installation_identity_native_unavailable",
    "device_key": "device_key_native_unavailable",
}
_ERROR_TYPES: dict[str, type[OSError]] = {
    "permission": PermissionError,
    "exists": FileExistsError,
    "os": OSError,
}
StateKind = Literal["outbox", "ack", "continuity", "device_key"]


def _state_owner_uid() -> int:
    """The only owner a Unix state file is trusted from; Windows skips the check."""

    return 0


def native_state(op: str, kind: StateKind, state_root: Path, content: bytes | None = None) -> dict[str, object]:
    """Ask the native runtime to read, write or remove one state file."""

    from ..native_runtime import _run_native_process, native_runtime_status

    unavailable = _UNAVAILABLE[kind]
    feature = HEALTH_LEASE_STATE_FEATURE if kind in {"outbox", "ack"} else MACHINE_STATE_FILES_FEATURE
    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        raise OSError(unavailable)
    request: dict[str, object] = {
        "schema": STATE_FILE_SCHEMA,
        "op": op,
        "kind": kind,
        "state_root": str(state_root),
        "owner_uid": _state_owner_uid(),
    }
    if content is not None:
        request["content"] = base64.b64encode(content).decode("ascii")
    output = _run_native_process(
        status.identity.path,
        (STATE_FILE_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True),
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    try:
        response = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        response = None
    if not isinstance(response, dict):
        raise OSError(unavailable)
    answer = cast(dict[str, object], response)
    if answer.get("ok") is True:
        return answer
    reason_code = answer.get("reason_code")
    error_type = _ERROR_TYPES.get(str(answer.get("error_class")))
    if error_type is None or not isinstance(reason_code, str):
        raise OSError(unavailable)
    raise error_type(reason_code)


def read_state(state_root: Path, kind: StateKind) -> bytes | None:
    """The file's bytes, or `None` when it does not exist."""

    content = native_state("read", kind, state_root).get("content")
    if content is None:
        return None
    if not isinstance(content, str):
        raise OSError(_UNAVAILABLE[kind])
    return base64.b64decode(content, validate=True)


def replace_state(state_root: Path, kind: StateKind, content: bytes) -> None:
    _ = native_state("replace", kind, state_root, content)
