"""Unlisted CLI observation and grants: one resident call records and decides, Python presents."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from . import store_storage_gate
from .models import GuardAction
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_guard_store import _raise_for_code
from .sqlite_tuning import sqlite_connect_timeout_seconds, sqlite_operation_deadline_monotonic

if TYPE_CHECKING:
    from .store import GuardStore

LOCAL_CLI_HOOK_FEATURE = "local-cli-hook-v1"
_RESULT_SCHEMA = "guard-local-cli-hook-result.v1"
_STORE_CODE_PREFIX = "native_guard_store_"
_TIMEOUT_SECONDS = 10.0
# The request carries the caller environment, as the identity call it replaces did.
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_GRANT_ACTIONS = frozenset({"allow", "block", "review"})
_CONNECTOR_FIELDS = frozenset({"cli_id", "identity_hash", "name", "surface", "queue_group_id"})
_CONNECTOR_SURFACES = frozenset({"cli", "package-scripts"})


@dataclass(frozen=True, slots=True)
class SetupConnector:
    """A local CLI this device has no allow or block decision for."""

    cli_id: str
    identity_hash: str
    name: str
    surface: str
    queue_group_id: str


def local_cli_grant_action(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
) -> GuardAction:
    """Record the CLI the command launches and refine the action with its grant."""

    if command is None:
        return current_action
    action = native_local_cli_hook(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action=current_action, grant_allowed=grant_allowed
    )
    if action is not None:
        return action
    return unverified_local_cli_action(store, current_action) if grant_allowed else current_action


def observe_unlisted_cli(*, store: GuardStore, command: str, cwd: Path, home_dir: Path | None) -> None:
    """Record the CLIs a command launches without consulting any grant."""

    native_local_cli_hook(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action="allow", grant_allowed=False
    )


def native_local_cli_hook(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
) -> GuardAction | None:
    """Return the resident's action, or ``None`` without a bound answer; a store failure raises."""

    reply = _native_local_cli_hook_reply(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action=current_action, grant_allowed=grant_allowed
    )
    return None if reply is None else reply[0]


def local_cli_setup_connector(
    *, store: GuardStore, command: str, cwd: Path, home_dir: Path | None
) -> SetupConnector | None:
    """The connector a command review waits on, when Guard was never set up for it on this device."""

    reply = _native_local_cli_hook_reply(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action="review", grant_allowed=True
    )
    if reply is None or reply[0] != "review":
        return None
    return reply[1]


def _native_local_cli_hook_reply(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
) -> tuple[GuardAction, SetupConnector | None] | None:

    # A caller operation clock bounds the call, as it bounds a store call.
    operation_deadline = sqlite_operation_deadline_monotonic()
    timeout_seconds = _TIMEOUT_SECONDS
    if operation_deadline is not None:
        timeout_seconds = min(timeout_seconds, operation_deadline - time.monotonic())
        if timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
    request: dict[str, object] = {
        "schema": "guard-local-cli-hook-request.v1",
        "request_id": f"local-cli-hook-{uuid4().hex}",
        "store_path": str(store.path),
        "guard_home": str(store.guard_home),
        "source": store.guard_source,
        "busy_timeout_ms": max(1, int(sqlite_connect_timeout_seconds() * 1000)),
        "command": command,
        "cwd": str(cwd),
        "home_dir": None if home_dir is None else str(home_dir),
        "user_home": str(Path.home()),
        "env": dict(os.environ),
        "current_action": current_action,
        "grant_allowed": grant_allowed,
    }
    digest = "sha256:" + _canonical_request_sha256(request)
    if not ensure_resident_prerequisite(store.guard_home):
        return None
    with store_storage_gate.hold_storage_gate(store.guard_home, exclusive=False):
        response = _resident_request(
            operation="local_cli_hook",
            request=request,
            guard_home=store.guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=LOCAL_CLI_HOOK_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
        )
    # The resident may have written the store, as a store call would.
    store._repair_store_permissions()
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return None
    status, code, payload = response.get("status"), response.get("code"), response.get("payload")
    if status == "error" and isinstance(code, str) and code.startswith(_STORE_CODE_PREFIX):
        _raise_store_failure(store, code)
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or set(payload) - {"connector"} != {"action"}:
        return None
    action = payload["action"]
    if not isinstance(action, str):
        return None
    # Only a grant can change the action, and only to allow, block or review.
    if action != current_action and action not in _GRANT_ACTIONS:
        return None
    connector = _setup_connector(payload.get("connector")) if action == "review" else None
    return cast(GuardAction, action), connector


def _setup_connector(value: object) -> SetupConnector | None:
    if not isinstance(value, dict) or set(value) != _CONNECTOR_FIELDS:
        return None
    fields = cast(dict[str, object], value)
    if not all(isinstance(fields[key], str) and fields[key] for key in _CONNECTOR_FIELDS):
        return None
    connector = SetupConnector(**cast(dict[str, str], fields))
    if connector.surface not in _CONNECTOR_SURFACES or not connector.queue_group_id.startswith(
        f"connector:{connector.identity_hash}:"
    ):
        return None
    return connector


def _raise_store_failure(store: GuardStore, code: str) -> None:
    """Raise the store failure as a store call would, recovering the store first."""

    try:
        _raise_for_code(code, None)
    except sqlite3.DatabaseError as failure:
        # The step already ran against the failed store: recover it for the
        # next call, then surface this failure.
        try:
            store._recover_fatal_sqlite_store(failure)
        except Exception as recovery_error:
            raise recovery_error from failure
        raise


def unverified_local_cli_action(store: object, current_action: GuardAction) -> GuardAction:
    """Hold an otherwise allowed command for review while a block rule might apply."""

    if current_action not in {"allow", "warn"}:
        return current_action
    probe = getattr(store, "has_local_cli_block_rules", None)
    try:
        has_blocks = bool(probe()) if callable(probe) else False
    except Exception:
        has_blocks = True
    return "review" if has_blocks else current_action
