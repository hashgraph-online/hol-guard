"""Unlisted CLI observation and grants: one resident call records and decides, Python presents."""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Mapping
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
# A sandbox-bound action an allowed grant widens rather than lifts.
ALLOW_CONTAINED_WITH_GRANT = "allow-contained-with-grant"
_CONTAINED_FROM = frozenset({"sandbox-required", "review"})
_CONTAINED_ROUTE_FIELDS = frozenset({"decision", "minimum_action", "policy_action", "reason_code", "reason"})
_CONTAINED_GRANT_FIELDS = frozenset({"cli_id", "identity_hash", "name", "capabilities"})
_GRANT_CAPABILITIES = ("loopback-network", "state-dir-read", "state-dir-write")
_PAYLOAD_FIELDS = frozenset({"action", "connector", "contained_grant", "contained_route"})


@dataclass(frozen=True, slots=True)
class SetupConnector:
    """A local CLI this device has no allow or block decision for."""

    cli_id: str
    identity_hash: str
    name: str
    surface: str
    queue_group_id: str


@dataclass(frozen=True, slots=True)
class ContainedGrant:
    """The allowed grant a sandbox-bound command runs widened by."""

    cli_id: str
    identity_hash: str
    name: str
    capabilities: tuple[str, ...]

    def prepare_input(self) -> dict[str, object]:
        """The ``grant`` field of ``prepare_workspace_contained``."""
        return {"identity_hash": self.identity_hash, "name": self.name, "capabilities": list(self.capabilities)}


@dataclass(frozen=True, slots=True)
class _Reply:
    action: str
    connector: SetupConnector | None
    contained_grant: ContainedGrant | None
    contained_route: Mapping[str, str] | None = None


def local_cli_grant_action(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
    reason_code: str | None = None,
    path: str | None = None,
) -> GuardAction:
    """Record the CLI the command launches and refine the action with its grant."""

    if command is None:
        return current_action
    action = native_local_cli_hook(
        store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
        grant_allowed=grant_allowed,
        reason_code=reason_code,
        path=path,
    )
    if action is not None:
        return action
    return unverified_local_cli_action(store, current_action) if grant_allowed else current_action


def observe_unlisted_cli(
    *, store: GuardStore, command: str, cwd: Path, home_dir: Path | None, path: str | None = None
) -> None:
    """Record the CLIs a command launches without consulting any grant."""

    native_local_cli_hook(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action="allow", grant_allowed=False, path=path
    )


def native_local_cli_hook(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
    reason_code: str | None = None,
    path: str | None = None,
) -> GuardAction | None:
    """Return the resident's action, or ``None`` without a bound answer; a store failure raises.

    A grant that only widens the sandbox keeps the action here: callers that
    run the command contained ask ``local_cli_contained_grant`` instead.
    """

    reply = _native_local_cli_hook_reply(
        store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
        grant_allowed=grant_allowed,
        reason_code=reason_code,
        path=path,
    )
    if reply is None:
        return None
    return current_action if reply.action == ALLOW_CONTAINED_WITH_GRANT else cast(GuardAction, reply.action)


def local_cli_contained_grant(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    reason_code: str | None,
    path: str | None = None,
) -> tuple[str, ContainedGrant | None, Mapping[str, str] | None] | None:
    """The refined action of a sandbox-bound command, the grant that widens it, and its route.

    ``None`` is no bound answer. ``block`` means this device blocked the CLI.
    """

    reply = _native_local_cli_hook_reply(
        store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
        grant_allowed=True,
        reason_code=reason_code,
        path=path,
    )
    return None if reply is None else (reply.action, reply.contained_grant, reply.contained_route)


def local_cli_setup_connector(
    *, store: GuardStore, command: str, cwd: Path, home_dir: Path | None, path: str | None = None
) -> SetupConnector | None:
    """The connector a command review waits on, when Guard was never set up for it on this device."""

    reply = _native_local_cli_hook_reply(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action="review", grant_allowed=True, path=path
    )
    if reply is None or reply.action != "review":
        return None
    return reply.connector


def _native_local_cli_hook_reply(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
    reason_code: str | None = None,
    path: str | None = None,
) -> _Reply | None:
    """Ask the resident about the CLI ``command`` launches.

    ``path`` is the ``PATH`` the agent runs the command with. A daemon started by
    the OS has its own short ``PATH``, so without it a CLI the agent finds in
    ``~/.local/bin`` would resolve to nothing here and miss its grant.
    """

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
        "env": _launch_env(path),
        "current_action": current_action,
        "grant_allowed": grant_allowed,
    }
    # Rust leaves an absent reason out of the digest material.
    if reason_code is not None:
        request["current_reason_code"] = reason_code
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
    if status != "ok" or code != "ok" or not isinstance(payload, dict):
        return None
    if "action" not in payload or not set(payload) <= _PAYLOAD_FIELDS:
        return None
    action = payload["action"]
    if not isinstance(action, str):
        return None
    if action == ALLOW_CONTAINED_WITH_GRANT:
        # Only a sandbox-bound action is widened, and only by a well-formed grant.
        grant = _contained_grant(payload.get("contained_grant"))
        route = _contained_route(payload.get("contained_route"))
        if current_action not in _CONTAINED_FROM or grant is None or route is None or "connector" in payload:
            return None
        return _Reply(action, None, grant, route)
    # Only a grant can change the action, and only to allow, block or review.
    if (
        "contained_grant" in payload
        or "contained_route" in payload
        or (action != current_action and action not in _GRANT_ACTIONS)
    ):
        return None
    connector = _setup_connector(payload.get("connector")) if action == "review" else None
    return _Reply(action, connector, None)


def _launch_env(path: str | None) -> dict[str, str]:
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = path
    return env


def _contained_route(value: object) -> Mapping[str, str] | None:
    """The review fields the resident routes a granted outside-roots command to.

    Every field is the resident's; this only refuses an answer that is not the
    shape a route takes, so a malformed reply keeps the review it was holding.
    """

    if not isinstance(value, dict) or set(value) != _CONTAINED_ROUTE_FIELDS:
        return None
    fields = cast(dict[str, object], value)
    if not all(isinstance(item, str) and item for item in fields.values()):
        return None
    return {key: cast(str, item) for key, item in fields.items()}


def _contained_grant(value: object) -> ContainedGrant | None:
    if not isinstance(value, dict) or set(value) != _CONTAINED_GRANT_FIELDS:
        return None
    fields = cast(dict[str, object], value)
    cli_id, identity_hash, name, capabilities = (
        fields["cli_id"],
        fields["identity_hash"],
        fields["name"],
        fields["capabilities"],
    )
    if not (isinstance(cli_id, str) and cli_id and isinstance(name, str) and name):
        return None
    if not isinstance(identity_hash, str) or len(identity_hash) != 64 or set(identity_hash) - set("0123456789abcdef"):
        return None
    if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
        return None
    known = [item for item in _GRANT_CAPABILITIES if item in capabilities]
    if capabilities != known:
        # Unknown, repeated or out-of-order names are not a grant Rust would send.
        return None
    return ContainedGrant(cli_id, identity_hash, name, tuple(known))


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
