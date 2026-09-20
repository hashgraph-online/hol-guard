"""Private local authority for inventory selection and conditional results.

These records are local coordination state, never transport or report fields.
The caller retains inventory admission across capture, collection and transport.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .adapters.base import HarnessContext
from .oauth_connection_authority import OAuthConnectionSnapshot, connection_identity

if TYPE_CHECKING:
    from .store import GuardStore

INVENTORY_CONTEXT_KEY = "aibom_inventory_context"
_CONTEXT_AUTHORITY_KEY = "aibom_inventory_context_authority"
_CONTEXT_ADOPTED_KEY = "aibom_inventory_context_adopted"
_RESULT_BINDINGS_KEY = "aibom_inventory_result_bindings"
_PRIVATE_KEYS = frozenset({_CONTEXT_AUTHORITY_KEY, _CONTEXT_ADOPTED_KEY, _RESULT_BINDINGS_KEY})
_RESULT_KEYS = frozenset({"aibom_sync_summary", "aibom_guard_events_backoff", "aibom_inventory_daemon"})
_CONTEXT_FIELDS = frozenset({"home_dir", "workspace_dir", "workspace_id"})


def reject_private_inventory_key(state_key: str) -> None:
    if type(state_key) is not str:
        raise ValueError("State keys must be plain strings.")
    if state_key in _PRIVATE_KEYS:
        raise ValueError("Inventory authority state requires its dedicated mutation boundary.")


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory state field.")
        result[key] = value
    return result


def _non_json_constant(_value: str) -> None:
    raise ValueError("Non-JSON inventory state value.")


def _read(connection: sqlite3.Connection, key: str) -> tuple[bool, object]:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
    if row is None:
        return False, None
    try:
        return True, json.loads(str(row[0]), object_pairs_hook=_unique_object, parse_constant=_non_json_constant)
    except (TypeError, ValueError, RecursionError):
        return True, None


def _write(connection: sqlite3.Connection, key: str, payload: object, now: str) -> None:
    connection.execute(
        """
        insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
        on conflict(state_key) do update set payload_json = excluded.payload_json, updated_at = excluded.updated_at
        """,
        (key, _json(payload), now),
    )


def _root(value: str | Path) -> str:
    if not str(value).strip():
        raise ValueError("Inventory paths must not be empty.")
    return str(Path(value).expanduser().resolve(strict=False))


def _selection(present: bool, payload: object) -> tuple[str, str]:
    if not present:
        return "absent", "null"
    if not isinstance(payload, dict) or not payload or not set(payload).issubset(_CONTEXT_FIELDS):
        return "invalid", "null"
    projection: dict[str, str] = {}
    try:
        for key, value in payload.items():
            if not isinstance(value, str) or not value.strip():
                return "invalid", "null"
            projection[key] = value if key == "workspace_id" else _root(value)
    except (OSError, RuntimeError, ValueError):
        return "invalid", "null"
    return "selected", _json(projection)


@dataclass(frozen=True, slots=True, repr=False)
class _SelectionAuthority:
    generation: str
    state: str
    projection: str


def _read_authority(connection: sqlite3.Connection) -> _SelectionAuthority | None:
    marker_present, marker = _read(connection, _CONTEXT_ADOPTED_KEY)
    authority_present, authority = _read(connection, _CONTEXT_AUTHORITY_KEY)
    if not marker_present or not authority_present or type(marker) is not dict:
        return None
    if set(marker) != {"version"} or type(marker.get("version")) is not int or marker["version"] != 1:
        return None
    if not isinstance(authority, dict) or set(authority) != {"version", "generation", "state", "projection"}:
        return None
    generation = authority["generation"]
    if (
        type(authority["version"]) is not int
        or authority["version"] != 1
        or not isinstance(generation, str)
        or len(generation) != 32
        or any(char not in "0123456789abcdef" for char in generation)
    ):
        return None
    state, projection = _selection(*_read(connection, INVENTORY_CONTEXT_KEY))
    if authority["state"] != state or authority["projection"] != json.loads(projection):
        return None
    return _SelectionAuthority(generation, state, projection)


def _new_authority(connection: sqlite3.Connection, state: str, projection: str, now: str) -> _SelectionAuthority:
    authority = _SelectionAuthority(uuid.uuid4().hex, state, projection)
    _write(connection, _CONTEXT_ADOPTED_KEY, {"version": 1}, now)
    _write(
        connection,
        _CONTEXT_AUTHORITY_KEY,
        {"version": 1, "generation": authority.generation, "state": state, "projection": json.loads(projection)},
        now,
    )
    return authority


def record_inventory_context_mutation(
    connection: sqlite3.Connection, payload: Mapping[str, object] | Sequence[object] | None, now: str
) -> None:
    """Called in the credential-locked transaction immediately before the public row write/delete."""
    previous = _read_authority(connection)
    state, projection = _selection(payload is not None, payload)
    if previous is None or (previous.state, previous.projection) != (state, projection) or state == "invalid":
        _new_authority(connection, state, projection, now)


def _capture_selection(connection: sqlite3.Connection, now: str) -> _SelectionAuthority | None:
    marker_present, _ = _read(connection, _CONTEXT_ADOPTED_KEY)
    authority_present, _ = _read(connection, _CONTEXT_AUTHORITY_KEY)
    if not marker_present and not authority_present:
        state, projection = _selection(*_read(connection, INVENTORY_CONTEXT_KEY))
        if state == "invalid":
            return None
        # Genuine legacy adoption. Complete out-of-band erasure of both private
        # rows is indistinguishable from legacy and is outside this API contract.
        return _new_authority(connection, state, projection, now)
    authority = _read_authority(connection)
    return authority if authority is not None and authority.state != "invalid" else None


def _requested_context(context: HarnessContext, store: GuardStore) -> str:
    guard_home = _root(context.guard_home)
    if guard_home != _root(store.guard_home):
        raise ValueError("Inventory context belongs to a different local store.")
    overrides = dict(context.executable_overrides)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in overrides.items()):
        raise ValueError("Invalid inventory executable selection.")
    return _json(
        {
            "home_dir": _root(context.home_dir),
            "workspace_dir": _root(context.workspace_dir) if context.workspace_dir is not None else None,
            "guard_home": guard_home,
            "executable_overrides": overrides,
            "home_override_explicit": context.home_override_explicit,
            "workspace_override_explicit": context.workspace_override_explicit,
        }
    )


def _installation(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "select installation_id from guard_devices where device_key = ?", ("local-device",)
    ).fetchone()
    return str(row[0]) if row is not None and isinstance(row[0], str) and row[0] else None


@dataclass(frozen=True, slots=True, repr=False)
class AibomOperation:
    """Captured source and roots; no secret-bearing field has a representation."""

    connection: OAuthConnectionSnapshot
    _requested_json: str
    _selection: _SelectionAuthority
    installation_id: str | None

    @property
    def workspace_id(self) -> str:
        return cast(str, self.connection.credentials()["workspace_id"])

    def context(self) -> HarnessContext:
        payload = json.loads(self._requested_json)
        return HarnessContext(
            home_dir=Path(payload["home_dir"]),
            workspace_dir=Path(payload["workspace_dir"]) if payload["workspace_dir"] is not None else None,
            guard_home=Path(payload["guard_home"]),
            executable_overrides=payload["executable_overrides"],
            home_override_explicit=payload["home_override_explicit"],
            workspace_override_explicit=payload["workspace_override_explicit"],
        )


def capture_aibom_operation(
    store: GuardStore, context: HarnessContext, *, now: str, bind_installation: bool
) -> AibomOperation | None:
    requested = _requested_context(context, store)
    with store.hold_oauth_credential_lock():
        source = store._capture_oauth_connection_unlocked(allow_primary=True, allow_recoverable=True)
        if source is None:
            return None
        workspace = source.credentials().get("workspace_id")
        if not isinstance(workspace, str) or not workspace.strip():
            return None
        if bind_installation:
            # This initializer opens its own connection. Finish it before the
            # short atomic selection/identity transaction below.
            store.get_or_create_installation_id()
        with store._connect() as connection:
            connection.execute("begin immediate")
            selected = _capture_selection(connection, now)
            installation = _installation(connection) if bind_installation else None
            if selected is None or (bind_installation and installation is None):
                return None
            return AibomOperation(source, requested, selected, installation)


def _source_current(store: GuardStore, operation: AibomOperation) -> bool:
    current = store._capture_oauth_connection_unlocked(allow_recoverable=True)
    return current is not None and operation.connection.same_authority(current)


def _local_current(connection: sqlite3.Connection, operation: AibomOperation) -> bool:
    selected = _read_authority(connection)
    return selected == operation._selection and (
        operation.installation_id is None or operation.installation_id == _installation(connection)
    )


def _aibom_operation_is_current_unlocked(store: GuardStore, operation: AibomOperation) -> bool:
    """Require the caller's credential lock; finish source capture before the SQL fence."""
    if not _source_current(store, operation):
        return False
    with store._connect() as connection:
        connection.execute("begin immediate")
        return _local_current(connection, operation)


def aibom_operation_is_current(store: GuardStore, operation: AibomOperation) -> bool:
    with store.hold_oauth_credential_lock():
        return _aibom_operation_is_current_unlocked(store, operation)


def require_current_aibom_operation(store: GuardStore, operation: AibomOperation) -> None:
    if not aibom_operation_is_current(store, operation):
        raise RuntimeError("The inventory operation context changed.")


def _result_scope(operation: AibomOperation, key: str) -> str:
    source = operation.connection
    binding: dict[str, object] = {
        "source": source.credential_key,
        "epoch": source.epoch,
        "store": source.store_scope,
        "identity": connection_identity(source.credentials()),
    }
    if key != "aibom_guard_events_backoff":
        binding.update(
            requested=operation._requested_json,
            selection=operation._selection.generation,
            installation=operation.installation_id,
        )
    return _digest(_json(binding))


def _result_bindings(connection: sqlite3.Connection) -> dict[str, object]:
    _, payload = _read(connection, _RESULT_BINDINGS_KEY)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "results"}
        or type(payload["version"]) is not int
        or payload["version"] != 1
        or not isinstance(payload["results"], dict)
        or not set(payload["results"]).issubset(_RESULT_KEYS)
    ):
        return {}
    results = cast(dict[str, object], payload["results"])
    for binding in results.values():
        if not isinstance(binding, dict) or set(binding) != {"scope", "digest"}:
            return {}
        if any(
            not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in binding.values()
        ):
            return {}
    return results


def commit_aibom_results(
    store: GuardStore, operation: AibomOperation, results: Mapping[str, Mapping[str, object]], *, now: str
) -> bool:
    """Atomically commit only results belonging to the still-current operation."""
    # Copy once, then validate that exact snapshot. A live Mapping can change
    # its keys between separate validation and iteration passes.
    items = list(results.items())
    if any(type(key) is not str for key, _ in items):
        raise ValueError("Inventory result state keys must be plain strings.")
    copied = {key: json.loads(_json(value)) for key, value in items}
    if not copied or not set(copied).issubset(_RESULT_KEYS):
        raise ValueError("Invalid inventory result state key.")
    if any(not isinstance(payload, dict) for payload in copied.values()):
        raise ValueError("Inventory result payloads must be objects.")
    with store.hold_oauth_credential_lock():
        if not _source_current(store, operation):
            return False
        with store._connect() as connection:
            connection.execute("begin immediate")
            if not _local_current(connection, operation):
                return False
            bindings = _result_bindings(connection)
            for key, payload in copied.items():
                bindings[key] = {"scope": _result_scope(operation, key), "digest": _digest(_json(payload))}
                _write(connection, key, payload, now)
            _write(connection, _RESULT_BINDINGS_KEY, {"version": 1, "results": bindings}, now)
            return True


def read_aibom_result(store: GuardStore, operation: AibomOperation, key: str) -> dict[str, object] | None:
    """Return a current, exact bound result; legacy/unbound summaries prove no freshness."""
    if type(key) is not str or key not in _RESULT_KEYS:
        raise ValueError("Invalid inventory result state key.")
    with store.hold_oauth_credential_lock():
        if not _source_current(store, operation):
            return None
        with store._connect() as connection:
            connection.execute("begin immediate")
            if not _local_current(connection, operation):
                return None
            present, payload = _read(connection, key)
            binding = _result_bindings(connection).get(key)
            if not present or not isinstance(payload, dict) or not isinstance(binding, dict):
                return None
            if binding != {"scope": _result_scope(operation, key), "digest": _digest(_json(payload))}:
                return None
            return cast(dict[str, object], payload)
