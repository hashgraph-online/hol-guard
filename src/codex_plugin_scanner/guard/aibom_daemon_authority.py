"""Private daemon attempt capture and conditional unavailable-state reporting.

Callers retain inventory admission. Observations cannot authorize inventory
transport, freshness, or a successful result without an ordinary operation.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .adapters.base import HarnessContext
from .aibom_operation_authority import (
    _CONTEXT_ADOPTED_KEY,
    _CONTEXT_AUTHORITY_KEY,
    _RESULT_BINDINGS_KEY,
    INVENTORY_CONTEXT_KEY,
    AibomOperation,
    _capture_selection,
    _digest,
    _installation,
    _json,
    _read_authority,
    _requested_context,
    _result_bindings,
    _root,
    _write,
    commit_aibom_results,
)
from .oauth_connection_authority import (
    OAuthConnectionSnapshot,
    connection_epoch_key,
    connection_identity,
)

if TYPE_CHECKING:
    from .store import GuardStore


def _row_digest(connection: sqlite3.Connection, keys: tuple[str, ...]) -> str:
    rows: list[object] = []
    for key in keys:
        row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
        # SQLite returns builtins here. Preserve absence and the stored type;
        # malformed values are observations, never interpreted as authority.
        rows.append([key, None if row is None else [type(row[0]).__name__, repr(row[0])]])
    return _digest(_json(rows))


def _selection_digest(connection: sqlite3.Connection) -> str:
    selected = _read_authority(connection)
    if selected is not None and selected.state != "invalid":
        return _digest(_json([selected.generation, selected.state, selected.projection]))
    return _row_digest(
        connection,
        (INVENTORY_CONTEXT_KEY, _CONTEXT_AUTHORITY_KEY, _CONTEXT_ADOPTED_KEY),
    )


def _source_digest(connection: sqlite3.Connection, credential_key: str) -> str:
    return _row_digest(connection, (credential_key, connection_epoch_key(credential_key)))


def _workspace(source: OAuthConnectionSnapshot | None) -> str | None:
    value = source.credentials().get("workspace_id") if source is not None else None
    return value if isinstance(value, str) and value.strip() else None


def _daemon_context(
    store: GuardStore,
    *,
    source: OAuthConnectionSnapshot | None,
    projection: str | None,
    explicit: HarnessContext | None,
    explicit_source: OAuthConnectionSnapshot | None,
    fallback_home: Path,
) -> HarnessContext:
    workspace = _workspace(source)
    selected = json.loads(projection) if projection is not None else None
    selected = (
        selected if isinstance(selected, dict) and selected.get("workspace_id") == workspace and workspace else {}
    )
    explicit_bound = (
        source is not None
        and explicit_source is not None
        and explicit_source.same_authority(source)
        and explicit is not None
        and explicit.workspace_dir is not None
    )
    if explicit_bound:
        assert explicit is not None
        return explicit
    home = selected.get("home_dir")
    local_workspace = selected.get("workspace_dir")
    return HarnessContext(
        home_dir=Path(home) if isinstance(home, str) else fallback_home,
        workspace_dir=Path(local_workspace) if isinstance(local_workspace, str) else None,
        guard_home=store.guard_home,
    )


@dataclass(frozen=True, slots=True, repr=False)
class AibomDaemonAttempt:
    operation: AibomOperation | None
    _source: OAuthConnectionSnapshot | None
    _credential_key: str
    _store_scope: str
    _unavailable_source_digest: str
    _selection_digest: str
    _requested_json: str
    _bind_installation: bool
    _installation_id: str | None

    def context(self) -> HarnessContext:
        value = json.loads(self._requested_json)
        return HarnessContext(
            home_dir=Path(value["home_dir"]),
            workspace_dir=Path(value["workspace_dir"]) if value["workspace_dir"] is not None else None,
            guard_home=Path(value["guard_home"]),
            executable_overrides=value["executable_overrides"],
            home_override_explicit=value["home_override_explicit"],
            workspace_override_explicit=value["workspace_override_explicit"],
        )


def capture_aibom_daemon_attempt(
    store: GuardStore,
    *,
    now: str,
    explicit: HarnessContext | None,
    explicit_source: OAuthConnectionSnapshot | None,
    fallback_home: Path,
    bind_installation: bool,
) -> AibomDaemonAttempt:
    fallback_home = Path(_root(fallback_home))
    # Snapshot explicitly requested mutable overrides before taking the lock.
    if explicit is not None:
        explicit_json = _requested_context(explicit, store)
        values = json.loads(explicit_json)
        explicit = HarnessContext(
            home_dir=Path(values["home_dir"]),
            workspace_dir=Path(values["workspace_dir"]) if values["workspace_dir"] is not None else None,
            guard_home=Path(values["guard_home"]),
            executable_overrides=values["executable_overrides"],
            home_override_explicit=values["home_override_explicit"],
            workspace_override_explicit=values["workspace_override_explicit"],
        )
    with store.hold_oauth_credential_lock():
        source = store._capture_oauth_connection_unlocked(allow_primary=True, allow_recoverable=True)
        workspace = _workspace(source)
        if workspace is not None and bind_installation:
            store.get_or_create_installation_id()
        with store._connect() as connection:
            connection.execute("begin immediate")
            selected = _capture_selection(connection, now)
            context = _daemon_context(
                store,
                source=source,
                projection=selected.projection if selected is not None else None,
                explicit=explicit,
                explicit_source=explicit_source,
                fallback_home=fallback_home,
            )
            requested = _requested_context(context, store)
            installation = _installation(connection) if bind_installation else None
            operation = (
                AibomOperation(source, requested, selected, installation)
                if source is not None
                and workspace is not None
                and selected is not None
                and (not bind_installation or installation is not None)
                else None
            )
            return AibomDaemonAttempt(
                operation,
                source,
                store._oauth_local_credentials_state_key,
                str(store.path.resolve()),
                _source_digest(connection, store._oauth_local_credentials_state_key),
                _selection_digest(connection),
                requested,
                bind_installation,
                installation,
            )


def commit_aibom_daemon_result(
    store: GuardStore,
    attempt: AibomDaemonAttempt,
    payload: dict[str, object],
    *,
    now: str,
) -> bool:
    copied = json.loads(_json(payload))
    if not isinstance(copied, dict):
        raise ValueError("The inventory daemon result must be an object.")
    if attempt.operation is not None:
        return commit_aibom_results(store, attempt.operation, {"aibom_inventory_daemon": copied}, now=now)
    if ("synced" in copied and copied["synced"] is not False) or copied.get("status") not in {
        "missing_workspace_context",
        "not_configured",
        "auth_expired",
        "error",
    }:
        raise ValueError("Unavailable inventory authority cannot report successful work.")
    if (
        attempt._store_scope != str(store.path.resolve())
        or attempt._credential_key != store._oauth_local_credentials_state_key
    ):
        return False
    with store.hold_oauth_credential_lock():
        current = store._capture_oauth_connection_unlocked(allow_primary=True, allow_recoverable=True)
        if attempt._source is None:
            if current is not None:
                return False
        elif current is None or not attempt._source.same_authority(current):
            return False
        with store._connect() as connection:
            connection.execute("begin immediate")
            if (
                (
                    attempt._source is None
                    and _source_digest(connection, attempt._credential_key) != attempt._unavailable_source_digest
                )
                or _selection_digest(connection) != attempt._selection_digest
                or (attempt._bind_installation and _installation(connection) != attempt._installation_id)
            ):
                return False
            scope = _digest(
                _json(
                    {
                        "observation": True,
                        "store": attempt._store_scope,
                        "source": attempt._credential_key,
                        "source_state": attempt._unavailable_source_digest
                        if attempt._source is None
                        else [
                            attempt._source.epoch,
                            connection_identity(attempt._source.credentials()),
                        ],
                        "selection": attempt._selection_digest,
                        "requested": attempt._requested_json,
                        "installation": attempt._installation_id,
                    }
                )
            )
            bindings = _result_bindings(connection)
            bindings["aibom_inventory_daemon"] = {
                "scope": scope,
                "digest": _digest(_json(copied)),
            }
            _write(connection, "aibom_inventory_daemon", copied, now)
            _write(
                connection,
                _RESULT_BINDINGS_KEY,
                {"version": 1, "results": bindings},
                now,
            )
            return True
