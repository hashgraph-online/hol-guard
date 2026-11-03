"""Read this computer's saved pairing without changing anything.

`hol-guard cloud-actions status --offline` is admitted as a read, so it must
not open the Guard store: opening it can migrate the schema, fix file
permissions or repair saved credentials. This reads the two saved records it
needs straight from `guard.db` in SQLite's read-only mode and never touches
the secret store.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .cloud_actions_access import CloudActionsPairing
from .connect_cloud_actions import (
    CLOUD_ACTIONS_CONNECT_STATE_PREFIX,
    CloudActionsConnectReport,
    parse_cloud_actions_connect_report,
)
from .oauth_client import resolve_guard_oauth_client_config

_PAIRING_STATE_KEY = "oauth_local_credentials"


def _saved_payload(connection: sqlite3.Connection, state_key: str) -> dict[str, object] | None:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (state_key,)).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def read_saved_pairing(guard_home: Path) -> tuple[CloudActionsPairing, CloudActionsConnectReport | None] | None:
    """The saved pairing and Cloud actions report, or None when none is saved."""

    database = guard_home / "guard.db"
    if not database.is_file():
        return None
    try:
        with closing(sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=1.0)) as connection:
            pairing = _saved_payload(connection, _PAIRING_STATE_KEY)
            grant_id = pairing.get("grant_id") if pairing is not None else None
            stored = (
                _saved_payload(connection, f"{CLOUD_ACTIONS_CONNECT_STATE_PREFIX}{grant_id}")
                if isinstance(grant_id, str) and grant_id
                else None
            )
    except sqlite3.Error:
        return None
    if pairing is None:
        return None
    issuer, client_id = pairing.get("issuer"), pairing.get("client_id")
    if not isinstance(issuer, str) or not issuer or not isinstance(client_id, str) or not client_id:
        return None
    try:
        origin = resolve_guard_oauth_client_config(issuer).issuer
    except ValueError:
        return None
    workspace_id = pairing.get("workspace_id")
    report = parse_cloud_actions_connect_report({"guard_cloud_actions": stored}) if stored is not None else None
    return (
        CloudActionsPairing(
            origin=origin,
            workspace_id=workspace_id.lower() if isinstance(workspace_id, str) and workspace_id else None,
        ),
        report,
    )


__all__ = ["read_saved_pairing"]
