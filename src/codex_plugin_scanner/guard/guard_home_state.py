"""Durable state detection for guard-home migration."""

from __future__ import annotations

import json
import sqlite3


def database_has_custom_extension_state(
    connection: sqlite3.Connection,
    tables: set[str],
) -> bool:
    if "extension_control_authority_snapshot" not in tables:
        return False
    snapshot = connection.execute(
        "select layers_json from extension_control_authority_snapshot where singleton = 1"
    ).fetchone()
    if snapshot is None:
        return False
    try:
        layers = json.loads(str(snapshot[0]))
    except json.JSONDecodeError:
        return True
    return isinstance(layers, list) and bool(layers)
