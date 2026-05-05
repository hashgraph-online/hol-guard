"""Guard Cloud agent identity hints for local harness adapters."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .base import HarnessContext

_SERVICE_RUNTIME_PROFILE_STATE_KEY = "service_runtime_profile"
_PROFILE_FIELDS = (
    "runtime",
    "label",
    "workspace",
    "surface",
    "client_name",
    "client_title",
    "client_version",
    "agent_id",
    "principal_id",
)
_ENV_FIELDS = {
    "runtime": "RUNTIME",
    "label": "LABEL",
    "workspace": "WORKSPACE",
    "agent_id": "AGENT_ID",
    "principal_id": "PRINCIPAL_ID",
}


def cloud_agent_identity_hints(
    context: HarnessContext,
    *,
    runtime: str,
) -> dict[str, str] | None:
    payload = _read_service_runtime_profile(context.guard_home / "guard.db")
    if payload is None or _string_field(payload, "runtime") != runtime:
        return None
    hints = {field: value for field in _PROFILE_FIELDS if (value := _string_field(payload, field)) is not None}
    return hints if hints else None


def cloud_agent_identity_environment(
    identity: object,
    *,
    prefix: str,
) -> dict[str, str]:
    if not isinstance(identity, dict):
        return {}
    env: dict[str, str] = {}
    for field, suffix in _ENV_FIELDS.items():
        value = identity.get(field)
        if isinstance(value, str) and value:
            env[f"{prefix}_GUARD_CLOUD_{suffix}"] = value
    return env


def _read_service_runtime_profile(db_path: Path) -> dict[str, object] | None:
    if not db_path.exists():
        return None
    try:
        db_uri = f"{db_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(db_uri, uri=True)
        try:
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_SERVICE_RUNTIME_PROFILE_STATE_KEY,),
            ).fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return None
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _string_field(payload: dict[str, object], field: str) -> str | None:
    value = payload.get(field)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
