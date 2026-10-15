"""Guard connect-state schema and response shape. The native store owns the state."""

from __future__ import annotations

import json
from collections.abc import Mapping

CONNECT_STATE_VERSION = "guard-connect-state.v1"


def connect_request_schema_statement() -> str:
    return """
        create table if not exists guard_connect_requests (
          request_id text primary key,
          sync_url text not null,
          allowed_origin text not null,
          pairing_secret_hash text not null,
          status text not null,
          created_at text not null,
          expires_at text not null,
          completed_at text
        )
        """


def connect_state_schema_statement() -> str:
    return """
        create table if not exists guard_connect_states (
          request_id text primary key,
          sync_url text not null,
          allowed_origin text not null,
          status text not null,
          milestone text not null,
          reason text,
          created_at text not null,
          updated_at text not null,
          expires_at text not null,
          completed_at text,
          proof_json text not null default '{}'
        )
        """


def build_connect_state_response(
    payload: Mapping[str, object],
    *,
    poll_after_ms: int | None = None,
) -> dict[str, object]:
    response: dict[str, object] = dict(payload)
    response["version"] = CONNECT_STATE_VERSION
    response["poll_after_ms"] = poll_after_ms if poll_after_ms is not None else _resolve_poll_after_ms(response)
    response["proof"] = _coerce_proof(response.get("proof"))
    return response


def _coerce_proof(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return dict(parsed)
    return {}


def _resolve_poll_after_ms(payload: dict[str, object]) -> int:
    if str(payload.get("status")) == "waiting":
        return 1500
    return 0
