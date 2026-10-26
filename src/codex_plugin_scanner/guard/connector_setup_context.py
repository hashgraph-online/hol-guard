"""Connector setup context: one resident call records it and answers with what is already allowed."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, cast
from uuid import uuid4

from . import store_storage_gate
from .local_cli_hook import _raise_store_failure
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .redaction import redact_sensitive_text, redact_text
from .sqlite_tuning import sqlite_connect_timeout_seconds, sqlite_operation_deadline_monotonic
from .store_local_cli_context import MAX_LABEL_CHARS, MAX_SUMMARY_CHARS, validated_first_blocked_cause

if TYPE_CHECKING:
    from .store import GuardStore

CONNECTOR_SETUP_CONTEXT_FEATURE: Final = "connector-setup-context-v1"
_REQUEST_SCHEMA: Final = "guard-connector-setup-context-request.v1"
_RESULT_SCHEMA: Final = "guard-connector-setup-context-result.v1"
_STORE_CODE_PREFIX: Final = "native_guard_store_"
_TIMEOUT_SECONDS: Final = 5.0
_RESOLUTION_STATES: Final = frozenset({"unset", "allowed", "blocked"})
_URL: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s`'\"<>]+")
_MAX_RAW_CHARS: Final = 4096


@dataclass(frozen=True, slots=True)
class AllowedAlternatives:
    """What this device already allows in the connector's namespace."""

    tools: tuple[str, ...] = ()
    subcommands: tuple[str, ...] = ()
    catalog_contributions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConnectorSetupAdvice:
    """The resident's answer: the setup state and the choice it would recommend.

    ``resolution_state`` is derived from the grant on every call, never stored.
    The recommendation is advice only; nothing on this path writes a grant or a
    capability, and nothing in it is preselected.
    """

    cli_id: str
    identity_hash: str
    surface: str
    first_blocked_cause: str | None
    resolution_state: str
    allowed_alternatives: AllowedAlternatives = field(default_factory=AllowedAlternatives)
    card_recommendation: Mapping[str, object] = field(default_factory=dict)


def scrub_connector_context_text(value: object, *, limit: int) -> str | None:
    """Keep review wording that is safe to store: no URL credential, query or secret.

    The resident scrubs again before it writes; this keeps the request itself
    free of what must never be kept.
    """

    if not isinstance(value, str):
        return None
    text = _URL.sub(_url_identity, value[:_MAX_RAW_CHARS])
    text = redact_sensitive_text(redact_text(text).text)
    text = " ".join("".join(" " if not char.isprintable() else char for char in text).split())
    return text[:limit].strip() or None


def record_connector_setup_context(
    store: GuardStore,
    *,
    cli_id: str,
    identity_hash: str,
    first_blocked_cause: str | None = None,
    trigger_summary: str | None = None,
    why_now: str | None = None,
    harness: str | None = None,
    workspace_label: str | None = None,
    budget_seconds: float | None = None,
) -> ConnectorSetupAdvice | None:
    """Record a connector's setup context and return the resident's advice, or ``None`` without one.

    ``budget_seconds`` is what the caller can still spend: the wait never
    exceeds it, and no budget left means no call. A store failure raises, as a
    store call would. The call never writes a grant or a capability.
    """

    cause = validated_first_blocked_cause(first_blocked_cause)
    timeout_seconds = _TIMEOUT_SECONDS if budget_seconds is None else min(_TIMEOUT_SECONDS, budget_seconds)
    if timeout_seconds <= 0:
        return None
    operation_deadline = sqlite_operation_deadline_monotonic()
    if operation_deadline is not None:
        timeout_seconds = min(timeout_seconds, operation_deadline - time.monotonic())
        if timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"connector-setup-context-{uuid4().hex}",
        "store_path": str(store.path),
        "guard_home": str(store.guard_home),
        "source": store.guard_source,
        "busy_timeout_ms": max(1, int(sqlite_connect_timeout_seconds() * 1000)),
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "first_blocked_cause": cause,
        "trigger_summary": scrub_connector_context_text(trigger_summary, limit=MAX_SUMMARY_CHARS),
        "why_now": scrub_connector_context_text(why_now, limit=MAX_SUMMARY_CHARS),
        "harness": scrub_connector_context_text(harness, limit=MAX_LABEL_CHARS),
        "workspace_label": scrub_connector_context_text(workspace_label, limit=MAX_LABEL_CHARS),
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    digest = "sha256:" + _canonical_request_sha256(request)
    if not ensure_resident_prerequisite(store.guard_home):
        return None
    with store_storage_gate.hold_storage_gate(store.guard_home, exclusive=False):
        response = _resident_request(
            operation="connector_setup_context",
            request=request,
            guard_home=store.guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=CONNECTOR_SETUP_CONTEXT_FEATURE,
            response_schema=_RESULT_SCHEMA,
        )
    # The resident wrote the store, as a store call would.
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
    if status != "ok" or code != "ok":
        return None
    return _advice(payload, cli_id=cli_id, identity_hash=identity_hash)


def _url_identity(match: re.Match[str]) -> str:
    """``scheme://host/path`` of a URL: remote identity has no credential, query or fragment."""

    scheme, _, rest = match.group(0).partition("://")
    authority_end = next((index for index, char in enumerate(rest) if char in "/?#"), len(rest))
    authority, tail = rest[:authority_end], rest[authority_end:]
    path = re.split(r"[?#]", tail, maxsplit=1)[0]
    return f"{scheme}://{authority.rsplit('@', 1)[-1]}{path}"


def _advice(payload: object, *, cli_id: str, identity_hash: str) -> ConnectorSetupAdvice | None:
    if not isinstance(payload, dict):
        return None
    fields = cast(dict[str, object], payload)
    cause, state, surface = fields.get("first_blocked_cause"), fields.get("resolution_state"), fields.get("surface")
    if (
        fields.get("cli_id") != cli_id
        or fields.get("identity_hash") != identity_hash
        or not isinstance(surface, str)
        or state not in _RESOLUTION_STATES
        or (cause is not None and not isinstance(cause, str))
    ):
        return None
    alternatives, recommendation = fields.get("allowed_alternatives"), fields.get("card_recommendation")
    if not isinstance(alternatives, dict) or not isinstance(recommendation, dict):
        return None
    # A recommendation starts off: nothing the resident returns is preselected.
    if recommendation.get("preselected") is not False:
        return None
    return ConnectorSetupAdvice(
        cli_id=cli_id,
        identity_hash=identity_hash,
        surface=surface,
        first_blocked_cause=cause,
        resolution_state=cast(str, state),
        allowed_alternatives=_alternatives(cast(dict[str, object], alternatives)),
        card_recommendation=dict(cast(dict[str, object], recommendation)),
    )


def _alternatives(value: dict[str, object]) -> AllowedAlternatives:
    def names(key: str) -> tuple[str, ...]:
        items = value.get(key)
        if not isinstance(items, list):
            return ()
        return tuple(item for item in items if isinstance(item, str))

    return AllowedAlternatives(
        tools=names("tools"),
        subcommands=names("subcommands"),
        catalog_contributions=names("catalog_contributions"),
    )


__all__ = [
    "CONNECTOR_SETUP_CONTEXT_FEATURE",
    "AllowedAlternatives",
    "ConnectorSetupAdvice",
    "record_connector_setup_context",
    "scrub_connector_context_text",
]
