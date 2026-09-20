"""Payload fields.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _remote_harness(value: object, *, allow_wildcard: bool = True) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return "*" if allow_wildcard else None


def _remote_workspace(item: dict[str, object]) -> str | None:
    return runner._optional_string(item.get("workspace")) or runner._optional_string(item.get("workspacePath"))


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _extract_dict_field(credentials: dict[str, object], key: str) -> dict[str, str] | None:
    value = credentials.get(key)
    if not isinstance(value, dict):
        return None
    return {str(k): str(v) for k, v in value.items()}


def _int_value(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _request_data_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    return None


def _auth_context_sync_url(auth_context: dict[str, object]) -> str:
    sync_url = runner._optional_string(auth_context.get("sync_url"))
    if sync_url is None:
        raise RuntimeError("Guard sync URL is unavailable.")
    return sync_url


def _metric_count(metrics: dict[str, dict[str, object]], key: str) -> int:
    metric = metrics.get(key)
    if not isinstance(metric, dict):
        return 0
    return runner._int_value(metric.get("value")) or 0


def _normalized_timestamp_string(value: object) -> str | None:
    raw_value = runner._optional_string(value)
    if raw_value is None:
        return None
    parsed = runner._parse_iso_timestamp(raw_value)
    if parsed is None:
        return None
    return parsed.isoformat()


def _last_uploaded_event_id(payload: dict[str, object] | list[object] | None) -> int:
    if not isinstance(payload, dict):
        return 0
    event_id = payload.get("event_id")
    return event_id if isinstance(event_id, int) and event_id > 0 else 0


def _pain_signal_sync_url(sync_url: str) -> str:
    parsed = runner.urllib.parse.urlsplit(sync_url)
    path = parsed.path.rstrip("/")
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) >= 2 and segments[-2:] in (["receipts", "sync"], ["inventory", "sync"]):
        next_segments = [*segments[:-2], "signals", "pain"]
    elif segments and segments[-1] in {"receipts", "inventory"}:
        next_segments = [*segments[:-1], "signals", "pain"]
    else:
        next_segments = [*segments, "signals", "pain"]
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/" + "/".join(next_segments),
            parsed.query,
            parsed.fragment,
        )
    )


def _normalized_receipts_sync_url(sync_url: str) -> str:
    parsed = runner.urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/registry/api/v1":
        return runner.urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/registry/api/v1/guard/receipts/sync",
                parsed.query,
                "",
            )
        )
    return sync_url


def _normalized_runtime_sessions_sync_url(sync_url: str) -> str:
    normalized_receipts_url = runner._normalized_receipts_sync_url(sync_url)
    parsed = runner.urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        return runner.urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/registry/api/v1/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        return runner.urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    if parsed.path.rstrip("/") == "/guard/receipts/sync":
        return runner.urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/runtime/sessions/sync",
            parsed.query,
            "",
        )
    )


def _normalized_supply_chain_bundle_url(sync_url: str, workspace_id: str) -> str:
    normalized_receipts_url = runner._normalized_receipts_sync_url(sync_url)
    parsed = runner.urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        next_path = "/registry/api/v1/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/bundle"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/bundle"
    query_pairs = [
        (key, value)
        for key, value in runner.urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            runner.urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _guard_events_sync_url(sync_url: str) -> str:
    parsed = runner.urllib.parse.urlsplit(runner._normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/").endswith("/api/v1/guard/events"):
        return runner.urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), parsed.query, ""))
    path = parsed.path.rstrip("/")
    for suffix in (
        "/registry/api/v1/guard/receipts/sync",
        "/api/guard/receipts/sync",
        "/guard/receipts/sync",
    ):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path.rstrip("/") + "/api/v1/guard/events",
            parsed.query,
            "",
        )
    )


def _sync_timestamp(payload: dict[str, object]) -> str:
    synced_at = runner._optional_string(payload.get("syncedAt"))
    if synced_at is not None and runner._parse_iso_timestamp(synced_at) is not None:
        return synced_at
    return runner._now()


def _parse_iso_timestamp(value: str) -> runner.datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = runner.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=runner.timezone.utc)
    return parsed


def _now() -> str:
    return runner.datetime.now(runner.timezone.utc).isoformat()
