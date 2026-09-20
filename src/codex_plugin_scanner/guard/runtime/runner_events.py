"""Events.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def sync_guard_events(
    store: runner.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Push pending GuardEventV1 envelopes to Guard Cloud."""

    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    sync_url = runner._guard_events_sync_url(
        runner._validate_guard_sync_url(runner._auth_context_sync_url(resolved_auth_context))
    )
    previous_summary = store.get_sync_payload("guard_events_v1_summary")
    total_events = 0
    total_accepted = 0
    synced_at = runner._now()
    while True:
        pending_events = store.list_guard_events_v1(uploaded=False, limit=200)
        if not pending_events:
            if (
                total_events == 0
                and isinstance(previous_summary, dict)
                and previous_summary.get("sync_reason") == "guard_events_endpoint_unavailable"
                and runner._guard_events_endpoint_unavailable_recently(store)
            ):
                return previous_summary
            break
        body = runner.json.dumps({"events": [event["payload"] for event in pending_events]}).encode("utf-8")
        request = runner._guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        try:
            payload = runner._urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=runner._SYNC_HTTP_TIMEOUT_SECONDS,
                retry_timeout_seconds=runner._SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            )
        except runner.urllib.error.HTTPError as error:
            if error.code == 404:
                pending_count = len(pending_events)
                summary: dict[str, object] = {
                    "synced_at": synced_at,
                    "events": total_events,
                    "accepted": total_accepted,
                    "skipped": 0,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_endpoint_unavailable",
                    "pending_count": pending_count,
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 429:
                retry_after_seconds = runner._parse_retry_after_header(error)
                summary: dict[str, object] = {
                    "synced_at": synced_at,
                    "events": total_events,
                    "accepted": total_accepted,
                    "skipped": 0,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_rate_limited",
                    "pending_count": len(pending_events),
                    "retry_after_seconds": retry_after_seconds,
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 403:
                is_plan, message = runner._check_plan_restriction_403(error)
                if is_plan:
                    raise runner.GuardSyncNotAvailableError(message) from error
                runner._record_guard_events_sync_failure(
                    store,
                    total_events=total_events,
                    total_accepted=total_accepted,
                    pending_count=len(pending_events),
                    error_type=type(error).__name__,
                    message=message,
                )
                raise RuntimeError(message) from error
            message = runner._sync_http_error_message(error)
            runner._record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(runner._redact_sync_text(message)) from error
        except OSError as error:
            message = runner._sync_url_error_message(error)
            runner._record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(runner._redact_sync_text(message)) from error
        completed_ids = runner._completed_guard_event_ids(payload)
        synced_at = runner._sync_timestamp(payload)
        uploaded = store.mark_guard_events_v1_uploaded(completed_ids, synced_at)
        total_events += len(pending_events)
        total_accepted += uploaded
        if uploaded == 0 or len(pending_events) < 200:
            break
    summary: dict[str, object] = {"synced_at": synced_at, "events": total_events, "accepted": total_accepted}
    store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
    return summary


def _record_guard_events_sync_failure(
    store: runner.GuardStore,
    *,
    total_events: int,
    total_accepted: int,
    pending_count: int,
    error_type: str,
    message: str,
) -> None:
    recorded_at = runner._now()
    next_retry_after = (
        runner.datetime.now(runner.timezone.utc) + runner.timedelta(seconds=runner._SYNC_HTTP_RETRY_TIMEOUT_SECONDS)
    ).isoformat()
    summary: dict[str, object] = {
        "synced_at": None,
        "status": "failed",
        "events": total_events,
        "accepted": total_accepted,
        "pending_events": pending_count,
        "error_type": error_type,
        "message": runner._redact_sync_text(message),
        "retry_after_seconds": runner._SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        "next_retry_after": next_retry_after,
    }
    store.set_sync_payload("guard_events_v1_summary", summary, recorded_at)


def _guard_events_endpoint_unavailable_recently(store: runner.GuardStore) -> bool:
    summary = store.get_sync_payload("guard_events_v1_summary")
    if not isinstance(summary, dict):
        return False
    if summary.get("sync_reason") not in ("guard_events_endpoint_unavailable", "guard_events_rate_limited"):
        return False
    synced_at = summary.get("synced_at")
    if not isinstance(synced_at, str):
        return True
    parsed = runner._parse_iso_timestamp(synced_at)
    if parsed is None:
        return True
    return runner.datetime.now(runner.timezone.utc) - parsed < runner.timedelta(
        minutes=runner._GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES
    )


def sync_pain_signals(
    store: runner.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> int:
    try:
        resolved_auth_context = auth_context or runner._resolve_guard_sync_auth_context(store)
    except runner.GuardSyncAuthorizationExpiredError:
        raise
    except runner.GuardSyncNotConfiguredError:
        return 0
    normalized_sync_url = runner._normalized_receipts_sync_url(
        runner._validate_guard_sync_url(runner._auth_context_sync_url(resolved_auth_context))
    )
    cursor_payload = store.get_sync_payload("pain_signal_cursor")
    last_event_id = runner._last_uploaded_event_id(cursor_payload)
    uploaded_count = 0
    current_event_id = last_event_id
    warn_occurrences: dict[tuple[str, str], int] = {}
    while True:
        candidates = store.list_events_after(
            current_event_id,
            limit=500,
            event_names=tuple(sorted(runner._PAIN_SIGNAL_EVENTS)),
        )
        if not candidates:
            break
        last_processed_event_id = runner._int_value(candidates[-1].get("event_id")) or current_event_id
        signal_items: list[dict[str, object]] = []
        for item in candidates:
            event_name = runner._optional_string(item.get("event_name"))
            payload = item.get("payload")
            if event_name == "install_time_warn" and isinstance(payload, dict):
                warn_key = runner._warning_occurrence_key(payload)
                if warn_key is not None:
                    warn_occurrences[warn_key] = warn_occurrences.get(warn_key, 0) + 1
            pain_signal = runner._pain_signal_item(item, warn_occurrences=warn_occurrences)
            if pain_signal is not None:
                signal_items.append(pain_signal)
        if signal_items:
            request = runner._guard_sync_request(
                resolved_auth_context,
                request_url=runner._pain_signal_sync_url(normalized_sync_url),
                method="POST",
                data=runner.json.dumps({"items": signal_items}).encode("utf-8"),
                extra_headers=None,
            )
            try:
                runner._urlopen_with_timeout_retry(
                    request=request,
                    timeout_seconds=runner._PAIN_SIGNAL_TIMEOUT_SECONDS,
                    retry_timeout_seconds=runner._PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS,
                )
            except runner.urllib.error.HTTPError as error:
                if error.code == 404:
                    return uploaded_count
                if error.code == 429:
                    return uploaded_count
                raise RuntimeError(runner._sync_http_error_message(error)) from error
            except OSError as error:
                raise RuntimeError(runner._sync_url_error_message(error)) from error
            uploaded_count += len(signal_items)
        current_event_id = last_processed_event_id
        store.set_sync_payload(
            "pain_signal_cursor",
            {"event_id": current_event_id},
            runner._now(),
        )
        if len(candidates) < 500:
            break
    return uploaded_count
