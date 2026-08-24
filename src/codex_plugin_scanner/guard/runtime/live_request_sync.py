"""Durable, independent synchronization for local Guard approval requests."""

import base64
import json
import logging
import os
import threading
import urllib.error
import urllib.parse
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..continuation_runtime import continuation_offer_payload
from ..mdm.user_health import run_user_health_cadence, user_health_report_due
from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
)
from ..store import GuardStore
from ..store_live_request_outbox import live_request_oauth_subject_hash
from .live_request_display import build_display_command as _build_display_command
from .live_request_display import resolve_display_provenance as _resolve_display_provenance
from .local_request_snapshots import (
    _cloud_safe_local_request_payload,
    _cloud_scrub_text,
    _resolve_cloud_receipt_redaction_level,
)

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)

LIVE_REQUEST_SYNC_BATCH_SIZE = 1
LIVE_REQUEST_SYNC_MAX_BATCHES = 200
LIVE_REQUEST_SYNC_PROTOCOL_VERSION = "2"
LIVE_REQUEST_SYNC_STATE_KEY = "guard_live_request_sync_state"
DEFAULT_POLL_INTERVAL_SECONDS = 0.1
DEFAULT_ERROR_BACKOFF_SECONDS = 30.0
_EVENT_TYPE_MAP = {
    "pending": "request_created",
    "resolved": "request_resolved",
    "superseded": "request_superseded",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redacted_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP Error {error.code}: {error.reason}"
    if isinstance(error, OSError):
        return type(error).__name__
    return str(error)


def _resolve_sync_url(auth_context: dict[str, object], path: str) -> str:
    sync_url = str(auth_context.get("sync_url") or "")
    if not sync_url:
        raise RuntimeError("Guard sync URL is not configured.")
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Guard sync URL must be an absolute HTTP(S) URL.")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, ""))


def _encode_live_request_events(events: list[dict[str, object]]) -> str:
    event_json = json.dumps(
        events,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(event_json).decode("ascii")


def _live_request_sync_state_key(store: GuardStore) -> str:
    source = store.guard_source
    if source == "default":
        return LIVE_REQUEST_SYNC_STATE_KEY
    return f"{LIVE_REQUEST_SYNC_STATE_KEY}:{source}"


def _load_sync_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(_live_request_sync_state_key(store))
    return dict(payload) if isinstance(payload, dict) else {}


def _save_sync_state(store: GuardStore, state: dict[str, object]) -> None:
    store.set_sync_payload(_live_request_sync_state_key(store), state, _now())


def _build_live_request_event(
    item: dict[str, object],
    *,
    oauth: GuardReviewOAuthMetadata | None,
    redaction_level: str,
    store: GuardStore,
    event_sequence: int,
) -> dict[str, object] | None:
    request_id = item.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return None

    stored_status = str(item.get("status") or "pending")
    status = "pending" if stored_status == "expired" else stored_status
    event_type = _EVENT_TYPE_MAP.get(status, "request_created")

    claim: dict[str, object] | None = None
    if oauth is not None:
        try:
            claim = build_local_review_request_claim(
                request_row=item,
                oauth=oauth,
                store=store,
            )
        except GuardReviewContractError:
            claim = None

    display_command, display_summary, raw_command, redacted_command = _build_display_command(item, redaction_level)
    request_payload = _cloud_safe_local_request_payload(item, redaction_level=redaction_level)
    continuation = continuation_offer_payload(store, request_row=item, now=_now(), headless=True)
    display_provenance = _resolve_display_provenance(
        has_command_details=bool(request_payload.get("command_text")),
        redaction_level=redaction_level,
    )
    created_at = str(item.get("created_at") or _now())
    last_seen_at = str(item.get("last_seen_at") or created_at)

    return {
        "localRequestId": request_id,
        "correlationId": continuation["correlationId"],
        "localEventSequence": event_sequence,
        "eventType": event_type,
        "harnessId": str(item.get("harness") or "guard-review"),
        "requestKind": str(item.get("review_kind") or item.get("harness") or "guard-review"),
        "displayProvenance": display_provenance,
        "displayCommand": display_command,
        "displaySummary": display_summary,
        "rawCommand": raw_command,
        "redactedCommand": redacted_command,
        "reviewClaim": claim,
        "requestPayload": request_payload,
        "continuationCapability": continuation["capability"],
        "continuationHookAttached": continuation["hookAttached"],
        "continuationOpaqueTargetId": continuation["opaqueTargetId"],
        "continuationWaitDeadline": continuation["waitDeadline"],
        "riskCategory": str(item.get("risk_category") or "") or None,
        "policyAction": str(item.get("policy_action") or "") or None,
        "recommendedScope": str(item.get("recommended_scope") or "") or None,
        "localCreatedAt": created_at,
        "localUpdatedAt": str(item.get("updated_at") or last_seen_at),
        "localLastSeenAt": last_seen_at,
        "guardVersion": str(item.get("guard_version") or "") or None,
        "firstSeenGuardVersion": str(item.get("first_seen_guard_version") or "") or None,
        "lastSeenGuardVersion": str(item.get("last_seen_guard_version") or "") or None,
        "localEmittedAt": _now(),
        "sentAt": _now(),
    }


def _post_sync_events(
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> dict[str, object]:
    from .runner import _guard_sync_request, _urlopen_json_with_timeout_retry

    request_url = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
    payload: dict[str, object] = {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "deviceId": machine_id,
        "workspaceId": workspace_id,
        "machineInstallationId": machine_installation_id,
        "inboundCursor": cursor,
        "eventsBase64Url": _encode_live_request_events(events),
    }
    request = _guard_sync_request(
        auth_context,
        request_url=request_url,
        method="POST",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(
        request=request,
        timeout_seconds=35,
        retry_timeout_seconds=60,
    )


def _is_terminally_superseded_result(item: dict[str, object]) -> bool:
    """Return whether Cloud already owns a newer authoritative request state.

    ``decision_queued`` means a Cloud decision was durably queued for delivery;
    subsequent local refresh/resolution events cannot replace it. The eventual
    ``decision_applied`` acknowledgement travels as a separate outbox event.
    """
    if item.get("code") == "stale_sequence":
        return True
    error = item.get("error")
    if error in {"decision_queued", "stale_regression_rejected", "stale_sequence"}:
        return True
    return isinstance(error, str) and error.startswith("stale event sequence ")


def _retry_result_message(items: list[dict[str, object]]) -> str:
    details: list[str] = []
    for item in items:
        code = item.get("code")
        error = item.get("error")
        detail = ": ".join(
            _cloud_scrub_text(value) for value in (code, error) if isinstance(value, str) and value.strip()
        )
        if detail and detail not in details:
            details.append(detail)
    message = f"{len(items)} live request events require retry."
    if details:
        return f"{message} Cloud reported: {'; '.join(details[:3])}."
    return message


def sync_live_requests_once(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    """Drain the durable local approval outbox into the Cloud projection."""
    machine_id = str(auth_context.get("machine_id") or "")
    workspace_id = str(auth_context.get("workspace_id") or "")
    machine_installation_id = str(auth_context.get("machine_installation_id") or "")
    oauth_subject_hash = str(auth_context.get("oauth_subject_hash") or "")
    oauth_source = str(auth_context.get("oauth_source") or "")
    supplied_binding = {
        "oauth_source": oauth_source,
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }

    if not all(supplied_binding.values()) or supplied_binding != store.get_live_request_oauth_binding():
        raise RuntimeError(
            "Guard live request sync requires a matching source, OAuth subject, machine, workspace, "
            "and installation binding."
        )
    delivery_binding = {
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }
    store.claim_unowned_live_request_outbox(**delivery_binding)

    state = _load_sync_state(store)
    state.update(
        {
            "state": "syncing",
            "last_sync_attempt_at": _now(),
            "last_error": None,
        }
    )
    _save_sync_state(store, state)

    total_accepted = 0
    total_rejected = 0
    all_errors: list[str] = []
    batches = 0

    try:
        while batches < LIVE_REQUEST_SYNC_MAX_BATCHES:
            newest_first = batches % 10 != 9
            outbox_rows = store.list_ready_live_request_outbox(
                now=_now(),
                limit=LIVE_REQUEST_SYNC_BATCH_SIZE,
                **delivery_binding,
                newest_first=newest_first,
            )
            if not outbox_rows:
                break

            events: list[dict[str, object]] = []
            sequences: list[int] = []
            missing_sequences: list[int] = []
            redaction_level = _resolve_cloud_receipt_redaction_level(store)
            try:
                oauth = guard_review_oauth_metadata(store)
            except GuardReviewContractError:
                oauth = None
            for outbox_row in outbox_rows:
                sequence_value = outbox_row["sequence"]
                if not isinstance(sequence_value, int):
                    raise RuntimeError("Live-request outbox sequence is invalid.")
                sequence = sequence_value
                request_id = str(outbox_row["local_request_id"])
                request = store.get_approval_request(request_id)
                row_binding = {
                    key: outbox_row.get(key)
                    for key in (
                        "oauth_subject_hash",
                        "workspace_id",
                        "machine_id",
                        "machine_installation_id",
                    )
                }
                if (
                    request is None
                    or request.get("oauth_source") != store.guard_source
                    or row_binding != delivery_binding
                ):
                    missing_sequences.append(sequence)
                    continue
                event = _build_live_request_event(
                    request,
                    redaction_level=redaction_level,
                    oauth=oauth,
                    store=store,
                    event_sequence=sequence,
                )
                if event is None:
                    missing_sequences.append(sequence)
                    continue
                sequences.append(sequence)
                events.append(event)

            if missing_sequences:
                store.acknowledge_live_request_outbox(missing_sequences, **delivery_binding)
            if not events:
                continue

            try:
                response = _post_sync_events(
                    auth_context,
                    workspace_id=workspace_id,
                    machine_id=machine_id,
                    machine_installation_id=machine_installation_id,
                    cursor=None,
                    events=events,
                )
            except Exception as error:
                store.retry_live_request_outbox(
                    sequences,
                    now=_now(),
                    error=_redacted_error(error),
                    **delivery_binding,
                )
                raise

            accepted_value = response.get("accepted")
            rejected_value = response.get("rejected")
            accepted = int(accepted_value) if isinstance(accepted_value, (int, float)) else 0
            rejected = int(rejected_value) if isinstance(rejected_value, (int, float)) else 0
            total_accepted += accepted
            total_rejected += rejected
            batches += 1

            errors = response.get("errors")
            if isinstance(errors, list):
                all_errors.extend(str(error) for error in errors[:5])
            per_event_results = response.get("perEventResults")
            if isinstance(per_event_results, list) and len(per_event_results) == len(events):
                acknowledged_sequences: list[int] = []
                retry_sequences: list[int] = []
                retry_results: list[dict[str, object]] = []
                valid_results = True
                for index, item in enumerate(per_event_results):
                    if (
                        not isinstance(item, dict)
                        or item.get("index") != index
                        or not isinstance(item.get("accepted"), bool)
                    ):
                        valid_results = False
                        break
                    if item["accepted"] or _is_terminally_superseded_result(item):
                        acknowledged_sequences.append(sequences[index])
                    else:
                        retry_sequences.append(sequences[index])
                        retry_results.append(item)
                if (
                    valid_results
                    and sum(bool(item["accepted"]) for item in per_event_results) == accepted
                    and len(per_event_results) - accepted == rejected
                ):
                    store.acknowledge_live_request_outbox(acknowledged_sequences, **delivery_binding)
                    if retry_sequences:
                        message = _retry_result_message(retry_results)
                        all_errors.append(message)
                        store.retry_live_request_outbox(
                            retry_sequences,
                            now=_now(),
                            error=message,
                            **delivery_binding,
                        )
                    continue

            accounted = accepted + rejected
            if accounted != len(events):
                message = "Cloud live request sync acknowledgement count did not match the batch."
                all_errors.append(message)
                store.retry_live_request_outbox(
                    sequences,
                    now=_now(),
                    error=message,
                    **delivery_binding,
                )
                break
            if rejected:
                message = f"{rejected} live request events were rejected."
                all_errors.append(message)
                store.retry_live_request_outbox(
                    sequences,
                    now=_now(),
                    error=message,
                    **delivery_binding,
                )
                break
            store.acknowledge_live_request_outbox(sequences, **delivery_binding)

        completed_at = _now()
        outbox_status = store.live_request_outbox_status(
            now=completed_at,
            **delivery_binding,
        )
        state.update(
            {
                "state": "idle",
                "last_sync_at": completed_at,
                "last_success_at": completed_at,
                "synced_count": total_accepted,
                "rejected_count": total_rejected,
                "last_error": all_errors[0] if all_errors else None,
                "outbox_depth": outbox_status["depth"],
                "outbox_oldest_changed_at": outbox_status["oldest_changed_at"],
            }
        )
        _save_sync_state(store, state)

        outbox_depth = outbox_status["depth"]
        if not isinstance(outbox_depth, int):
            raise RuntimeError("Live-request outbox depth is invalid.")
        _LOGGER.info(
            "Guard live request sync complete: accepted=%d rejected=%d batches=%d outbox_depth=%d",
            total_accepted,
            total_rejected,
            batches,
            outbox_depth,
        )
        return {
            "synced": total_accepted,
            "rejected": total_rejected,
            "errors": all_errors[:5],
            "cursor": None,
            "batches": batches,
            "outbox": outbox_status,
        }
    except urllib.error.HTTPError as error:
        error_message = f"HTTP {error.code}: {error.reason}"
        state.update(
            {
                "state": "error",
                "last_error": error_message,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_message)
        raise
    except Exception as error:
        error_message = _redacted_error(error)
        state.update(
            {
                "state": "error",
                "last_error": error_message,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_message)
        raise


def live_request_sync_status(store: GuardStore) -> dict[str, object]:
    """Return live request outbox and delivery health."""
    state = _load_sync_state(store)
    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    binding = store.get_live_request_oauth_binding()
    if binding is not None:
        outbox = store.live_request_outbox_status(
            now=_now(),
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
    else:
        outbox = store.live_request_outbox_status(
            now=_now(),
            workspace_id=workspace_id,
        )
    return {
        "state": state.get("state") or "not_configured",
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_error": state.get("last_error"),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "outbox": outbox,
        "oauth_source": store.guard_source,
        "protocol_version": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    }


@dataclass
class LiveRequestSyncWorker:
    """Background worker for live-request event outbox sync."""

    thread: threading.Thread
    stop_event: threading.Event


def start_cloud_sync_sync_worker(
    store: GuardStore,
    existing: LiveRequestSyncWorker | None = None,
    *,
    poll_interval: float | None = None,
    error_backoff: float | None = None,
) -> LiveRequestSyncWorker | None:
    """Start independent live-request sync worker at daemon startup.

    Runs continuously syncing the outbox to cloud regardless of whether the
    command-queue lease path is active. Offline preservation ensures local
    enforcement continues while outbox buffers.
    """
    if existing is not None and existing.thread.is_alive() and not existing.stop_event.is_set():
        return existing
    if existing is not None and existing.thread.is_alive():
        existing.thread.join(timeout=1.0)
        if existing.thread.is_alive():
            raise RuntimeError("Previous live-request sync worker did not stop.")

    if os.environ.get("GUARD_LIVE_REQUEST_ENABLED", "1").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
    }:
        return None
    profile = store.get_cloud_sync_profile()
    if not isinstance(profile, dict) or not profile.get("workspace_id") or not profile.get("sync_url"):
        return None
    stop_event = threading.Event()
    poll_interval = poll_interval or float(
        os.environ.get(
            "GUARD_LIVE_REQUEST_POLL_INTERVAL",
            str(DEFAULT_POLL_INTERVAL_SECONDS),
        )
    )
    error_backoff = error_backoff or float(
        os.environ.get(
            "GUARD_LIVE_REQUEST_ERROR_BACKOFF",
            str(DEFAULT_ERROR_BACKOFF_SECONDS),
        )
    )

    thread = threading.Thread(
        target=_cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "poll_interval": poll_interval,
            "error_backoff": error_backoff,
        },
        daemon=True,
        name="hol-guard-live-request-sync",
    )
    thread.start()
    return LiveRequestSyncWorker(thread=thread, stop_event=stop_event)


def stop_cloud_sync_sync_worker(
    worker: LiveRequestSyncWorker | None,
) -> LiveRequestSyncWorker | None:
    """Signal a live-request sync worker and wait briefly for shutdown."""
    if worker is None:
        return None
    worker.stop_event.set()
    worker.thread.join(timeout=1.0)
    return worker if worker.thread.is_alive() else None


def _with_live_request_sync_identity(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    oauth = guard_review_oauth_metadata(store)
    subject_hash = live_request_oauth_subject_hash(oauth.grant_id)
    if subject_hash is None:
        raise GuardReviewContractError("missing_oauth_subject")
    binding = store.get_live_request_oauth_binding()
    expected_binding = {
        "oauth_source": store.guard_source,
        "oauth_subject_hash": subject_hash,
        "workspace_id": oauth.workspace_id,
        "machine_id": oauth.machine_id,
        "machine_installation_id": oauth.installation_id,
    }
    if binding != expected_binding:
        raise GuardReviewContractError("oauth_binding_mismatch")
    return {
        **auth_context,
        **expected_binding,
    }


def _resolve_live_request_sync_auth_context(store: GuardStore) -> dict[str, Any]:
    """Resolve cloud sync auth context and repair paired storage when possible."""
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _resolve_guard_sync_auth_context,
        repair_guard_cloud_connect_storage,
    )

    try:
        return _with_live_request_sync_identity(store, _resolve_guard_sync_auth_context(store))
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = repair_guard_cloud_connect_storage(store)
        if repair["existing_sign_in_valid"] or repair["repaired_storage"]:
            return _with_live_request_sync_identity(store, _resolve_guard_sync_auth_context(store))
        raise


def _cloud_sync_sync_loop(
    store: GuardStore,
    stop_event: threading.Event,
    *,
    poll_interval: float,
    error_backoff: float,
) -> None:
    """Main loop for the independent live-request sync worker."""
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
    )

    error_streak = 0
    while not stop_event.is_set():
        try:
            auth_context = _resolve_live_request_sync_auth_context(store)
            result = sync_live_requests_once(store, auth_context)
            with suppress(OSError, PermissionError, RuntimeError, ValueError):
                if user_health_report_due(store.guard_home):
                    run_user_health_cadence(store.guard_home)
            synced = result.get("synced", 0)
            if isinstance(synced, int) and synced > 0:
                error_streak = 0
                continue
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
            error_streak += 1
            state = _load_sync_state(store)
            state.update(
                {
                    "state": "error",
                    "last_error": _redacted_error(error),
                    "last_error_at": _now(),
                }
            )
            _save_sync_state(store, state)
        except Exception as error:
            error_streak += 1
            _LOGGER.exception("Unexpected error in live-request sync loop")
            state = _load_sync_state(store)
            state.update(
                {
                    "state": "error",
                    "last_error": _redacted_error(error),
                    "last_error_at": _now(),
                }
            )
            _save_sync_state(store, state)

        wait = min(error_backoff, poll_interval * (2 ** min(error_streak, 10))) if error_streak else poll_interval
        if stop_event.wait(wait):
            return
