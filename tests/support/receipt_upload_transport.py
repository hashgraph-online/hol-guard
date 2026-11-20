"""Carry the receipt upload over urllib in unit tests.

The native ``cloud-event-sync`` command uploads the receipts itself, so a test
that fakes ``urllib`` or ``cloud_sync_transport._urlopen_json_with_timeout_retry`` would
otherwise never see those requests. Most such tests check what the runner does
with Cloud's answer (the policy bundle, advisories, the summary), not the
upload. This double selects, batches and posts the receipts the way the
earlier Python runner did, through the transport those tests already fake, and
answers in the native command's shape.

The native upload is tested in
``rust/crates/guard-runtime/src/cloud_receipt_upload_tests.rs``; mark a test
``native_receipt_upload`` to run the real command.
"""

from __future__ import annotations

import json
import logging
import types
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

RECEIPT_SYNC_BATCH_SIZE = 50
RECEIPT_SYNC_CURSOR_PAGE_SIZE = 200
RECEIPT_SYNC_CURSOR_BACKFILL_ROWS = 200
RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS = 30
RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT = 200
RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER = "cloud_receipt_command_detail_backfill_v2"
RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG = "__command_detail_backfill"
# Serialized size of the `, "workspaceAssessments": ` key the summary adds to the sync context.
WORKSPACE_ASSESSMENT_KEY_OVERHEAD = 32


def receipt_upload_over_urllib(original: Callable[..., object], *, native: bool = False) -> Callable[..., object]:
    """Wrap ``cloud_receipt_upload`` for tests that fake ``urllib``."""

    def cloud_receipt_upload(
        guard_home: Path,
        upload: Mapping[str, object],
        *,
        auth_context: Mapping[str, object] | None = None,
    ) -> object:
        if native:
            return original(guard_home, upload, auth_context=auth_context)
        return upload_receipts(Path(guard_home), dict(upload), auth_context=auth_context)

    return cloud_receipt_upload


def receipt_sync_cursor_rowid(store: object) -> int | None:
    payload = store.get_sync_payload("receipt_sync_cursor")
    if not isinstance(payload, dict):
        return None
    value = payload.get("last_rowid")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _window_floor(receipts: list[dict[str, object]]) -> int | None:
    rowids = [
        value
        for value in (item.get("receipt_rowid") for item in receipts)
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    if not rowids:
        return None
    return max(min(rowids) - 1, 0)


def receipt_sync_rows_for_upload(store: object, *, cursor_rowid: int | None) -> list[dict[str, object]]:
    """The rows past the cursor; the first page reads its window in rowid order."""

    if cursor_rowid is None:
        newest = store.list_receipts(limit=RECEIPT_SYNC_CURSOR_PAGE_SIZE)
        first_after = _window_floor(newest)
        if first_after is None:
            return newest
        return store.list_receipts_since_rowid(after_rowid=first_after, limit=RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    latest_rowid = store.latest_receipt_rowid()
    if latest_rowid is None:
        return []
    if cursor_rowid > latest_rowid:
        backfill_after = max(latest_rowid - RECEIPT_SYNC_CURSOR_BACKFILL_ROWS, 0)
        return store.list_receipts_since_rowid(after_rowid=backfill_after, limit=RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    return store.list_receipts_since_rowid(after_rowid=cursor_rowid, limit=RECEIPT_SYNC_CURSOR_PAGE_SIZE)


def _backfill_before_rowid(marker: object, *, redaction_level: str) -> int | None:
    if not isinstance(marker, dict) or marker.get("level") != redaction_level:
        return None
    value = marker.get("before_rowid")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def receipt_sync_rows_with_command_detail_backfill(
    store: object,
    *,
    receipts: list[dict[str, object]],
    redaction_level: str,
    synced_at: str,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    """The rows with older receipts appended for their command detail, and the marker."""

    if redaction_level not in {"partial", "none"}:
        return receipts, None
    marker = store.get_sync_payload(RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)
    before_rowid = _backfill_before_rowid(marker, redaction_level=redaction_level)
    if isinstance(marker, dict) and marker.get("level") == redaction_level and marker.get("complete") is True:
        return receipts, None
    backfill_rows = store.list_receipts_for_command_detail_backfill(
        limit=RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        days=RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        before_rowid=before_rowid,
    )
    seen = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    merged = list(receipts)
    added = 0
    for row in backfill_rows:
        receipt_id = row.get("receipt_id")
        if not isinstance(receipt_id, str) or receipt_id in seen:
            continue
        merged.append({**row, RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG: True})
        seen.add(receipt_id)
        added += 1
    rowids = [row["receipt_rowid"] for row in backfill_rows if isinstance(row.get("receipt_rowid"), int)]
    return merged, {
        "level": redaction_level,
        "updated_at": synced_at,
        "days": RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        "limit": RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        "receipts": added,
        "queried": len(backfill_rows),
        "before_rowid": min(rowids) if rowids else before_rowid,
        "complete": not backfill_rows,
    }


def _advance_marker(
    marker: dict[str, object] | None, batch: Sequence[Mapping[str, object]], synced_at: str
) -> dict[str, object] | None:
    if marker is None:
        return None
    rowids = [
        rowid
        for item in batch
        if item.get(RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG) is True
        and isinstance((rowid := item.get("receipt_rowid")), int)
    ]
    if not rowids:
        return None
    return {**marker, "before_rowid": min(rowids), "updated_at": synced_at}


def receipt_sync_cursor_rowids_from_batch(
    batch: Sequence[Mapping[str, object]], *, cursor_receipt_ids: set[object]
) -> list[object]:
    return [item.get("receipt_rowid") for item in batch if item.get("receipt_id") in cursor_receipt_ids]


def _batches(receipts: list[dict[str, object]]) -> tuple[list[dict[str, object]], ...]:
    if not receipts:
        return ([],)
    return tuple(
        receipts[index : index + RECEIPT_SYNC_BATCH_SIZE] for index in range(0, len(receipts), RECEIPT_SYNC_BATCH_SIZE)
    )


def _save_cursor(store: object, rowid: int | None, synced_at: str) -> None:
    if rowid is not None:
        store.set_sync_payload("receipt_sync_cursor", {"last_rowid": rowid, "synced_at": synced_at}, synced_at)


def _post(store: object, auth: dict[str, object], body: bytes, *, refresh: bool) -> tuple[dict[str, object], bool]:
    from codex_plugin_scanner.guard.runtime import runner
    from tests.support import cloud_sync_transport

    def send(context: Mapping[str, object]) -> object:
        url = runner._sync.normalized_receipts_sync_url(
            runner._validate_guard_sync_url(runner._auth_context_sync_url(context))
        )
        request = cloud_sync_transport._guard_sync_request(
            context, request_url=url, method="POST", data=body, extra_headers=None
        )
        return cloud_sync_transport._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=runner._SYNC_HTTP_TIMEOUT_SECONDS,
            retry_timeout_seconds=runner._SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        )

    refreshed = False
    try:
        try:
            payload = send(auth)
        except urllib.error.HTTPError as error:
            if error.code != 401 or runner._cloud_edge_block_from_http_error(error) is not None or not refresh:
                raise
            refreshed = True
            auth.clear()
            auth.update(runner._resolve_guard_sync_auth_context(store, force_refresh=True))
            payload = send(auth)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            edge_block = runner._cloud_edge_block_from_http_error(error)
            if edge_block is not None:
                raise RuntimeError(edge_block) from error
            raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message()) from error
        if error.code == 403:
            is_plan, message = runner._check_plan_restriction_403(error)
            if is_plan:
                raise runner.GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        raise RuntimeError(runner._sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    if not isinstance(payload, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    return payload, refreshed


def _record_posture(store: object, posture: Mapping[str, object] | None, response: dict[str, object]) -> None:
    from codex_plugin_scanner.guard.runtime import fleet_posture, runner

    stamp = runner._sync_timestamp(response)
    if posture is not None:
        built = types.SimpleNamespace(
            next_state=posture.get("nextState"), advanced_inventory=posture.get("advancedInventory") is True
        )
        try:
            fleet_posture.commit_fleet_posture_sent(store, built, now=stamp)
        except Exception:
            _LOGGER.debug("Fleet posture snapshot could not be recorded", exc_info=True)
    request = response.get("fleetPostureRequest")
    if isinstance(request, dict) and request.get("inventory") == "full":
        try:
            fleet_posture.request_full_inventory(store, source="cloud", now=stamp)
        except Exception:
            _LOGGER.debug("Full inventory request could not be recorded", exc_info=True)


def upload_receipts(
    guard_home: Path, upload: dict[str, object], *, auth_context: Mapping[str, object] | None
) -> dict[str, object]:
    """The receipt upload the earlier Python runner ran, answered in the native shape."""

    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.runtime import workspace_assessment_sync as workspace
    from codex_plugin_scanner.guard.runtime.cloud_request_native import cloud_sync_receipt_payloads
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(guard_home)
    auth = dict(auth_context) if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    level = str(upload["redactionLevel"])
    receipts: list[dict[str, object]] = []
    prior_cursor: int | None = None
    marker: dict[str, object] | None = None
    # A context-only request carries no receipts and moves no cursor.
    if upload.get("contextOnly") is not True:
        prior_cursor = receipt_sync_cursor_rowid(store)
        receipts = receipt_sync_rows_for_upload(store, cursor_rowid=prior_cursor)
    cursor_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    if upload.get("contextOnly") is not True:
        receipts, marker = receipt_sync_rows_with_command_detail_backfill(
            store, receipts=receipts, redaction_level=level, synced_at=str(upload["now"])
        )
    sync_context = dict(upload["syncContext"])
    posture = upload.get("fleetPosture")
    built = upload.get("workspaceAssessments")
    pending = None if built is None else workspace.WorkspaceAssessmentSyncBuild(built["payload"], built["digest"])
    allow_refresh = upload.get("allowAuthRefresh") is True
    refreshed = False
    latest: int | None = None
    payload: dict[str, object] = {}
    tally: dict[str, object] = {"stored": 0, "advisories": [], "bundle": None, "sync_payload": None}
    flags = {"provided": False, "malformed": False, "delivery_provided": False}
    delivery: object = None
    preferences: dict[str, object] | None = None
    review_keys: object = None
    for index, batch in enumerate(_batches(receipts)):
        context = dict(sync_context)
        if index == 0 and isinstance(posture, dict):
            context["fleetPosture"] = posture["payload"]
        projected = cloud_sync_receipt_payloads(
            batch,
            device_id=str(upload["deviceId"]),
            device_name=str(upload["deviceName"]),
            redaction_level=level,
            now=str(upload["now"]),
        )
        sent = None
        if pending is not None:
            base = len(json.dumps({"receipts": projected, "syncContext": context}).encode("utf-8"))
            sent = workspace.fit_workspace_assessment_to_request(
                pending, workspace.MAX_REQUEST_BYTES - base - WORKSPACE_ASSESSMENT_KEY_OVERHEAD
            )
            if sent is not None:
                context["workspaceAssessments"] = sent.payload
                pending = None
        body = json.dumps({"receipts": projected, "syncContext": context}).encode("utf-8")
        payload, did_refresh = _post(store, auth, body, refresh=allow_refresh and not refreshed)
        refreshed = refreshed or did_refresh
        _record_posture(store, posture if index == 0 and isinstance(posture, dict) else None, payload)
        workspace.record_workspace_assessment_delivery(store, sent)
        for rowid in receipt_sync_cursor_rowids_from_batch(batch, cursor_receipt_ids=cursor_ids):
            if isinstance(rowid, int) and (latest is None or rowid > latest):
                latest = rowid
        stamp = runner._sync_timestamp(payload)
        advanced = _advance_marker(marker, batch, stamp)
        if advanced is not None:
            marker = advanced
            store.set_sync_payload(RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER, marker, stamp)
        _save_cursor(store, latest, stamp)
        stored = payload.get("receiptsStored")
        if isinstance(stored, int):
            tally["stored"] = int(tally["stored"]) + stored
        advisories = payload.get("advisories")
        if isinstance(advisories, list):
            tally["advisories"].extend(item for item in advisories if isinstance(item, dict))
        if "policyBundle" in payload:
            flags["provided"] = True
            bundle = payload.get("policyBundle")
            if isinstance(bundle, dict):
                if bundle or tally["bundle"] is None:
                    tally["bundle"] = bundle
                    tally["sync_payload"] = payload
                    flags["delivery_provided"] = "policyBundleDelivery" in payload
                    delivery = payload.get("policyBundleDelivery")
            else:
                flags["malformed"] = True
        alert = payload.get("alertPreferences")
        if isinstance(alert, dict) and (alert or preferences is None):
            preferences = alert
        if "reviewVerificationKeys" in payload:
            review_keys = payload.get("reviewVerificationKeys")
    now = runner._sync_timestamp(payload)
    if marker is not None:
        store.set_sync_payload(RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER, marker, now)
    cursor = latest if latest is not None else prior_cursor
    _save_cursor(store, cursor, now)
    return {
        "synced_at": payload.get("syncedAt"),
        "now": now,
        "receipts": len(receipts),
        "receipts_stored": tally["stored"],
        "advisories": tally["advisories"],
        "policy_bundle": {**flags, "sync_payload": tally["sync_payload"], "delivery": delivery},
        "alert_preferences": preferences,
        "review_verification_keys": review_keys,
        "receipt_cursor_rowid": cursor,
        "receipt_cursor_backfill": bool(
            prior_cursor is not None
            and receipts
            and not any(
                isinstance(rowid := item.get("receipt_rowid"), int) and rowid > prior_cursor for item in receipts
            )
        ),
        "auth_refreshed": refreshed,
    }
