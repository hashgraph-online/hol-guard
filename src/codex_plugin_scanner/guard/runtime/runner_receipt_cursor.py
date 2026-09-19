"""Receipt cursor.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _completed_guard_event_ids(payload: dict[str, object]) -> list[str]:
    statuses = payload.get("statuses")
    if not isinstance(statuses, list):
        return []
    completed: list[str] = []
    for item in statuses:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        event_id = item.get("eventId")
        if status in {"accepted", "duplicate", "rejected"} and isinstance(event_id, str):
            completed.append(event_id)
    return completed


def _cloud_sync_receipts_payload(
    receipts: list[dict[str, object]],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> list[dict[str, object]]:
    return [
        runner._cloud_sync_receipt_payload(
            receipt,
            device_id=device_id,
            device_name=device_name,
            redaction_level=redaction_level,
        )
        for receipt in receipts
    ]


def _dedupe_sync_payload_items(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for item in items:
        fingerprint = runner.json.dumps(item, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(item)
    return deduped


def _iter_receipt_sync_batches(receipts: list[dict[str, object]]) -> tuple[list[dict[str, object]], ...]:
    if not receipts:
        return ([],)
    return tuple(
        receipts[index : index + runner._RECEIPT_SYNC_BATCH_SIZE]
        for index in range(0, len(receipts), runner._RECEIPT_SYNC_BATCH_SIZE)
    )


def _receipt_sync_cursor_rowid(store: runner.GuardStore) -> int | None:
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


def _receipt_sync_rows_for_upload(store: runner.GuardStore, *, cursor_rowid: int | None) -> list[dict[str, object]]:
    if cursor_rowid is None:
        return store.list_receipts(limit=runner._RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    latest_rowid = store.latest_receipt_rowid()
    if latest_rowid is None:
        return []
    if cursor_rowid > latest_rowid:
        backfill_after = max(latest_rowid - runner._RECEIPT_SYNC_CURSOR_BACKFILL_ROWS, 0)
        return store.list_receipts_since_rowid(after_rowid=backfill_after, limit=runner._RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    return store.list_receipts_since_rowid(after_rowid=cursor_rowid, limit=runner._RECEIPT_SYNC_CURSOR_PAGE_SIZE)


def _receipt_sync_rows_with_command_detail_backfill(
    store: runner.GuardStore,
    *,
    receipts: list[dict[str, object]],
    redaction_level: str,
    synced_at: str,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    if runner._receipt_redaction_level_rank(redaction_level) <= runner._receipt_redaction_level_rank("full"):
        return receipts, None
    marker = store.get_sync_payload(runner._RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)
    before_rowid = runner._receipt_command_detail_backfill_before_rowid(marker, redaction_level=redaction_level)
    if isinstance(marker, dict) and marker.get("level") == redaction_level and marker.get("complete") is True:
        return receipts, None
    backfill_rows = store.list_receipts_for_command_detail_backfill(
        limit=runner._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        days=runner._RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        before_rowid=before_rowid,
    )
    seen_receipt_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    merged = list(receipts)
    added = 0
    for row in backfill_rows:
        receipt_id = row.get("receipt_id")
        if not isinstance(receipt_id, str) or receipt_id in seen_receipt_ids:
            continue
        merged.append({**row, runner._RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG: True})
        seen_receipt_ids.add(receipt_id)
        added += 1
    backfill_rowids: list[int] = []
    for row in backfill_rows:
        receipt_rowid = row.get("receipt_rowid")
        if isinstance(receipt_rowid, int):
            backfill_rowids.append(receipt_rowid)
    next_before_rowid = min(backfill_rowids) if backfill_rowids else before_rowid
    complete = len(backfill_rows) < runner._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT
    return merged, {
        "level": redaction_level,
        "updated_at": synced_at,
        "days": runner._RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        "limit": runner._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        "receipts": added,
        "queried": len(backfill_rows),
        "before_rowid": next_before_rowid,
        "complete": complete,
    }


def _receipt_command_detail_backfill_before_rowid(marker: object, *, redaction_level: str) -> int | None:
    if not isinstance(marker, dict) or marker.get("level") != redaction_level:
        return None
    value = marker.get("before_rowid")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _advance_command_detail_backfill_marker(
    marker: dict[str, object] | None,
    *,
    receipt_batch: runner.Sequence[runner.Mapping[str, object]],
    synced_at: str,
) -> dict[str, object] | None:
    if marker is None:
        return None
    backfill_rowids = [
        receipt_rowid
        for item in receipt_batch
        if item.get(runner._RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG) is True
        and isinstance((receipt_rowid := item.get("receipt_rowid")), int)
    ]
    if not backfill_rowids:
        return None
    updated_marker = dict(marker)
    updated_marker["before_rowid"] = min(backfill_rowids)
    updated_marker["updated_at"] = synced_at
    return updated_marker


def _receipt_sync_cursor_rowids_from_batch(
    receipt_batch: runner.Sequence[runner.Mapping[str, object]],
    *,
    cursor_receipt_ids: set[object],
) -> list[object]:
    return [item.get("receipt_rowid") for item in receipt_batch if item.get("receipt_id") in cursor_receipt_ids]


def _validated_policy_bundle_acknowledgement(
    store: runner.GuardStore,
    *,
    device_id: str,
    device_name: str,
) -> dict[str, object] | None:
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    if not isinstance(acknowledgement, dict):
        return None
    if acknowledgement.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT:
        validated, _error = runner.validated_policy_bundle_v2_acknowledgement(acknowledgement)
        return validated

    policy_bundle = runner.validated_synced_policy_bundle(store)
    if policy_bundle is None:
        return None

    bundle_hash = runner.non_empty_string(policy_bundle.get("bundleHash"))
    bundle_version = runner.non_empty_string(policy_bundle.get("bundleVersion"))
    if bundle_hash is None or bundle_version is None:
        return None
    if acknowledgement.get("bundleHash") != bundle_hash:
        return None
    if acknowledgement.get("bundleVersion") != bundle_version:
        return None
    if acknowledgement.get("deviceId") != device_id:
        return None
    if acknowledgement.get("deviceName") != device_name:
        return None
    if acknowledgement.get("status") != "synced":
        return None
    if runner._normalized_timestamp_string(acknowledgement.get("appliedAt")) is None:
        return None
    return acknowledgement


def _receipt_sync_context(
    store: runner.GuardStore,
    *,
    local_guard_online_at: str,
    device_id: str | None = None,
    device_name: str | None = None,
) -> dict[str, object]:
    resolved_device_id = device_id
    resolved_device_name = device_name
    if resolved_device_id is None or resolved_device_name is None:
        resolved_device_id, resolved_device_name = runner._guard_device_metadata(store)
    runtime_summary = store.get_sync_payload("runtime_session_summary")
    runtime_synced_at = (
        runner._optional_string(runtime_summary.get("runtime_session_synced_at"))
        if isinstance(runtime_summary, dict)
        else None
    )
    runtime_harness = (
        runner._optional_string(runtime_summary.get("runtime_harness")) if isinstance(runtime_summary, dict) else None
    )
    sync_health = "healthy" if runtime_synced_at is not None else "degraded"
    policy_bundle_ack = runner._validated_policy_bundle_acknowledgement(
        store,
        device_id=resolved_device_id,
        device_name=resolved_device_name,
    )
    context: dict[str, object] = {
        "deviceId": resolved_device_id,
        "deviceName": resolved_device_name,
        "harness": runtime_harness or "hol-guard",
        "localGuardOnlineAt": local_guard_online_at,
        "syncHealth": sync_health,
    }
    if isinstance(policy_bundle_ack, dict) and policy_bundle_ack:
        acknowledgement_key = (
            "policyBundleAcknowledgementV2"
            if policy_bundle_ack.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT
            else "policyBundleAcknowledgement"
        )
        context[acknowledgement_key] = policy_bundle_ack
    if runtime_synced_at is not None:
        context["lastRuntimeSyncAt"] = runtime_synced_at
    return context


def _persist_receipt_sync_cursor(
    *,
    store: runner.GuardStore,
    latest_uploaded_rowid: int | None,
    synced_at: str,
) -> None:
    if latest_uploaded_rowid is None:
        return
    payload: dict[str, object] = {
        "last_rowid": latest_uploaded_rowid,
        "synced_at": synced_at,
    }
    store.set_sync_payload("receipt_sync_cursor", payload, synced_at)
