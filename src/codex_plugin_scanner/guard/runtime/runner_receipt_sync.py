"""Receipt sync.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def sync_receipts(
    store: runner.GuardStore,
    *,
    persist_sync_summary: bool = True,
    persist_connect_state: bool = True,
    auth_context: dict[str, object] | None = None,
    home_dir: runner.Path | None = None,
    workspace_dir: runner.Path | None = None,
    include_aibom: bool = False,
    force_aibom: bool = False,
    managed_controls_publish: (
        runner.Callable[[runner.ExtensionControlAuthorityView, runner.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    sync_url = runner._normalized_receipts_sync_url(
        runner._validate_guard_sync_url(runner._auth_context_sync_url(resolved_auth_context))
    )
    local_guard_online_at = runner._now()
    redaction_level = runner._resolve_cloud_receipt_redaction_level(store)
    runner._ensure_cloud_review_privacy_projection(store, level=redaction_level, synced_at=local_guard_online_at)
    runner._ensure_relaxed_receipt_redaction_resync(store, level=redaction_level, synced_at=local_guard_online_at)
    prior_receipt_cursor = runner._receipt_sync_cursor_rowid(store)
    receipts = runner._receipt_sync_rows_for_upload(store, cursor_rowid=prior_receipt_cursor)
    cursor_receipt_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    receipts, command_detail_backfill_marker = runner._receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=receipts,
        redaction_level=redaction_level,
        synced_at=local_guard_online_at,
    )
    inventory = store.list_inventory()
    payload: dict[str, object] = {}
    receipts_stored_total = 0
    advisories_payload: list[dict[str, object]] = []
    policy_bundle_payload: dict[str, object] | None = None
    policy_bundle_sync_payload: dict[str, object] | None = None
    policy_bundle_delivery_payload: object = None
    policy_bundle_delivery_field_provided = False
    policy_bundle_field_provided = False
    policy_bundle_field_malformed = False
    alert_preferences_payload: dict[str, object] | None = None
    review_verification_keys_payload: object | None = None
    remote_decisions: set[runner.PolicyDecision] = set()
    device_id, device_name = runner._guard_device_metadata(store)
    sync_context = runner._receipt_sync_context(
        store=store,
        local_guard_online_at=local_guard_online_at,
        device_id=device_id,
        device_name=device_name,
    )
    latest_uploaded_rowid: int | None = None
    auth_refresh_retried = False
    persisted_command_detail_backfill_marker = command_detail_backfill_marker
    for receipt_batch in runner._iter_receipt_sync_batches(receipts):
        body = runner.json.dumps(
            {
                "receipts": runner._cloud_sync_receipts_payload(
                    receipt_batch,
                    device_id=device_id,
                    device_name=device_name,
                    redaction_level=redaction_level,
                ),
                "syncContext": sync_context,
            }
        ).encode("utf-8")
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
            if error.code == 401:
                if auth_context is None and not auth_refresh_retried:
                    auth_refresh_retried = True
                    resolved_auth_context = runner._resolve_guard_sync_auth_context(store, force_refresh=True)
                    sync_url = runner._normalized_receipts_sync_url(
                        runner._validate_guard_sync_url(runner._auth_context_sync_url(resolved_auth_context))
                    )
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
                    except runner.urllib.error.HTTPError as retry_error:
                        if retry_error.code == 401:
                            raise runner.GuardSyncAuthorizationExpiredError(
                                runner._guard_oauth_reauthorization_message()
                            ) from retry_error
                        if retry_error.code == 403:
                            _is_plan, _msg = runner._check_plan_restriction_403(retry_error)
                            if _is_plan:
                                raise runner.GuardSyncNotAvailableError(_msg) from retry_error
                            raise RuntimeError(_msg) from retry_error
                        raise RuntimeError(runner._sync_http_error_message(retry_error)) from retry_error
                    except OSError as retry_error:
                        raise RuntimeError(runner._sync_url_error_message(retry_error)) from retry_error
                else:
                    raise runner.GuardSyncAuthorizationExpiredError(
                        runner._guard_oauth_reauthorization_message()
                    ) from error
            elif error.code == 403:
                _is_plan, _msg = runner._check_plan_restriction_403(error)
                if _is_plan:
                    raise runner.GuardSyncNotAvailableError(_msg) from error
                raise RuntimeError(_msg) from error
            else:
                raise RuntimeError(runner._sync_http_error_message(error)) from error
        except OSError as error:
            raise RuntimeError(runner._sync_url_error_message(error)) from error
        cursor_batch_rowids = runner._receipt_sync_cursor_rowids_from_batch(
            receipt_batch,
            cursor_receipt_ids=cursor_receipt_ids,
        )
        for rowid in cursor_batch_rowids:
            if isinstance(rowid, int) and (latest_uploaded_rowid is None or rowid > latest_uploaded_rowid):
                latest_uploaded_rowid = rowid
        batch_synced_at = runner._sync_timestamp(payload)
        updated_command_detail_backfill_marker = runner._advance_command_detail_backfill_marker(
            persisted_command_detail_backfill_marker,
            receipt_batch=receipt_batch,
            synced_at=batch_synced_at,
        )
        if updated_command_detail_backfill_marker is not None:
            persisted_command_detail_backfill_marker = updated_command_detail_backfill_marker
            store.set_sync_payload(
                runner._RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
                persisted_command_detail_backfill_marker,
                batch_synced_at,
            )
        if latest_uploaded_rowid is not None:
            runner._persist_receipt_sync_cursor(
                store=store,
                latest_uploaded_rowid=latest_uploaded_rowid,
                synced_at=batch_synced_at,
            )
        batch_receipts_stored = payload.get("receiptsStored")
        if isinstance(batch_receipts_stored, int):
            receipts_stored_total += batch_receipts_stored
        advisories = payload.get("advisories")
        if isinstance(advisories, list):
            advisories_payload.extend(item for item in advisories if isinstance(item, dict))
        if "policyBundle" in payload:
            policy_bundle_field_provided = True
            policy_bundle = payload.get("policyBundle")
            if isinstance(policy_bundle, dict):
                if policy_bundle or policy_bundle_payload is None:
                    policy_bundle_payload = policy_bundle
                    policy_bundle_sync_payload = payload
                    policy_bundle_delivery_field_provided = "policyBundleDelivery" in payload
                    policy_bundle_delivery_payload = payload.get("policyBundleDelivery")
            else:
                policy_bundle_field_malformed = True
        alert_preferences = payload.get("alertPreferences")
        if isinstance(alert_preferences, dict) and (alert_preferences or alert_preferences_payload is None):
            alert_preferences_payload = alert_preferences
        if "reviewVerificationKeys" in payload:
            review_verification_keys_payload = payload.get("reviewVerificationKeys")
    now = runner._sync_timestamp(payload)
    aibom_context: dict[str, object] = {}
    if home_dir is not None:
        aibom_context["home_dir"] = str(home_dir)
    if workspace_dir is not None:
        aibom_context["workspace_dir"] = str(workspace_dir)
        workspace_id = store.get_cloud_workspace_id()
        if workspace_id is not None:
            aibom_context["workspace_id"] = workspace_id
    if aibom_context:
        store.set_sync_payload("aibom_inventory_context", aibom_context, now)
    if persisted_command_detail_backfill_marker is not None:
        store.set_sync_payload(
            runner._RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
            persisted_command_detail_backfill_marker,
            now,
        )
    persisted_cursor_rowid = latest_uploaded_rowid if latest_uploaded_rowid is not None else prior_receipt_cursor
    runner._persist_receipt_sync_cursor(
        store=store,
        latest_uploaded_rowid=persisted_cursor_rowid,
        synced_at=now,
    )
    deduped_advisories = runner._dedupe_sync_payload_items(advisories_payload)
    # Top-level ``policy``, ``teamPolicyPack``, and ``exceptions`` fields are
    # legacy unsigned siblings. They may be present on an authenticated HTTPS
    # response, but they are not covered by the pinned policy-bundle signature
    # and therefore cannot be persisted or materialized as local authority.
    # Only decisions and exceptions inside a validated signed bundle are used.
    deduped_exceptions: list[dict[str, object]] = []
    advisories_stored = 0
    if deduped_advisories:
        advisories_stored = store.cache_advisories(deduped_advisories, now)
    (
        cloud_workspace_id,
        cloud_exception_items,
        remote_policies_stored,
        remote_policy_sync_blocked,
    ) = runner._activate_receipt_sync_policy(
        store=store,
        device_id=device_id,
        device_name=device_name,
        now=now,
        policy_bundle_field_provided=policy_bundle_field_provided,
        policy_bundle_field_malformed=policy_bundle_field_malformed,
        policy_bundle_payload=policy_bundle_payload,
        policy_bundle_sync_payload=policy_bundle_sync_payload,
        policy_bundle_delivery_field_provided=policy_bundle_delivery_field_provided,
        policy_bundle_delivery_payload=policy_bundle_delivery_payload,
        alert_preferences_payload=alert_preferences_payload,
        remote_decisions=remote_decisions,
        managed_controls_publish=managed_controls_publish,
    )
    if review_verification_keys_payload is not None:
        if cloud_workspace_id is None:
            raise RuntimeError("review_verification_keys_workspace_missing")
        review_verification_keys = runner.validated_review_verification_keys_from_sync(
            review_verification_keys_payload,
            store=store,
            workspace_id=cloud_workspace_id,
        )
        store.set_sync_payload(
            "guard_review_verification_keyring",
            [key.to_dict() for key in review_verification_keys],
            now,
        )
    runner._record_synced_alert_events(
        store=store,
        advisories=deduped_advisories,
        alert_preferences=alert_preferences_payload,
        exceptions=deduped_exceptions,
        now=now,
    )
    try:
        pain_signals_uploaded = runner.sync_pain_signals(store, auth_context=resolved_auth_context)
    except RuntimeError as pain_signal_error:
        if "429" in str(pain_signal_error):
            pain_signals_uploaded = 0
        else:
            raise
    value_metrics = runner._build_value_metrics(store)
    weekly_digest = runner._build_weekly_firewall_digest(metrics=value_metrics, now=now)
    summary: dict[str, object] = {
        "synced_at": payload.get("syncedAt"),
        "receipts_stored": receipts_stored_total,
        "advisories_stored": advisories_stored,
        "exceptions_stored": len(deduped_exceptions),
        "cloud_exceptions_stored": len(cloud_exception_items),
        "remote_policies_stored": remote_policies_stored,
        "pain_signals_uploaded": pain_signals_uploaded,
        "receipts": len(receipts),
        "receipt_cursor_rowid": persisted_cursor_rowid,
        "receipt_cursor_backfill": bool(
            prior_receipt_cursor is not None
            and len(receipts) > 0
            and not any(
                (receipt_rowid := runner._int_value(item.get("receipt_rowid"))) is not None
                and receipt_rowid > prior_receipt_cursor
                for item in receipts
            )
        ),
        "inventory": 0,
        "inventory_tracked": len(inventory),
        "value_metrics": value_metrics,
        "weekly_digest": weekly_digest,
    }
    if remote_policy_sync_blocked:
        summary["remote_policy_sync_blocked"] = True
    summary["guard_events_v1"] = runner.sync_guard_events(store, auth_context=resolved_auth_context)
    if include_aibom:
        from ..aibom_cli import sync_aibom_snapshots_if_due

        summary["aibom_inventory"] = sync_aibom_snapshots_if_due(
            store,
            generated_at=now,
            auth_context=resolved_auth_context,
            force=force_aibom,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    else:
        summary["aibom_inventory"] = {
            "synced": False,
            "skipped": True,
            "reason": "background_deferred",
            "message": (
                "AIBOM inventory refresh is deferred to the Guard daemon background lane; "
                "run hol-guard sync --deep to refresh now."
            ),
        }
    if persist_sync_summary:
        store.set_sync_payload("sync_summary", summary, now)
    if persist_connect_state:
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=now)
    return summary
