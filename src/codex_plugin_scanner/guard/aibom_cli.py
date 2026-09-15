"""AIBOM CLI helpers for status, export, inventory enrichment, and cloud sync."""

from __future__ import annotations

import importlib
import os
import time as time
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..version import __version__ as __version__
from .adapters.base import HarnessContext as HarnessContext
from .aibom_cloud_contract import cloud_syncable_snapshots as cloud_syncable_snapshots
from .aibom_cloud_contract import inventory_snapshot_event as _inventory_snapshot_event
from .aibom_collection import _resolve_trust_attestation_context as _resolve_trust_attestation_context
from .aibom_collection import collect_aibom_snapshots as collect_aibom_snapshots
from .aibom_commands import build_aibom_export_payload as build_aibom_export_payload
from .aibom_commands import build_aibom_status_payload as build_aibom_status_payload
from .aibom_commands import build_inventory_json_payload as build_inventory_json_payload
from .aibom_commands import sync_aibom_snapshots_if_due as sync_aibom_snapshots_if_due
from .aibom_content_upload import GuardAibomPrimaryContentSource as GuardAibomPrimaryContentSource
from .aibom_content_upload import empty_content_upload_summary as empty_content_upload_summary
from .aibom_content_upload import merge_content_upload_summary as merge_content_upload_summary
from .aibom_content_upload import primary_content_sources_from_artifacts as primary_content_sources_from_artifacts
from .aibom_content_upload import upload_primary_content_sources as upload_primary_content_sources
from .aibom_models import _AIBOM_AUTO_SYNC_INTERVAL_SECONDS as _AIBOM_AUTO_SYNC_INTERVAL_SECONDS
from .aibom_models import _AIBOM_CLOUD_SYNC_OPTIONS as _AIBOM_CLOUD_SYNC_OPTIONS
from .aibom_models import _AIBOM_EMPTY_SYNC_RETRY_SECONDS as _AIBOM_EMPTY_SYNC_RETRY_SECONDS
from .aibom_models import _AIBOM_GUARD_EVENTS_BACKOFF_KEY as _AIBOM_GUARD_EVENTS_BACKOFF_KEY
from .aibom_models import _AIBOM_GUARD_EVENTS_BACKOFF_MINUTES as _AIBOM_GUARD_EVENTS_BACKOFF_MINUTES
from .aibom_models import _AIBOM_MAX_REQUEST_BODY_BYTES as _AIBOM_MAX_REQUEST_BODY_BYTES
from .aibom_models import _AIBOM_SYNC_BATCH_SIZE as _AIBOM_SYNC_BATCH_SIZE
from .aibom_models import AibomCliOptions as AibomCliOptions
from .aibom_models import AibomExportFormat as AibomExportFormat
from .aibom_reporting import _aggregate_redaction_report as _aggregate_redaction_report
from .aibom_reporting import _aibom_connection_status as _aibom_connection_status
from .aibom_reporting import _artifact_rows_from_store as _artifact_rows_from_store
from .aibom_reporting import _metadata_lookup_from_snapshots as _metadata_lookup_from_snapshots
from .aibom_reporting import _redact_inventory_store_item as _redact_inventory_store_item
from .aibom_reporting import _render_aibom_markdown as _render_aibom_markdown
from .aibom_reporting import _store_only_artifact_metadata_extensions as _store_only_artifact_metadata_extensions
from .aibom_reporting import _store_row_config_path as _store_row_config_path
from .aibom_reporting import summarize_aibom_drift as summarize_aibom_drift
from .aibom_reporting import summarize_aibom_layers as summarize_aibom_layers
from .aibom_reporting import summarize_aibom_trust as summarize_aibom_trust
from .aibom_sync import _accepted_snapshot_ids as _accepted_snapshot_ids
from .aibom_sync import _batch_inventory_events as _batch_inventory_events
from .aibom_sync import _inventory_events_request_body as _inventory_events_request_body
from .aibom_sync import _sync_summary as _sync_summary
from .aibom_sync import _sync_timestamp_from_payload as _sync_timestamp_from_payload
from .aibom_trust_metadata import apply_local_trust_metadata as apply_local_trust_metadata
from .inventory_cisco import run_cisco_inventory_scans as run_cisco_inventory_scans
from .inventory_contract import GuardAgentInventorySnapshot as GuardAgentInventorySnapshot
from .inventory_contract import cloud_inventory_artifacts_from_detection as cloud_inventory_artifacts_from_detection
from .inventory_contract import extract_aibom_metadata_extensions as extract_aibom_metadata_extensions
from .inventory_contract import inventory_snapshot_from_detection as inventory_snapshot_from_detection
from .inventory_contract import redact_local_path as redact_local_path
from .inventory_contract import serialize_inventory_snapshot as serialize_inventory_snapshot
from .store import GuardStore as GuardStore


def _runner_module():
    """Load the runtime lazily to retain the CLI dependency and testing interface."""
    return importlib.import_module(".runtime.runner", __package__)


def detect_all(context: HarnessContext):
    """Delegate native discovery through the current runtime module."""
    return importlib.import_module(".consumer", __package__).detect_all(context)


# Guard Cloud queues large projection work; preserve snapshot replacement semantics in transit.


def _aware_utc_timestamp(value: str) -> datetime:
    """Normalize a recorded timestamp to timezone-aware UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _aibom_sync_is_due(
    store: Any,
    *,
    generated_at: str,
    min_interval_seconds: int,
) -> bool:
    """Apply freshness and empty-inventory retry intervals to prior sync state."""
    prior = store.get_sync_payload("aibom_sync_summary")
    if not isinstance(prior, dict):
        return True
    if prior.get("synced") is not True:
        return True
    synced_at = prior.get("synced_at")
    if not isinstance(synced_at, str) or not synced_at.strip():
        return True
    retry_interval = min_interval_seconds
    if prior.get("snapshots") == 0:
        retry_interval = min(min_interval_seconds, _AIBOM_EMPTY_SYNC_RETRY_SECONDS)
    try:
        last_sync = _aware_utc_timestamp(synced_at)
        now = _aware_utc_timestamp(generated_at)
        elapsed = (now - last_sync).total_seconds()
    except (ValueError, OverflowError, TypeError):
        return True
    return elapsed >= retry_interval


def _aibom_guard_events_endpoint_unavailable_recently(store: Any) -> bool:
    """Respect the recorded missing-endpoint backoff interval."""
    summary = store.get_sync_payload(_AIBOM_GUARD_EVENTS_BACKOFF_KEY)
    if not isinstance(summary, dict):
        return False
    if summary.get("sync_reason") != "guard_events_endpoint_unavailable":
        return False
    synced_at = summary.get("synced_at")
    if not isinstance(synced_at, str) or not synced_at.strip():
        return False
    try:
        parsed = _aware_utc_timestamp(synced_at)
    except (ValueError, OverflowError, TypeError):
        return False
    return datetime.now(timezone.utc) - parsed < timedelta(minutes=_AIBOM_GUARD_EVENTS_BACKOFF_MINUTES)


def _resolve_operator_home_dir(home_dir: Path | None = None) -> Path:
    """Resolve an explicitly configured operator home or the normal user home."""
    if home_dir is not None:
        return home_dir.expanduser().resolve()
    home_env = os.environ.get("HOME")
    if home_env:
        return Path(home_env).expanduser().resolve()
    return Path.home().resolve()


def sync_aibom_snapshots(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    auth_context: dict[str, object] | None = None,
    expected_workspace_id: str | None = None,
) -> dict[str, object]:
    """Sync compatible snapshots and upload content only after cloud acknowledgment."""
    runner = _runner_module()
    guard_sync_not_configured_error = runner.GuardSyncNotConfiguredError

    with store.hold_oauth_credential_lock():
        current_workspace_id = store.get_cloud_workspace_id()
        if current_workspace_id is None:
            raise guard_sync_not_configured_error(
                "Guard Cloud workspace is not configured. Run `hol-guard connect` first."
            )
        if expected_workspace_id is not None and current_workspace_id != expected_workspace_id:
            raise ValueError("Guard Cloud workspace changed before AIBOM inventory sync.")
        workspace_id = expected_workspace_id or current_workspace_id
        trust_attestation_context = _resolve_trust_attestation_context(
            store,
            generated_at=generated_at,
            include_upload_session_bindings=True,
            workspace_id=workspace_id,
        )

    resolved_options = options or _AIBOM_CLOUD_SYNC_OPTIONS
    primary_content_sources: list[GuardAibomPrimaryContentSource] = []
    snapshots = collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=resolved_options,
        trust_attestation_context=trust_attestation_context,
        primary_content_sources=primary_content_sources,
    )
    snapshots = cloud_syncable_snapshots(snapshots)
    cloud_snapshot_ids = {snapshot.snapshot_id for snapshot in snapshots}
    primary_content_sources = [source for source in primary_content_sources if source.snapshot_id in cloud_snapshot_ids]
    if not snapshots:
        synced_at = generated_at
        summary: dict[str, object] = {
            "synced": True,
            "synced_at": synced_at,
            "snapshots": 0,
            "accepted": 0,
            "message": "No cloud-compatible harness snapshots were available to sync.",
        }
        store.set_sync_payload("aibom_sync_summary", summary, synced_at)
        return summary

    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    sync_url = runner._guard_events_sync_url(str(resolved_auth_context["sync_url"]))
    events = [
        _inventory_snapshot_event(
            snapshot=snapshot,
            workspace_id=workspace_id,
            device_id=trust_attestation_context.get("deviceId"),
            generated_at=generated_at,
        )
        for snapshot in snapshots
    ]
    event_batches, oversized_events = _batch_inventory_events(events)
    content_sources_by_snapshot: dict[str, tuple[GuardAibomPrimaryContentSource, ...]] = {}
    for snapshot in snapshots:
        content_sources_by_snapshot[snapshot.snapshot_id] = tuple(
            source for source in primary_content_sources if source.snapshot_id == snapshot.snapshot_id
        )
    content_upload_summary = empty_content_upload_summary()
    content_uploaded_snapshot_ids: set[str] = set()
    oversized_statuses: list[dict[str, object]] = [
        {
            "eventId": str(event.get("eventId") or ""),
            "status": "rejected",
            "reason": "snapshot_too_large",
        }
        for event in oversized_events
    ]
    if not event_batches:
        failure_summary: dict[str, object] = {
            "synced": False,
            "synced_at": generated_at,
            "snapshots": len(snapshots),
            "accepted": 0,
            "rejected": len(oversized_events),
            "statuses": oversized_statuses,
            "partial": False,
            "reason": "snapshot_too_large",
            "error": "Guard Cloud AIBOM sync failed because an inventory snapshot exceeds the request limit.",
            "content_upload": content_upload_summary,
        }
        store.set_sync_payload("aibom_sync_summary", failure_summary, generated_at)
        return failure_summary
    total_accepted = 0
    total_rejected = len(oversized_events)
    all_statuses: list[dict[str, object]] = oversized_statuses
    synced_at = generated_at
    batches_sent = 0
    events_sent = 0
    syncable_event_count = sum(len(batch) for batch in event_batches)

    for batch in event_batches:
        body = _inventory_events_request_body(batch)
        request = runner._guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        auth_refresh_retried = False
        try:
            payload = runner._urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=90,
                retry_timeout_seconds=120,
            )
        except urllib.error.HTTPError as error:
            if error.code == 401 and not auth_refresh_retried:
                auth_refresh_retried = True
                resolved_auth_context = runner._resolve_guard_sync_auth_context(store, force_refresh=True)
                request = runner._guard_sync_request(
                    resolved_auth_context,
                    request_url=sync_url,
                    method="POST",
                    data=body,
                    extra_headers=None,
                )
                payload = runner._urlopen_json_with_timeout_retry(
                    request=request,
                    timeout_seconds=90,
                    retry_timeout_seconds=120,
                )
            elif error.code == 404:
                synced_at = generated_at
                remaining_events = syncable_event_count - events_sent
                store.set_sync_payload(
                    _AIBOM_GUARD_EVENTS_BACKOFF_KEY,
                    {
                        "synced_at": synced_at,
                        "events": remaining_events,
                        "accepted": total_accepted,
                        "skipped": remaining_events,
                        "sync_skipped": True,
                        "sync_reason": "guard_events_endpoint_unavailable",
                    },
                    synced_at,
                )
                summary: dict[str, object] = {
                    "synced": False,
                    "synced_at": synced_at,
                    "snapshots": len(snapshots),
                    "accepted": total_accepted,
                    "rejected": total_rejected,
                    "statuses": all_statuses,
                    "partial": batches_sent > 0 or bool(oversized_events),
                    "reason": "guard_events_endpoint_unavailable",
                    "content_upload": content_upload_summary,
                }
                if batches_sent == 0:
                    summary["skipped"] = True
                store.set_sync_payload("aibom_sync_summary", summary, synced_at)
                return summary
            failure_summary: dict[str, object] = {
                "synced": False,
                "synced_at": synced_at,
                "snapshots": len(snapshots),
                "accepted": total_accepted,
                "rejected": total_rejected,
                "statuses": all_statuses,
                "partial": batches_sent > 0 or bool(oversized_events),
                "error": "Guard Cloud AIBOM sync failed due to an HTTP error.",
                "content_upload": content_upload_summary,
            }
            store.set_sync_payload("aibom_sync_summary", failure_summary, synced_at)
            raise RuntimeError("Guard Cloud AIBOM sync failed due to an HTTP error.") from error
        except OSError as error:
            failure_summary = {
                "synced": False,
                "synced_at": synced_at,
                "snapshots": len(snapshots),
                "accepted": total_accepted,
                "rejected": total_rejected,
                "statuses": all_statuses,
                "partial": batches_sent > 0 or bool(oversized_events),
                "error": "Guard Cloud AIBOM sync failed due to a network error.",
                "content_upload": content_upload_summary,
            }
            store.set_sync_payload("aibom_sync_summary", failure_summary, synced_at)
            raise RuntimeError("Guard Cloud AIBOM sync failed due to a network error.") from error
        batches_sent += 1
        events_sent += len(batch)
        batch_accepted = payload.get("accepted")
        if isinstance(batch_accepted, int):
            total_accepted += batch_accepted
        batch_rejected = payload.get("rejected")
        if isinstance(batch_rejected, int):
            total_rejected += batch_rejected
        batch_statuses = payload.get("statuses")
        if isinstance(batch_statuses, list):
            all_statuses.extend(s for s in batch_statuses if isinstance(s, dict))
        batch_synced_at = _sync_timestamp_from_payload(payload)
        if isinstance(batch_synced_at, str):
            synced_at = batch_synced_at
        for snapshot_id in _accepted_snapshot_ids(batch, payload):
            if snapshot_id in content_uploaded_snapshot_ids:
                continue
            sources = content_sources_by_snapshot.get(snapshot_id, ())
            upload_summary, resolved_auth_context = upload_primary_content_sources(
                store,
                runner,
                resolved_auth_context,
                sources=sources,
                workspace_id=workspace_id,
            )
            merge_content_upload_summary(content_upload_summary, upload_summary)
            content_uploaded_snapshot_ids.add(snapshot_id)
    content_eligible_value = content_upload_summary.get("eligible")
    content_stored_value = content_upload_summary.get("stored")
    content_eligible = content_eligible_value if isinstance(content_eligible_value, int) else 0
    content_stored = content_stored_value if isinstance(content_stored_value, int) else 0
    content_upload_complete = content_stored == content_eligible
    summary: dict[str, object] = {
        "synced": content_upload_complete,
        "synced_at": synced_at,
        "snapshots": len(snapshots),
        "accepted": total_accepted,
        "rejected": total_rejected,
        "statuses": all_statuses,
        "content_upload": content_upload_summary,
        "content_upload_complete": content_upload_complete,
    }
    if oversized_events:
        summary["partial"] = True
        summary["reason"] = "snapshot_too_large"
    if not content_upload_complete:
        summary["partial"] = True
        summary["reason"] = "content_upload_incomplete"
    store.set_sync_payload("aibom_sync_summary", summary, synced_at)
    return summary
