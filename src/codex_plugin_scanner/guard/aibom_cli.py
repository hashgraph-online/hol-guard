"""AIBOM CLI helpers for status, export, inventory enrichment, and cloud sync."""

from __future__ import annotations

import importlib
import json
import os
import time
import urllib.error
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

from ..version import __version__
from .adapters.base import HarnessContext
from .aibom_trust_metadata import apply_local_trust_metadata
from .inventory_cisco import run_cisco_inventory_scans
from .inventory_contract import (
    GuardAgentInventorySnapshot,
    extract_aibom_metadata_extensions,
    inventory_snapshot_from_detection,
    redact_local_path,
    serialize_inventory_snapshot,
)
from .store import GuardStore

AibomExportFormat = Literal["json", "markdown"]


@dataclass(frozen=True, slots=True)
class AibomCliOptions:
    include_symlinks: bool = True
    follow_unsafe_symlinks: bool = False
    cisco_skill_scan: str = "off"
    cisco_mcp_scan: str = "off"
    cisco_timeout_seconds: float | None = None


_AIBOM_CLOUD_SYNC_OPTIONS = AibomCliOptions(
    cisco_skill_scan="auto",
    cisco_mcp_scan="auto",
    cisco_timeout_seconds=30.0,
)


def _runner_module():
    return importlib.import_module(".runtime.runner", __package__)


def detect_all(context: HarnessContext):
    return importlib.import_module(".consumer", __package__).detect_all(context)


def collect_aibom_snapshots(
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    trust_attestation_context: dict[str, object] | None = None,
) -> tuple[GuardAgentInventorySnapshot, ...]:
    resolved = options or AibomCliOptions()
    snapshots: list[GuardAgentInventorySnapshot] = []
    remaining_cisco_timeout_seconds = resolved.cisco_timeout_seconds
    for detection in detect_all(context):
        if not detection.installed and not detection.artifacts:
            continue
        cisco_started = time.monotonic()
        cisco_runs = run_cisco_inventory_scans(
            harness=str(getattr(detection, "harness", "unknown")),
            context=context,
            detection=detection,
            mcp_mode=resolved.cisco_mcp_scan,
            skill_mode=resolved.cisco_skill_scan,
            timeout_seconds=remaining_cisco_timeout_seconds,
        )
        if remaining_cisco_timeout_seconds is not None:
            remaining_cisco_timeout_seconds = max(
                remaining_cisco_timeout_seconds - max(time.monotonic() - cisco_started, 0.0),
                0.0,
            )
        snapshots.append(
            inventory_snapshot_from_detection(
                detection,
                generated_at=generated_at,
                home_dir=context.home_dir,
                workspace_dir=context.workspace_dir,
                cisco_runs=cisco_runs,
                include_symlinks=resolved.include_symlinks,
                follow_unsafe_symlinks=resolved.follow_unsafe_symlinks,
                trust_attestation_context=trust_attestation_context,
            )
        )
    return tuple(snapshots)


def _resolve_trust_attestation_context(
    store: GuardStore,
    *,
    generated_at: str,
    include_upload_session_bindings: bool = False,
) -> dict[str, object]:
    from .runtime.trust_attestation import (
        resolve_guard_oauth_trust_attestation_signing_config,
        resolve_trust_attestation_signing_config,
        trust_attestation_v2_enabled,
    )

    oauth_credentials = store.get_oauth_local_credentials(allow_primary=True)
    signing_config = resolve_guard_oauth_trust_attestation_signing_config(oauth_credentials)
    if signing_config is None:
        # Only auto-generate persistent key during sync (not read-only status/export/inventory)
        guard_home = store.guard_home if include_upload_session_bindings else None
        signing_config = resolve_trust_attestation_signing_config(guard_home=guard_home)
    enable_v2 = trust_attestation_v2_enabled()
    installation_id = store.get_or_create_installation_id() if enable_v2 else None
    context: dict[str, object] = {
        "analyzerId": "hol-guard" if enable_v2 else None,
        "analyzerSpecVersion": "guard-aibom-trust-spec.v1" if enable_v2 else None,
        "analyzerVersion": __version__ if enable_v2 else None,
        "challengeId": None,
        "deviceId": installation_id,
        "expiresAt": None,
        "installationId": installation_id,
        "nonce": None,
        "policyVersion": "guard-aibom-trust-policy.v1" if enable_v2 else None,
        "sequence": None,
        "signingConfig": signing_config,
        "uploadId": None,
        "workspaceId": store.get_cloud_workspace_id() if enable_v2 else None,
    }
    if not enable_v2 or not include_upload_session_bindings:
        return context
    try:
        expires_at = (_aware_utc_timestamp(generated_at) + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    except (OverflowError, TypeError, ValueError):
        expires_at = None
    context.update(
        {
            "challengeId": f"guard-aibom-challenge-{uuid.uuid4().hex}",
            "expiresAt": expires_at,
            "nonce": uuid.uuid4().hex,
            "sequence": store.next_aibom_trust_attestation_sequence(generated_at),
            "uploadId": f"guard-aibom-upload-{uuid.uuid4().hex}",
        }
    )
    return context


def build_inventory_json_payload(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=_resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots)
    items: list[dict[str, object]] = []
    for item in store.list_inventory():
        enriched = _redact_inventory_store_item(item, home_dir=context.home_dir)
        artifact_id = str(item.get("artifact_id") or "")
        harness = str(item.get("harness") or "")
        extensions = metadata_by_artifact.get((harness, artifact_id))
        config_path = _store_row_config_path(item) if str(item.get("artifact_type") or "") == "skill_file" else None
        config_path_exists = config_path.exists() if config_path is not None else None
        if not extensions:
            extensions = _store_only_artifact_metadata_extensions(
                enriched,
                context=context,
                generated_at=generated_at,
                config_path=config_path,
                config_path_exists=config_path_exists,
            )
            if config_path_exists is False:
                enriched["present"] = False
        if extensions:
            enriched.update(extensions)
        items.append(enriched)
    redaction_report = _aggregate_redaction_report(snapshots)
    return {
        "generated_at": generated_at,
        "items": items,
        "snapshots": [serialize_inventory_snapshot(snapshot) for snapshot in snapshots],
        "redaction_report": redaction_report,
    }


def build_aibom_status_payload(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=_resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    sync_summary = _sync_summary(store)
    layer_summary, trust_summary, drift_summary = summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    return {
        "generated_at": generated_at,
        "status": _aibom_connection_status(store),
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": _aggregate_redaction_report(snapshots),
        "last_sync_at": sync_summary.get("synced_at"),
        "snapshot_count": len(snapshots),
        "artifact_inventory_count": len(store.list_inventory()),
    }


def build_aibom_export_payload(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    export_format: AibomExportFormat = "json",
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=_resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    serialized_snapshots = [serialize_inventory_snapshot(snapshot) for snapshot in snapshots]
    artifacts = _artifact_rows_from_store(store, snapshots, context=context, generated_at=generated_at)
    layer_summary, trust_summary, drift_summary = summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    sync_summary = _sync_summary(store)
    payload: dict[str, object] = {
        "generated_at": generated_at,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "snapshots": serialized_snapshots,
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": _aggregate_redaction_report(snapshots),
        "last_sync_at": sync_summary.get("synced_at"),
    }
    if export_format == "markdown":
        payload["markdown"] = _render_aibom_markdown(payload)
    return payload


_AIBOM_AUTO_SYNC_INTERVAL_SECONDS = 15 * 60  # 15 min — stale AIBOM data undermines trust surfaces
_AIBOM_EMPTY_SYNC_RETRY_SECONDS = 2 * 60
_AIBOM_GUARD_EVENTS_BACKOFF_KEY = "aibom_guard_events_backoff"
_AIBOM_GUARD_EVENTS_BACKOFF_MINUTES = 5  # matches _GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES
_AIBOM_SYNC_BATCH_SIZE = 3  # keep each POST under Cloudflare's 100s origin timeout
# Guard Cloud queues large projection work; preserve snapshot replacement semantics in transit.
_AIBOM_MAX_REQUEST_BODY_BYTES = 3_900_000  # stay below the portal's 4 MB request limit


def _aware_utc_timestamp(value: str) -> datetime:
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
    from datetime import timedelta

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
    if home_dir is not None:
        return home_dir.expanduser().resolve()
    home_env = os.environ.get("HOME")
    if home_env:
        return Path(home_env).expanduser().resolve()
    return Path.home().resolve()


def sync_aibom_snapshots_if_due(
    store: Any,
    *,
    generated_at: str,
    min_interval_seconds: int = _AIBOM_AUTO_SYNC_INTERVAL_SECONDS,
    force: bool = False,
    options: AibomCliOptions | None = None,
    auth_context: dict[str, object] | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    runner = _runner_module()
    guard_sync_not_configured_error = runner.GuardSyncNotConfiguredError

    if store.get_cloud_workspace_id() is None:
        return {"synced": False, "skipped": True, "reason": "not_configured"}
    if _aibom_guard_events_endpoint_unavailable_recently(store):
        return {
            "synced": False,
            "skipped": True,
            "reason": "guard_events_endpoint_unavailable",
        }
    if not force and not _aibom_sync_is_due(
        store,
        generated_at=generated_at,
        min_interval_seconds=min_interval_seconds,
    ):
        prior = store.get_sync_payload("aibom_sync_summary")
        return {
            "synced": False,
            "skipped": True,
            "reason": "recently_synced",
            "last_sync_at": prior.get("synced_at") if isinstance(prior, dict) else None,
        }
    context = HarnessContext(
        home_dir=_resolve_operator_home_dir(home_dir),
        workspace_dir=workspace_dir,
        guard_home=store.guard_home,
    )
    try:
        return sync_aibom_snapshots(
            store,
            context,
            generated_at=generated_at,
            options=options,
            auth_context=auth_context,
        )
    except guard_sync_not_configured_error:
        return {"synced": False, "skipped": True, "reason": "not_configured"}
    except ValueError as error:
        return {"synced": False, "error": str(error)}
    except (OSError, RuntimeError) as error:
        return {"synced": False, "error": str(error)}


def sync_aibom_snapshots(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    runner = _runner_module()
    guard_sync_not_configured_error = runner.GuardSyncNotConfiguredError

    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        raise guard_sync_not_configured_error("Guard Cloud workspace is not configured. Run `hol-guard connect` first.")

    resolved_options = options or _AIBOM_CLOUD_SYNC_OPTIONS
    trust_attestation_context = _resolve_trust_attestation_context(
        store,
        generated_at=generated_at,
        include_upload_session_bindings=True,
    )
    snapshots = collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=resolved_options,
        trust_attestation_context=trust_attestation_context,
    )
    if not snapshots:
        synced_at = generated_at
        summary: dict[str, object] = {
            "synced": True,
            "synced_at": synced_at,
            "snapshots": 0,
            "accepted": 0,
            "message": "No installed harness snapshots were available to sync.",
        }
        store.set_sync_payload("aibom_sync_summary", summary, synced_at)
        return summary

    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    sync_url = runner._guard_events_sync_url(str(resolved_auth_context["sync_url"]))
    events = [
        _inventory_snapshot_event(
            snapshot=snapshot,
            workspace_id=workspace_id,
            device_id=(
                str(trust_attestation_context["deviceId"])
                if isinstance(trust_attestation_context.get("deviceId"), str)
                else None
            ),
            generated_at=generated_at,
        )
        for snapshot in snapshots
    ]
    event_batches, oversized_events = _batch_inventory_events(events)
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
            }
            store.set_sync_payload("aibom_sync_summary", failure_summary, synced_at)
            raise RuntimeError("Guard Cloud AIBOM sync failed due to a network error.") from error
        batches_sent += 1  # noqa: SIM113
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
    summary: dict[str, object] = {
        "synced": True,
        "synced_at": synced_at,
        "snapshots": len(snapshots),
        "accepted": total_accepted,
        "rejected": total_rejected,
        "statuses": all_statuses,
    }
    if oversized_events:
        summary["partial"] = True
        summary["reason"] = "snapshot_too_large"
    store.set_sync_payload("aibom_sync_summary", summary, synced_at)
    return summary


def summarize_aibom_layers(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    generated_at: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    counts = {
        "instructions": 0,
        "skills": 0,
        "mcp": 0,
        "plugins": 0,
        "policies": 0,
        "findings": 0,
        "trust": 0,
        "sources": 0,
        "configSources": 0,
    }
    for snapshot in snapshots:
        counts["findings"] += len(snapshot.findings)
        counts["configSources"] += len(snapshot.sources)
        for item in snapshot.items:
            if item.item_kind in {"overlay", "prompt_pack"}:
                counts["instructions"] += 1
            elif item.item_kind == "skill":
                counts["skills"] += 1
            elif item.item_kind in {"mcp_server", "mcp_tool"}:
                counts["mcp"] += 1
            elif item.item_kind in {"plugin", "daemon_plugin"}:
                counts["plugins"] += 1
            elif item.item_kind == "policy":
                counts["policies"] += 1
            if isinstance(item.metadata.get("trustResolution"), dict):
                counts["trust"] += 1
            source_links = item.metadata.get("sourceLinks")
            source_of_truth = item.metadata.get("sourceOfTruth")
            if isinstance(source_links, list) and source_links:
                counts["sources"] += len(source_links)
            elif isinstance(source_of_truth, dict):
                counts["sources"] += 1
    drift = summarize_aibom_drift(snapshots)
    trust = summarize_aibom_trust(snapshots)
    layer_summary = {
        **counts,
        "driftCount": drift.get("total", 0),
        "highRiskCount": drift.get("high_risk", 0),
        "lowTrustCount": trust.get("low_trust", 0),
        "generatedAt": generated_at,
        "staleSnapshot": False,
    }
    return layer_summary, trust, drift


def summarize_aibom_trust(snapshots: tuple[GuardAgentInventorySnapshot, ...]) -> dict[str, object]:
    covered = 0
    eligible = 0
    low_trust = 0
    scores: list[int] = []
    for snapshot in snapshots:
        for item in snapshot.items:
            if item.item_kind not in {"skill", "plugin", "mcp_server"}:
                continue
            eligible += 1
            trust = item.metadata.get("trustResolution")
            if not isinstance(trust, dict):
                continue
            covered += 1
            score = trust.get("trustScore")
            if isinstance(score, int):
                scores.append(score)
                if score < 70:
                    low_trust += 1
    coverage_percent = round((covered / eligible) * 100) if eligible else 100
    average_score = round(sum(scores) / len(scores)) if scores else None
    return {
        "eligible": eligible,
        "covered": covered,
        "coverage_percent": coverage_percent,
        "low_trust": low_trust,
        "average_score": average_score,
    }


def summarize_aibom_drift(snapshots: tuple[GuardAgentInventorySnapshot, ...]) -> dict[str, object]:
    counts = {"new": 0, "changed": 0, "removed": 0, "unchanged": 0, "high_risk": 0}
    for snapshot in snapshots:
        for item in snapshot.items:
            state = item.drift_state
            if state in counts:
                counts[state] += 1
            if item.risk_level in {"critical", "high"}:
                counts["high_risk"] += 1
        for drift in snapshot.drift:
            state = drift.state
            if state in counts:
                counts[state] += 1
    total = counts["new"] + counts["changed"] + counts["removed"]
    return {
        "new": counts["new"],
        "changed": counts["changed"],
        "removed": counts["removed"],
        "unchanged": counts["unchanged"],
        "high_risk": counts["high_risk"],
        "total": total,
    }


def _metadata_lookup_from_snapshots(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> dict[tuple[str, str], dict[str, object]]:
    lookup: dict[tuple[str, str], dict[str, object]] = {}
    for snapshot in snapshots:
        harness = snapshot.agent_type
        for item in snapshot.items:
            extensions = extract_aibom_metadata_extensions(item.metadata)
            if not extensions:
                continue
            lookup[(harness, item.item_id)] = extensions
    return lookup


def _artifact_rows_from_store(
    store: Any,
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    context: HarnessContext,
    generated_at: str,
) -> list[dict[str, object]]:
    metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots)
    artifacts: list[dict[str, object]] = []
    for item in store.list_inventory():
        trust_verdict = str(item.get("last_policy_action") or "unknown")
        harness = str(item.get("harness") or "")
        artifact_id = str(item.get("artifact_id") or "")
        row: dict[str, object] = dict(item)
        row["trust_verdict"] = trust_verdict
        extensions = metadata_by_artifact.get((harness, artifact_id))
        config_path = _store_row_config_path(row) if str(row.get("artifact_type") or "") == "skill_file" else None
        config_path_exists = config_path.exists() if config_path is not None else None
        if not extensions:
            extensions = _store_only_artifact_metadata_extensions(
                row,
                context=context,
                generated_at=generated_at,
                config_path=config_path,
                config_path_exists=config_path_exists,
            )
            if config_path_exists is False:
                row["present"] = False
        if extensions:
            row.update(extensions)
        artifacts.append(row)
    return artifacts


def _store_row_config_path(row: dict[str, object]) -> Path | None:
    raw_config_path = row.get("config_path")
    if not isinstance(raw_config_path, str) or not raw_config_path.strip():
        return None
    return Path(raw_config_path).expanduser()


def _store_only_artifact_metadata_extensions(
    row: dict[str, object],
    *,
    context: HarnessContext,
    generated_at: str,
    config_path: Path | None,
    config_path_exists: bool | None,
) -> dict[str, object]:
    artifact_type = str(row.get("artifact_type") or "")
    if artifact_type != "skill_file":
        return {}
    if config_path is None or config_path_exists is not True:
        return {}
    artifact = SimpleNamespace(
        artifact_id=str(row.get("artifact_id") or ""),
        artifact_type=artifact_type,
        config_path=str(config_path),
        name=str(row.get("artifact_name") or row.get("artifact_id") or "skill_file"),
    )
    metadata = apply_local_trust_metadata(
        artifact,
        captured_at=generated_at,
        item_kind="skill",
        metadata={"artifactType": artifact_type},
        workspace_dir=context.workspace_dir,
    )
    return extract_aibom_metadata_extensions(metadata)


def _aggregate_redaction_report(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> dict[str, object]:
    redacted_fields: set[str] = set()
    raw_secrets = False
    symlink_items = 0
    for snapshot in snapshots:
        report = snapshot.redaction_report
        if report.get("rawSecretsIncluded") is True:
            raw_secrets = True
        fields = report.get("redactedFields")
        if isinstance(fields, (list, tuple)):
            redacted_fields.update(str(field) for field in fields)
        for item in snapshot.items:
            source_of_truth = item.metadata.get("sourceOfTruth")
            source_links = item.metadata.get("sourceLinks")
            if isinstance(source_of_truth, dict) or (isinstance(source_links, list) and source_links):
                symlink_items += 1
    return {
        "rawValuesIncluded": raw_secrets,
        "redactedFields": sorted(redacted_fields),
        "symlinkItems": symlink_items,
        "snapshots": len(snapshots),
    }


def _redact_inventory_store_item(
    item: dict[str, object],
    *,
    home_dir: Path,
) -> dict[str, object]:
    redacted = dict(item)
    config_path = item.get("config_path")
    if isinstance(config_path, str) and config_path:
        redacted["config_path"] = redact_local_path(Path(config_path), home_dir=home_dir)
    return redacted


def _aibom_connection_status(store: Any) -> str:
    if store.get_cloud_sync_profile() is None:
        return "not_connected"
    if store.get_cloud_workspace_id() is None:
        return "workspace_required"
    sync_summary = _sync_summary(store)
    if sync_summary.get("synced") is True and sync_summary.get("synced_at"):
        return "synced"
    return "sync_required"


def _sync_summary(store: Any) -> dict[str, object]:
    payload = store.get_sync_payload("aibom_sync_summary")
    return payload if isinstance(payload, dict) else {}


def _inventory_snapshot_event(
    *,
    snapshot: GuardAgentInventorySnapshot,
    workspace_id: str,
    device_id: str | None,
    generated_at: str,
) -> dict[str, object]:
    event_id = str(uuid.uuid4())
    return {
        "eventId": event_id,
        "eventType": "agent.inventory_snapshot",
        "idempotencyKey": snapshot.snapshot_id,
        "occurredAt": generated_at,
        "source": "edge",
        "workspaceId": workspace_id,
        "deviceId": device_id,
        "payload": {"snapshot": serialize_inventory_snapshot(snapshot)},
    }


def _inventory_events_request_body(events: list[dict[str, object]]) -> bytes:
    return json.dumps({"events": events}).encode("utf-8")


def _batch_inventory_events(
    events: list[dict[str, object]],
    *,
    max_batch_size: int = _AIBOM_SYNC_BATCH_SIZE,
    max_body_bytes: int = _AIBOM_MAX_REQUEST_BODY_BYTES,
) -> tuple[list[list[dict[str, object]]], list[dict[str, object]]]:
    """Batch whole inventory snapshots without changing replacement semantics."""
    if max_batch_size < 1 or max_body_bytes < 1:
        raise ValueError("AIBOM request batch limits must be positive.")

    batches: list[list[dict[str, object]]] = []
    oversized_events: list[dict[str, object]] = []
    batch: list[dict[str, object]] = []
    for event in events:
        if len(_inventory_events_request_body([event])) > max_body_bytes:
            oversized_events.append(event)
            continue

        candidate = [*batch, event]
        candidate_too_large = len(_inventory_events_request_body(candidate)) > max_body_bytes
        if batch and (len(candidate) > max_batch_size or candidate_too_large):
            batches.append(batch)
            batch = [event]
        else:
            batch = candidate

    if batch:
        batches.append(batch)
    return batches, oversized_events


def _sync_timestamp_from_payload(payload: dict[str, object]) -> str | None:
    for key in ("syncedAt", "synced_at", "acceptedAt"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _render_aibom_markdown(payload: dict[str, object]) -> str:
    layer_summary = payload.get("layer_summary")
    trust_summary = payload.get("trust_summary")
    lines = [
        "# HOL Guard AIBOM",
        "",
        "## Layer summary",
        "",
    ]
    if isinstance(layer_summary, dict):
        lines.extend(
            [
                f"- Instructions: {layer_summary.get('instructions', 0)}",
                f"- Skills: {layer_summary.get('skills', 0)}",
                f"- MCP: {layer_summary.get('mcp', 0)}",
                f"- Plugins: {layer_summary.get('plugins', 0)}",
                f"- Policies: {layer_summary.get('policies', 0)}",
                f"- Findings: {layer_summary.get('findings', 0)}",
                f"- Trust: {layer_summary.get('trust', 0)}",
                f"- Sources: {layer_summary.get('sources', 0)}",
                f"- Drift: {layer_summary.get('driftCount', 0)}",
                "",
            ]
        )
    lines.extend(
        [
            "## Artifacts",
            "",
            "| Artifact | Harness | Type | Scope | Verdict | Present |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    artifacts = payload.get("artifacts")
    if isinstance(artifacts, list):
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                f"{item.get('artifact_name', '')} | {item.get('harness', '')} | {item.get('artifact_type', '')} | "
                f"{item.get('source_scope', '')} | {item.get('trust_verdict', '')} | "
                f"{'yes' if item.get('present') else 'no'} |"
            )
    if isinstance(trust_summary, dict):
        lines.extend(
            [
                "",
                "## Trust coverage",
                "",
                f"- Covered: {trust_summary.get('covered', 0)} / {trust_summary.get('eligible', 0)}",
                f"- Coverage: {trust_summary.get('coverage_percent', 0)}%",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
