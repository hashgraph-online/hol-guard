"""Aibom commands helpers preserving the public CLI dependency seams."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from .adapters.base import HarnessContext
from .aibom_models import (
    _AIBOM_AUTO_SYNC_INTERVAL_SECONDS,
    AibomCliOptions,
    AibomExportFormat,
)

if TYPE_CHECKING:
    from .aibom_operation_authority import AibomOperation


def build_inventory_json_payload(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    """Build the public inventory response from current detection and stored evidence."""
    from . import aibom_cli as api

    snapshots = api.collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=api._resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    metadata_by_artifact = api._metadata_lookup_from_snapshots(snapshots)
    items: list[dict[str, object]] = []
    for item in store.list_inventory():
        enriched = api._redact_inventory_store_item(item, home_dir=context.home_dir)
        artifact_id = str(item.get("artifact_id") or "")
        harness = str(item.get("harness") or "")
        extensions = metadata_by_artifact.get((harness, artifact_id))
        config_path = api._store_row_config_path(item) if str(item.get("artifact_type") or "") == "skill_file" else None
        config_path_exists = config_path.exists() if config_path is not None else None
        if not extensions:
            extensions = api._store_only_artifact_metadata_extensions(
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
    redaction_report = api._aggregate_redaction_report(snapshots)
    return {
        "generated_at": generated_at,
        "items": items,
        "snapshots": [api.serialize_inventory_snapshot(snapshot) for snapshot in snapshots],
        "redaction_report": redaction_report,
    }


def build_aibom_status_payload(
    store: Any,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    """Summarize local inventory, cloud connection, and the last synchronization."""
    from . import aibom_cli as api

    snapshots = api.collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=api._resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    sync_summary = api._sync_summary(store)
    layer_summary, trust_summary, drift_summary = api.summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    return {
        "generated_at": generated_at,
        "status": api._aibom_connection_status(store),
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": api._aggregate_redaction_report(snapshots),
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
    """Export redacted AIBOM evidence in the requested supported format."""
    from . import aibom_cli as api

    snapshots = api.collect_aibom_snapshots(
        context,
        generated_at=generated_at,
        options=options,
        trust_attestation_context=api._resolve_trust_attestation_context(store, generated_at=generated_at),
    )
    serialized_snapshots = [api.serialize_inventory_snapshot(snapshot) for snapshot in snapshots]
    artifacts = api._artifact_rows_from_store(store, snapshots, context=context, generated_at=generated_at)
    layer_summary, trust_summary, drift_summary = api.summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    sync_summary = api._sync_summary(store)
    payload: dict[str, object] = {
        "generated_at": generated_at,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "snapshots": serialized_snapshots,
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": api._aggregate_redaction_report(snapshots),
        "last_sync_at": sync_summary.get("synced_at"),
    }
    if export_format == "markdown":
        payload["markdown"] = api._render_aibom_markdown(payload)
    return payload


def sync_aibom_snapshots_if_due(
    store: Any,
    *,
    generated_at: str,
    min_interval_seconds: int = _AIBOM_AUTO_SYNC_INTERVAL_SECONDS,
    force: bool = False,
    options: AibomCliOptions | None = None,
    auth_context: dict[str, object] | None = None,
    expected_workspace_id: str | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    """Apply connection and freshness checks before invoking the existing sync API."""
    from . import aibom_cli as api

    runner = api._runner_module()
    guard_sync_not_configured_error = runner.GuardSyncNotConfiguredError

    with store.hold_aibom_sync_lock():
        context = api.HarnessContext(
            home_dir=api._resolve_operator_home_dir(home_dir),
            workspace_dir=workspace_dir,
            guard_home=store.guard_home,
        )
        operation = api.capture_aibom_operation(
            store, context, now=generated_at, bind_installation=api.trust_attestation_v2_enabled()
        )
        if operation is None:
            return {"synced": False, "skipped": True, "reason": "not_configured"}
        skipped = _aibom_sync_preflight(
            store,
            operation=operation,
            generated_at=generated_at,
            min_interval_seconds=min_interval_seconds,
            force=force,
            expected_workspace_id=expected_workspace_id,
        )
        if skipped is not None:
            return skipped
        try:
            return api._sync_aibom_snapshots_admitted(
                store,
                context,
                generated_at=generated_at,
                options=options,
                auth_context=auth_context,
                expected_workspace_id=operation.workspace_id,
                operation=operation,
            )
        except guard_sync_not_configured_error:
            return {"synced": False, "skipped": True, "reason": "not_configured"}
        except ValueError as error:
            return {"synced": False, "error": str(error)}
        except (OSError, RuntimeError) as error:
            return {"synced": False, "error": str(error)}


def _aibom_sync_preflight(
    store: Any,
    *,
    operation: AibomOperation,
    generated_at: str,
    min_interval_seconds: int,
    force: bool,
    expected_workspace_id: str | None,
) -> dict[str, object] | None:
    from . import aibom_cli as api

    if expected_workspace_id is not None and operation.workspace_id != expected_workspace_id:
        return {
            "synced": False,
            "reason": "workspace_changed",
            "error": "Guard Cloud workspace changed before AIBOM inventory sync.",
        }
    if api._aibom_guard_events_endpoint_unavailable_recently(store, operation=operation):
        api.require_current_aibom_operation(store, operation)
        return {
            "synced": False,
            "skipped": True,
            "reason": "guard_events_endpoint_unavailable",
        }
    if not force and not api._aibom_sync_is_due(
        store,
        generated_at=generated_at,
        min_interval_seconds=min_interval_seconds,
        operation=operation,
    ):
        prior = api.read_aibom_result(store, operation, "aibom_sync_summary")
        api.require_current_aibom_operation(store, operation)
        return {
            "synced": False,
            "skipped": True,
            "reason": "recently_synced",
            "last_sync_at": prior.get("synced_at") if isinstance(prior, dict) else None,
        }
    return None


def _sync_aibom_snapshots_if_due_admitted(
    store: Any,
    *,
    operation: AibomOperation,
    generated_at: str,
    min_interval_seconds: int = _AIBOM_AUTO_SYNC_INTERVAL_SECONDS,
) -> dict[str, object]:
    """Run a captured daemon attempt while its caller retains inventory admission.

    Authentication errors propagate so the daemon can preserve its existing
    terminal categories without a separate, unbound authentication attempt.
    """
    from . import aibom_cli as api

    skipped = _aibom_sync_preflight(
        store,
        operation=operation,
        generated_at=generated_at,
        min_interval_seconds=min_interval_seconds,
        force=False,
        expected_workspace_id=operation.workspace_id,
    )
    if skipped is not None:
        return skipped
    return api._sync_aibom_snapshots_admitted(
        store,
        operation.context(),
        generated_at=generated_at,
        expected_workspace_id=operation.workspace_id,
        operation=operation,
    )
