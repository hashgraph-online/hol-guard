"""Aibom collection helpers preserving the public CLI dependency seams."""

from __future__ import annotations

import time
import uuid
from datetime import timedelta

from .adapters.base import HarnessContext
from .aibom_content_upload import (
    GuardAibomPrimaryContentSource,
)
from .aibom_models import (
    AibomCliOptions,
)
from .inventory_contract import (
    GuardAgentInventorySnapshot,
)
from .store import GuardStore


def collect_aibom_snapshots(
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    trust_attestation_context: dict[str, object] | None = None,
    primary_content_sources: list[GuardAibomPrimaryContentSource] | None = None,
) -> tuple[GuardAgentInventorySnapshot, ...]:
    """Collect redacted native inventories while preserving the CLI dependency interface."""
    from . import aibom_cli as api

    resolved = options or api.AibomCliOptions()
    snapshots: list[api.GuardAgentInventorySnapshot] = []
    remaining_cisco_timeout_seconds = resolved.cisco_timeout_seconds
    for detection in api.detect_all(context):
        if not detection.installed and not detection.artifacts:
            continue
        cisco_started = time.monotonic()
        cisco_runs = api.run_cisco_inventory_scans(
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
        artifacts = api.cloud_inventory_artifacts_from_detection(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        snapshot = api.inventory_snapshot_from_detection(
            detection,
            generated_at=generated_at,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
            cisco_runs=cisco_runs,
            include_symlinks=resolved.include_symlinks,
            follow_unsafe_symlinks=resolved.follow_unsafe_symlinks,
            trust_attestation_context=trust_attestation_context,
            artifacts=artifacts,
        )
        snapshots.append(snapshot)
        if primary_content_sources is not None:
            primary_content_sources.extend(
                api.primary_content_sources_from_artifacts(
                    artifacts,
                    snapshot,
                    workspace_dir=context.workspace_dir,
                )
            )
    return tuple(snapshots)


def _resolve_trust_attestation_context(
    store: GuardStore,
    *,
    generated_at: str,
    include_upload_session_bindings: bool = False,
    workspace_id: str | None = None,
) -> dict[str, object]:
    """Resolve locally available trust context without changing workspace identity."""
    from . import aibom_cli as api
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
    resolved_workspace_id = workspace_id or store.get_cloud_workspace_id()
    installation_id = store.get_or_create_installation_id() if enable_v2 else None
    context: dict[str, object] = {
        "analyzerId": "hol-guard" if enable_v2 else None,
        "analyzerSpecVersion": "guard-aibom-trust-spec.v1" if enable_v2 else None,
        "analyzerVersion": api.__version__ if enable_v2 else None,
        "challengeId": None,
        "deviceId": installation_id,
        "expiresAt": None,
        "installationId": installation_id,
        "nonce": None,
        "policyVersion": "guard-aibom-trust-policy.v1" if enable_v2 else None,
        "sequence": None,
        "signingConfig": signing_config,
        "uploadId": None,
        "workspaceId": resolved_workspace_id if enable_v2 else None,
    }
    if not enable_v2 or not include_upload_session_bindings:
        return context
    try:
        expires_at = (api._aware_utc_timestamp(generated_at) + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
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
