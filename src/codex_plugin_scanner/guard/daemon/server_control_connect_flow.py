"""Guard connect finalisation, repair and settings payloads for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from ..cli.connect_flow import (
    CONNECT_SYNC_AUTH_CONTEXT_KEY,
    _build_sync_auth_context,
    _persist_oauth_local_credentials,
    exchange_guard_authorization_code,
    resolve_connect_url,
    resolve_guard_oauth_client_config,
)
from ..cli.connect_sync_result import (
    apply_guard_connect_sync_result,
)
from ..package_firewall_entitlement import (
    reconcile_connect_state_with_oauth_entitlement,
)
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus, ActivityDecisionReason
from ..runtime.command_activity_lifecycle import CommandActivityDecisionFacts, build_pre_hook_evidence
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowControl,
    baseline_command_shadow_proposal,
    build_command_shadow_observation,
)
from ..runtime.extension_control_authority import ExtensionControlAuthorityView
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    current_extension_control_snapshot,
)
from ..runtime.native_command_evaluation import evaluate_command_native
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
)
from ..store import GuardStore
from .server_common import (
    _now,
)
from .server_control_cloud_sync import (
    _sync_local_guard_cloud_proof_with_optional_auth_context,
    _sync_supply_chain_cloud_state_with_optional_auth_context,
)

_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS = 180


def _finalize_daemon_guard_connect_payload(
    *,
    store: GuardStore,
    connect_url: str,
    payload: dict[str, object],
    now: str,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    sync_auth_context = payload.pop(CONNECT_SYNC_AUTH_CONTEXT_KEY, None)
    resolved_sync_auth_context = sync_auth_context if isinstance(sync_auth_context, dict) else None
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
    sync_url = f"{allowed_origin}/api/guard/receipts/sync"
    dashboard_url = f"{allowed_origin}/guard"
    payload.setdefault("connect_url", normalized_connect_url)
    payload.setdefault("sync_url", sync_url)
    payload.setdefault("dashboard_url", dashboard_url)
    payload.setdefault("inbox_url", f"{dashboard_url}/inbox")
    payload.setdefault("fleet_url", f"{dashboard_url}/protect")
    if str(payload.get("status") or "") != "connected":
        return payload
    store.clear_cloud_sync_state_for_reconnect(
        now=now,
        managed_controls_publish=managed_controls_publish,
    )
    latest_state = store.record_guard_connect_pairing_completed(
        sync_url=sync_url,
        allowed_origin=allowed_origin,
        now=now,
    )
    payload.update(
        {
            "status": str(latest_state.get("status") or payload.get("status") or "connected"),
            "milestone": str(latest_state.get("milestone") or "first_sync_pending"),
            "completed_at": latest_state.get("completed_at") or now,
            "latest_connect_state": latest_state,
        }
    )
    oauth_health = store.get_oauth_local_credential_health()
    if store.get_cloud_sync_profile() is None and (
        oauth_health.get("state") == "degraded" or not oauth_health.get("configured")
    ):
        repair_message = (
            "Guard Cloud authorization did not persist locally. "
            "Start Guard Cloud connect again to repair local sign-in."
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=now,
            reason=repair_message,
        )
        payload.update(
            {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "sync_succeeded": False,
                "sync_error": repair_message,
                "repair_message": repair_message,
                "latest_connect_state": store.get_effective_guard_connect_state(now=now),
            }
        )
        return payload
    if store.get_cloud_sync_profile() is None:
        payload["sync_attempted"] = False
        return payload
    payload["sync_attempted"] = True
    try:
        sync_payload = _sync_local_guard_cloud_proof_with_optional_auth_context(
            store,
            resolved_sync_auth_context,
            managed_controls_publish,
        )
    except GuardSyncNotAvailableError as error:
        payload = apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="connected",
            recorded_milestone="sync_not_available",
            repair_message=str(error),
        )
        reconciled_state = reconcile_connect_state_with_oauth_entitlement(store, now=now)
        if reconciled_state is not None:
            payload["milestone"] = str(reconciled_state.get("milestone") or "first_sync_pending")
            payload["latest_connect_state"] = reconciled_state
        return payload
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        return apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="retry_required",
            recorded_milestone="first_sync_failed",
            repair_message="Run Guard Cloud connect again to refresh local authorization.",
            payload_status="retry_required",
        )
    except (RuntimeError, TimeoutError) as error:
        return apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="connected",
            recorded_milestone="first_sync_pending",
            repair_message=(
                "Guard Cloud pairing finished, but the first proof sync is still pending. Local Guard will retry while "
                "the daemon is running."
            ),
            payload_status="connected",
        )
    latest_state = store.record_latest_guard_connect_sync_success(
        sync_payload=sync_payload,
        now=str(sync_payload.get("synced_at") or now),
        request_id=str(latest_state.get("request_id") or ""),
    )
    payload.update(
        {
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "sync_succeeded": True,
            "sync": sync_payload,
            "last_sync_at": sync_payload.get("synced_at"),
            "latest_connect_state": latest_state or store.get_latest_guard_connect_state(now=now),
        }
    )
    try:
        payload["supply_chain"] = _sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            resolved_sync_auth_context,
        )
    except (GuardSyncNotConfiguredError, GuardSyncNotAvailableError, RuntimeError) as error:
        payload["supply_chain_error"] = str(error)
    return payload


def _complete_browser_oauth_connect(
    *,
    store: GuardStore,
    session: Any,
    connect_url: str,
    browser_opened: bool,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None),
) -> dict[str, object]:
    _, allowed_origin = resolve_connect_url(connect_url)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    callback = session.wait_for_callback(_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS)
    if callback is None or callback.code is None:
        raise RuntimeError("Guard OAuth callback missing authorization code.")
    token_result = exchange_guard_authorization_code(
        token_endpoint=oauth_client.token_endpoint,
        client_id=oauth_client.client_id,
        code=callback.code,
        redirect_uri=session.redirect_uri,
        code_verifier=session.pkce_verifier,
        dpop_key_material=session.dpop_key_material,
    )
    if token_result.refresh_token is None:
        raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
    timestamp = _now()
    _persist_oauth_local_credentials(
        store=store,
        issuer=oauth_client.issuer,
        client_id=oauth_client.client_id,
        refresh_token=token_result.refresh_token,
        dpop_key_material=session.dpop_key_material,
        grant_id=token_result.grant_id,
        **token_result.target_binding(),
        supply_chain_entitlement=token_result.supply_chain_entitlement,
        workspace_id=token_result.workspace_id,
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        access_token=token_result.access_token,
        access_token_expires_at=token_result.access_token_expires_at,
        now=timestamp,
    )
    sync_url = f"{allowed_origin}/api/guard/receipts/sync"
    return _finalize_daemon_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={
            "status": "connected",
            "connect_mode": "browser_oauth",
            "browser_opened": browser_opened,
            "authorize_url": session.authorize_url,
            "redirect_uri": session.redirect_uri,
            "grant_id": token_result.grant_id,
            "machine_id": token_result.machine_id,
            "workspace_id": token_result.workspace_id,
            "connect_url": connect_url,
            "sync_url": sync_url,
            "_guard_sync_auth_context": _build_sync_auth_context(
                access_token=token_result.access_token,
                dpop_key_material=session.dpop_key_material,
                sync_url=sync_url,
            ),
        },
        now=timestamp,
        managed_controls_publish=managed_controls_publish,
    )


_PROTECTION_REPAIR_PROBE_COMMAND = "git status --porcelain=v1"


def _repair_command_activity_persistence_health(store: GuardStore) -> str | None:
    """Probe command-evidence persistence; return the reason it could not run.

    A probe that cannot evaluate the native policy engine proves nothing, so it
    must not mutate persistence health. Real probe failures still surface through
    ``probe_command_activity_persistence``.
    """

    snapshot = current_extension_control_snapshot()
    if snapshot is None:
        try:
            snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
                store.read_extension_control_authority_for_registry(
                    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                    read_only=True,
                )
            )
        except Exception:
            snapshot = None
    try:
        evaluation = (
            evaluate_command_native(
                _PROTECTION_REPAIR_PROBE_COMMAND,
                guard_home=store.guard_home,
                extension_control_snapshot=snapshot,
            )
            if snapshot is not None
            else None
        )
    except Exception:
        evaluation = None
    if evaluation is None:
        return "native_evaluation_unavailable"
    occurred_at = datetime.now(timezone.utc)
    activity_id = f"activity:protection-repair-probe:{uuid.uuid4().hex}"
    decision_reason = ActivityDecisionReason.EXTENSION_MATCH if evaluation.matches else ActivityDecisionReason.NO_MATCH
    evidence = build_pre_hook_evidence(
        evaluation,
        CommandActivityDecisionFacts(
            policy_action="allow",
            decision_reason_code=decision_reason,
            prompted=False,
            approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
            receipt_id=None,
        ),
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness="codex",
        request_correlation=None,
    )
    shadow = None
    shadow_evaluation_succeeded = True
    try:
        shadow = build_command_shadow_observation(
            evaluation,
            authoritative_action="allow",
            proposal=baseline_command_shadow_proposal(evaluation),
            activity_id=activity_id,
            occurred_at=occurred_at,
            control=CommandShadowControl(
                enabled=True,
                kill_switch=False,
                release_cohorts=frozenset({CommandShadowCohort.BASELINE}),
                disabled_cohorts=frozenset(),
                sample_basis_points=10_000,
            ),
        )
    except (RuntimeError, TypeError, ValueError):
        shadow = None
        shadow_evaluation_succeeded = False
    store.probe_command_activity_persistence(
        evidence,
        shadow=shadow,
        shadow_evaluation_succeeded=shadow_evaluation_succeeded,
    )
    return None
