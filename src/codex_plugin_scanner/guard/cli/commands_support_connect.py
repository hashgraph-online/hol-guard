"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ._commands_shared import _SERVICE_RUNTIME_CHOICES, _SERVICE_RUNTIME_PROFILE_STATE_KEY, _now
    from .commands_support_runtime_artifacts import _optional_string


from ._commands_shared import *
from .commands_parser_helpers import *
from ..local_supply_chain import _resolve_guard_sync_auth_context as _local_resolve_guard_sync_auth_context


def _print_connect_progress(message: str) -> None:
    """Print a progress message to stderr during connect flow so the user sees activity."""
    print(f"hol-guard: {message}", file=sys.stderr, flush=True)


def _connect_guard_sync_auth_context(store: GuardStore) -> dict[str, object]:
    resolver = globals().get("_resolve_guard_sync_auth_context")
    if callable(resolver):
        return cast(dict[str, object], resolver(store))
    return _local_resolve_guard_sync_auth_context(store)

def _validate_policy_scope(
    scope: str,
    artifact_id: str | None,
    workspace: Path | None,
    publisher: str | None,
) -> None:
    if scope == "artifact" and not artifact_id:
        print("--artifact-id is required when --scope artifact", file=sys.stderr)
        raise SystemExit(2)
    if scope == "workspace" and workspace is None:
        print("--workspace is required when --scope workspace", file=sys.stderr)
        raise SystemExit(2)
    if scope == "publisher" and not publisher:
        print("--publisher is required when --scope publisher", file=sys.stderr)
        raise SystemExit(2)

def _resolve_policy_expiry(args: argparse.Namespace) -> str | None:
    hours = getattr(args, "expires_in_hours", None)
    if hours is None:
        return None
    if hours <= 0:
        print("--expires-in-hours must be greater than 0.", file=sys.stderr)
        raise SystemExit(2)
    return (datetime.now(timezone.utc) + timedelta(hours=float(hours))).isoformat()

def _guard_doctor_connect_health_payload(store: GuardStore) -> dict[str, object]:
    oauth_storage_health = store.get_oauth_local_credential_health()
    cloud_profile = store.get_cloud_sync_profile()
    effective_connect_state = store.get_effective_guard_connect_state(now=_now())
    latest_state = normalize_connect_state_for_missing_oauth(
        latest_state=effective_connect_state,
        oauth_storage_health=oauth_storage_health,
        oauth_required=connect_state_requires_oauth(
            latest_state=effective_connect_state,
            cloud_profile=cloud_profile,
        ),
    )
    payload: dict[str, object] = {
        "oauth_storage_health": _guard_doctor_oauth_storage_health_payload_from_health(oauth_storage_health),
        "connect_recovery_command": connect_recovery_command(latest_state),
    }
    if isinstance(latest_state, dict):
        payload["latest_connect_state"] = _guard_doctor_latest_connect_state_payload(latest_state)
    return payload

def _guard_doctor_oauth_storage_health_payload(store: GuardStore) -> dict[str, str]:
    return _guard_doctor_oauth_storage_health_payload_from_health(
        store.get_oauth_local_credential_health(),
    )

def _guard_doctor_oauth_storage_health_payload_from_health(oauth_storage_health: dict[str, object]) -> dict[str, str]:
    state = "unknown"
    if isinstance(oauth_storage_health, dict):
        raw_state = oauth_storage_health.get("state")
        if isinstance(raw_state, str) and raw_state.strip():
            state = raw_state
    return {"state": state}

def _guard_doctor_latest_connect_state_payload(latest_state: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key in (
        "request_id",
        "status",
        "milestone",
        "reason",
        "created_at",
        "updated_at",
        "expires_at",
        "completed_at",
        "version",
    ):
        value = latest_state.get(key)
        if isinstance(value, str) and value.strip():
            payload[key] = value
    poll_after_ms = latest_state.get("poll_after_ms")
    if isinstance(poll_after_ms, int):
        payload["poll_after_ms"] = poll_after_ms
    return payload

def _synced_policy_payload(store: GuardStore) -> dict[str, object] | None:
    policy_bundle = store.get_sync_payload("policy_bundle")
    if isinstance(policy_bundle, dict):
        policy_defaults = policy_bundle.get("policyDefaults")
        if isinstance(policy_defaults, dict):
            payload = dict(policy_defaults)
            issued_at = _optional_string(policy_bundle.get("issuedAt"))
            bundle_hash = _optional_string(policy_bundle.get("bundleHash"))
            bundle_version = _optional_string(policy_bundle.get("bundleVersion"))
            if issued_at is not None:
                payload["updatedAt"] = issued_at
            if bundle_hash is not None:
                payload["bundleHash"] = bundle_hash
            if bundle_version is not None:
                payload["bundleVersion"] = bundle_version
            return payload
    payload = store.get_sync_payload("policy")
    return payload if isinstance(payload, dict) else None


_PERSISTED_POLICY_BUNDLE_REJECTION_REASONS = frozenset(
    {
        "bundle_hash_mismatch",
        "bundle_version_downgrade",
        "invalid_acknowledgements",
        "invalid_bundle_hash",
        "invalid_bundle_version",
        "invalid_cloud_exceptions",
        "invalid_expires_at",
        "invalid_issued_at",
        "invalid_policy_bundle",
        "invalid_policy_defaults",
        "invalid_rollout_state",
        "invalid_rules",
        "invalid_verifier",
        "invalid_workspace_id",
        "missing_required_field",
        "payload_hash_mismatch",
        "unsupported_contract_version",
        "unsupported_daemon_version",
        "wrong_workspace",
    }
)


def _refresh_cloud_policy_bundle(store: GuardStore, *, bundle_only: bool = False) -> None:
    if store.get_cloud_sync_profile() is None:
        return
    now = _now()
    try:
        if bundle_only:
            # Protect/install flows need the latest signed bundle only.
            # Receipt uploads and workspace audit jobs can backlog into slow multi-request
            # sync loops and should not block command protection on every invocation.
            sync_supply_chain_bundle(store)
        else:
            sync_receipts(store)
            sync_supply_chain_cloud_state(store)
    except GuardSyncAuthorizationExpiredError as error:
        message = str(error).strip()
        auth_expired_message = "Guard authorization expired. Run `hol-guard connect` to sign in again."
        if message.startswith(auth_expired_message):
            message = auth_expired_message
        store.set_sync_payload(
            "policy_bundle_last_error",
            {"reason": "auth_expired", "message": message},
            now,
        )
        return
    except GuardSyncNotConfiguredError:
        return
    except RuntimeError as error:
        store.set_sync_payload(
            "policy_bundle_last_error",
            {"reason": "sync_failed", "message": str(error)},
            now,
        )
        return
    policy_bundle_last_error = store.get_sync_payload("policy_bundle_last_error")
    policy_bundle_rejection_reason = (
        _optional_string(policy_bundle_last_error.get("reason"))
        if isinstance(policy_bundle_last_error, dict)
        else None
    )
    if policy_bundle_rejection_reason not in _PERSISTED_POLICY_BUNDLE_REJECTION_REASONS:
        store.set_sync_payload("policy_bundle_last_error", {}, now)

def _guard_cloud_urls_for_connect(connect_url: str) -> dict[str, str]:
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
    prefix = guard_api_base_path(allowed_origin)
    dashboard_url = f"{allowed_origin}{prefix}/guard"
    api_base = f"{allowed_origin}{prefix}/api/guard"
    return {
        "connect_url": normalized_connect_url,
        "sync_url": f"{api_base}/receipts/sync",
        "dashboard_url": dashboard_url,
        "inbox_url": f"{dashboard_url}/inbox",
        "fleet_url": f"{dashboard_url}/protect",
        "allowed_origin": allowed_origin,
    }

def _finalize_guard_connect_payload(
    *,
    store: GuardStore,
    connect_url: str,
    payload: dict[str, object],
    now: str,
) -> dict[str, object]:
    sync_auth_context = payload.pop(CONNECT_SYNC_AUTH_CONTEXT_KEY, None)
    resolved_sync_auth_context = sync_auth_context if isinstance(sync_auth_context, dict) else None
    urls = _guard_cloud_urls_for_connect(connect_url)
    for key in ("connect_url", "sync_url", "dashboard_url", "inbox_url", "fleet_url"):
        payload.setdefault(key, urls[key])
    if str(payload.get("status") or "") != "connected":
        return payload
    store.clear_cloud_sync_state_for_reconnect()
    latest_state = store.record_guard_connect_pairing_completed(
        sync_url=str(urls["sync_url"]),
        allowed_origin=str(urls["allowed_origin"]),
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
    oauth_state = str(oauth_health.get("state") or "")
    if store.get_cloud_sync_profile() is None and (
        oauth_state == "degraded" or not oauth_health.get("configured")
    ):
        repair_message = (
            "Guard Cloud authorization did not persist locally. "
            "Run hol-guard connect again to repair local sign-in."
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
        _print_connect_progress("Syncing local proof to Guard Cloud...")
        sync_payload = sync_local_guard_cloud_proof(
            store,
            auth_context=resolved_sync_auth_context,
            now=now,
        )
    except GuardSyncNotAvailableError as error:
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="sync_not_available",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "milestone": "sync_not_available",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": str(error),
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": "Run hol-guard connect again to refresh Guard Cloud authorization.",
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    except (RuntimeError, TimeoutError) as error:
        repair_message = (
            "Guard Cloud pairing finished, but the first proof sync is still pending. "
            "Local Guard will retry automatically while the daemon is running, or run hol-guard sync now."
        )
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="first_sync_pending",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "status": "connected",
                "milestone": "first_sync_pending",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": repair_message,
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    _print_connect_progress("Guard Cloud sync complete.")
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
        _print_connect_progress("Syncing supply chain state...")
        payload["supply_chain"] = sync_supply_chain_cloud_state(
            store,
            auth_context=resolved_sync_auth_context,
        )
    except (GuardSyncNotConfiguredError, GuardSyncNotAvailableError, RuntimeError) as error:
        payload["supply_chain_error"] = str(error)
    return payload

def _filter_policy_items(items: list[dict[str, object]], *, active_only: bool) -> list[dict[str, object]]:
    if not active_only:
        return items
    current_time = datetime.now(timezone.utc)
    filtered: list[dict[str, object]] = []
    for item in items:
        expires_at = item.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.strip():
            filtered.append(item)
            continue
        try:
            expires_on = datetime.fromisoformat(expires_at)
        except ValueError:
            filtered.append(item)
            continue
        if expires_on > current_time:
            filtered.append(item)
    return filtered

def _run_guard_device_connect_flow(
    *,
    store: GuardStore,
    connect_url: str,
    wait_timeout_seconds: int = 180,
    announce_copy=None,
    open_browser: Callable[[str], bool] | None = None,
    ci_safe: bool = False,
    machine_label: str | None = None,
) -> dict[str, object]:
    return run_guard_device_connect_command(
        store=store,
        connect_url=connect_url,
        wait_timeout_seconds=wait_timeout_seconds,
        announce_copy=announce_copy,
        open_browser=open_browser,
        ci_safe=ci_safe,
        machine_label=machine_label,
        include_sync_auth_context=True,
    )

def _run_guard_browser_connect_flow(
    *,
    store: GuardStore,
    connect_url: str,
    wait_timeout_seconds: int,
) -> dict[str, object]:
    return run_guard_browser_connect_command(
        store=store,
        connect_url=connect_url,
        wait_timeout_seconds=wait_timeout_seconds,
        include_sync_auth_context=True,
    )

def _build_guard_device_connect_payload(
    *,
    store: GuardStore,
    connect_url: str,
    use_browser_oauth: bool,
    open_device_browser: bool = False,
    wait_timeout_seconds: int = 180,
    announce_copy=None,
    ci_safe: bool = False,
    machine_label: str | None = None,
) -> tuple[dict[str, object] | None, int]:
    try:
        if use_browser_oauth:
            payload = _run_guard_browser_connect_flow(
                store=store,
                connect_url=connect_url,
                wait_timeout_seconds=wait_timeout_seconds,
            )
        elif open_device_browser:
            payload = _run_guard_device_connect_flow(
                store=store,
                connect_url=connect_url,
                wait_timeout_seconds=wait_timeout_seconds,
                announce_copy=announce_copy,
                open_browser=webbrowser.open,
                ci_safe=ci_safe,
                machine_label=machine_label,
            )
        else:
            payload = _run_guard_device_connect_flow(
                store=store,
                connect_url=connect_url,
                wait_timeout_seconds=wait_timeout_seconds,
                announce_copy=announce_copy,
                ci_safe=ci_safe,
                machine_label=machine_label,
            )
    except json.JSONDecodeError as error:
        print(f"Guard authorization failed: {error}", file=sys.stderr)
        return None, 1
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return None, 2
    except (RuntimeError, TimeoutError, urllib.error.URLError, http.client.HTTPException) as error:
        print(f"Guard authorization failed: {error}", file=sys.stderr)
        return None, 1
    payload = _finalize_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload=payload,
        now=_now(),
    )
    return payload, 0

def _announce_guard_device_connect_copy(payload: dict[str, object]) -> None:
    user_code = _optional_string(payload.get("user_code")) or "unknown"
    target = _optional_string(payload.get("verification_uri")) or _optional_string(
        payload.get("verification_uri_complete")
    )
    if target is None:
        return
    print("HOL Guard headless approval", file=sys.stderr)
    print(f"1. Open {target}", file=sys.stderr)
    print(f"2. Enter code {user_code}", file=sys.stderr)
    print("3. Keep this terminal open while HOL Guard waits for approval.", file=sys.stderr)

def _guard_ci_safe_connect_options(args: argparse.Namespace) -> tuple[bool, str | None]:
    ci_safe = bool(getattr(args, "ci_safe", False))
    if not ci_safe:
        return False, None
    if not bool(getattr(args, "headless", False)):
        raise ValueError("Guard CI-safe connect requires --headless.")
    workspace = _optional_string(getattr(args, "workspace", None))
    if workspace is None:
        raise ValueError("Guard CI-safe headless connect requires --workspace.")
    label = _optional_string(getattr(args, "label", None))
    if label is None:
        raise ValueError("Guard CI-safe headless connect requires --label.")
    return True, label

def _manual_guard_login_payload(
    *,
    args: argparse.Namespace,
    store: GuardStore,
) -> tuple[dict[str, object] | None, int] | None:
    manual_token = _optional_string(getattr(args, "token", None))
    if manual_token is None:
        return None
    print(
        "Manual token login is retired. Run `hol-guard connect` to sign in with browser OAuth.",
        file=sys.stderr,
    )
    return None, 2

def _guard_service_runtime_profile(
    store: GuardStore,
) -> dict[str, str] | None:
    payload = store.get_sync_payload(_SERVICE_RUNTIME_PROFILE_STATE_KEY)
    if not isinstance(payload, dict):
        return None
    runtime = _optional_string(payload.get("runtime"))
    label = _optional_string(payload.get("label"))
    surface = _optional_string(payload.get("surface"))
    client_name = _optional_string(payload.get("client_name"))
    client_title = _optional_string(payload.get("client_title"))
    client_version = _optional_string(payload.get("client_version"))
    if (
        runtime not in _SERVICE_RUNTIME_CHOICES
        or label is None
        or surface is None
        or client_name is None
        or client_title is None
        or client_version is None
    ):
        return None
    return {
        "runtime": runtime,
        "label": label,
        "workspace": _optional_string(payload.get("workspace")) or "",
        "surface": surface,
        "client_name": client_name,
        "client_title": client_title,
        "client_version": client_version,
    }

__all__ = [
    "_announce_guard_device_connect_copy",
    "_build_guard_device_connect_payload",
    "_filter_policy_items",
    "_finalize_guard_connect_payload",
    "_guard_ci_safe_connect_options",
    "_guard_cloud_urls_for_connect",
    "_guard_doctor_connect_health_payload",
    "_guard_doctor_latest_connect_state_payload",
    "_guard_doctor_oauth_storage_health_payload",
    "_guard_service_runtime_profile",
    "_manual_guard_login_payload",
    "_refresh_cloud_policy_bundle",
    "_resolve_policy_expiry",
    "_run_guard_browser_connect_flow",
    "_run_guard_device_connect_flow",
    "_synced_policy_payload",
    "_validate_policy_scope",
]
