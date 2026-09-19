"""Posture helpers using the original live supply-chain namespace."""

from __future__ import annotations


def sync_local_guard_cloud_proof(
    store: _api.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return _api._runtime_runner_module().sync_local_guard_cloud_proof(store, auth_context=auth_context)


def sync_supply_chain_bundle(
    store: _api.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    return _api._runtime_runner_module().sync_supply_chain_bundle(store, auth_context=auth_context)


def _resolve_guard_sync_auth_context(store: _api.GuardStore):
    return _api._runtime_runner_module()._resolve_guard_sync_auth_context(store)


def evaluate_package_request_artifact(*args: object, **kwargs: object):
    return _api._supply_chain_package_eval_module().evaluate_package_request_artifact(*args, **kwargs)


def _is_package_request_evaluation(value: object) -> _api.TypeGuard[_api.Any]:
    return isinstance(value, _api._supply_chain_package_eval_module().PackageRequestEvaluation)


def _package_firewall_refresh_state_path(guard_home: _api.Path) -> _api.Path:
    return guard_home / _api._PACKAGE_FIREWALL_REFRESH_STATE_FILE


def _read_package_firewall_refresh_state(guard_home: _api.Path) -> dict[str, object]:
    path = _api._package_firewall_refresh_state_path(guard_home)
    try:
        payload = _api.json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _api.json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_firewall_refresh_state(guard_home: _api.Path, last_attempt: float) -> None:
    path = _api._package_firewall_refresh_state_path(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{_api.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(
            _api.json.dumps({"last_refresh_attempt_at": last_attempt}, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(path)
    finally:
        if tmp_path.exists():
            with _api.suppress(OSError):
                tmp_path.unlink()


def build_local_supply_chain_posture(
    store: _api.Any,
    config: _api.GuardConfig,
    *,
    now: str | None = None,
) -> dict[str, object]:
    from .synced_policy import synced_policy_payload

    snapshot_now = _api._parse_timestamp(now) or _api.datetime.now(_api.timezone.utc)
    workspace_id = store.get_cloud_workspace_id()
    cloud_profile = store.get_cloud_sync_profile()
    summary = _api._dict_payload(store.get_sync_payload("supply_chain_bundle_summary"))
    entitlement = _api._dict_payload(store.get_sync_payload("supply_chain_bundle_entitlement"))
    remote_policy = _api._dict_payload(synced_policy_payload(store))
    # Legacy team-policy siblings are not signed policy-bundle content and
    # therefore cannot contribute enforcement or managed-policy status.
    team_policy_pack: dict[str, object] = {}
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id else None
    bundle_payload = _api._dict_payload(cached_bundle.get("bundle")) if isinstance(cached_bundle, dict) else {}
    expires_at_text = _api._string_value(bundle_payload.get("expiresAt"))
    expires_at = _api._parse_timestamp(expires_at_text)
    status = _api._posture_status(
        credentials_present=cloud_profile is not None,
        workspace_id=workspace_id,
        summary=summary,
        bundle_payload=bundle_payload,
        expires_at=expires_at,
        snapshot_now=snapshot_now,
    )
    synced_at = _api._string_value(summary.get("synced_at"))
    next_refresh_at = _api._resolve_next_refresh_at(
        summary=summary,
        synced_at=synced_at,
    )
    health_status = _api._posture_health_status(
        status=status,
        next_refresh_at=next_refresh_at,
        snapshot_now=snapshot_now,
    )
    support = summary.get("ecosystem_support")
    supported_ecosystems = support if isinstance(support, list) and support else list(_api.ecosystem_support_matrix())
    bundle_version = (
        _api._string_value(summary.get("bundle_version"))
        or _api._string_value(entitlement.get("bundle_version"))
        or _api._string_value(bundle_payload.get("bundleVersion"))
    )
    tier = (
        _api._string_value(summary.get("tier"))
        or _api._string_value(entitlement.get("tier"))
        or _api._string_value(bundle_payload.get("tier"))
    )
    remote_package_script_action = _api._string_value(remote_policy.get("packageScriptAction")) or _api._string_value(
        remote_policy.get("package_script_action")
    )
    remote_cloud_advisory_action = _api._string_value(remote_policy.get("cloudAdvisoryAction")) or _api._string_value(
        remote_policy.get("cloud_advisory_action")
    )
    managed_by_cloud = bool(remote_policy or team_policy_pack)
    managed_label = _api._string_value(team_policy_pack.get("name")) or (
        "Guard Cloud sync" if managed_by_cloud else None
    )
    managed_updated_at = _api._string_value(team_policy_pack.get("updatedAt")) or _api._string_value(
        remote_policy.get("updatedAt")
    )
    return {
        "status": status,
        "health_status": health_status,
        "detail": _api._posture_detail(status),
        "connection": {
            "logged_in": cloud_profile is not None,
            "paired": workspace_id is not None,
            "workspace_id": workspace_id,
        },
        "bundle": {
            "bundle_version": bundle_version,
            "feed_snapshot_hash": _api._string_value(summary.get("feed_snapshot_hash"))
            or _api._string_value(bundle_payload.get("feedSnapshotHash")),
            "policy_hash": _api._string_value(summary.get("policy_hash"))
            or _api._string_value(entitlement.get("policy_hash"))
            or _api._string_value(bundle_payload.get("policyHash")),
            "synced_at": synced_at,
            "next_refresh_at": next_refresh_at,
            "expires_at": expires_at_text,
            "tier": tier,
            "workspace_id": _api._string_value(summary.get("workspace_id"))
            or _api._string_value(entitlement.get("workspace_id"))
            or workspace_id,
            "advisory_count": _api._int_value(summary.get("advisory_count")),
            "package_count": _api._int_value(summary.get("package_count")),
        },
        "policy": {
            "security_level": config.security_level,
            "cloud_advisory_action": remote_cloud_advisory_action
            or _api.resolve_risk_action(config, "cloud_advisory", harness=None),
            "package_script_action": remote_package_script_action
            or _api.resolve_risk_action(config, "package_script", harness=None),
            "managed_by_cloud": managed_by_cloud,
            "remote_policy_active": bool(remote_policy),
            "team_policy_active": bool(team_policy_pack),
            "managed_label": managed_label,
            "managed_updated_at": managed_updated_at,
        },
        "supported_ecosystems": supported_ecosystems,
        "package_manager_protection": _api._build_package_manager_protection(store),
    }


def build_supply_chain_status_payload(
    *,
    store: _api.Any,
    config: _api.GuardConfig,
    now: str,
) -> dict[str, object]:
    posture = _api.build_local_supply_chain_posture(store, config, now=now)
    return {
        "generated_at": now,
        "mode": "status",
        "executed": False,
        "dry_run": True,
        "supply_chain": posture,
    }


def _call_sync_with_optional_auth_context(
    refresh: _api.Any,
    *,
    store: _api.Any,
    auth_context: dict[str, object],
) -> dict[str, object]:
    try:
        parameters = _api.inspect.signature(refresh).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "auth_context" in parameters:
        return refresh(store, auth_context=auth_context)
    return refresh(store)


def resolve_package_firewall_entitlement_with_refresh(store: _api.Any) -> dict[str, object]:
    """Resolve package-firewall access and opportunistically heal stale cloud state."""

    entitlement_module = _api._package_firewall_entitlement_module()
    runner = _api._runtime_runner_module()

    entitlement = entitlement_module.resolve_package_firewall_entitlement(store)
    if bool(entitlement.get("allowed")):
        return entitlement
    if store.get_cloud_sync_profile() is None:
        return entitlement
    if str(entitlement.get("reason") or "") not in {
        "guard_cloud_connect_required",
        "guard_cloud_reconnect_required",
        "paid_guard_cloud_required",
    }:
        return entitlement
    now_iso = _api.datetime.now(_api.timezone.utc).isoformat()
    now = _api.time.time()
    with _api._PACKAGE_FIREWALL_REFRESH_LOCK:
        state = _api._read_package_firewall_refresh_state(store.guard_home)
        last_refresh_at = state.get("last_refresh_attempt_at")
        if (
            isinstance(last_refresh_at, (int, float))
            and (now - float(last_refresh_at)) < _api._PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS
        ):
            return entitlement
        _api._write_package_firewall_refresh_state(store.guard_home, now)
    auth_context: dict[str, object] | None = None
    try:
        auth_context = _api._resolve_guard_sync_auth_context(store)
    except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotAvailableError):
        auth_context = None
    except (runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
        auth_context = None
    for refresh in (_api.sync_local_guard_cloud_proof, _api.sync_supply_chain_bundle):
        try:
            if auth_context is None:
                refresh(store)
            else:
                _api._call_sync_with_optional_auth_context(
                    refresh,
                    store=store,
                    auth_context=auth_context,
                )
        except runner.GuardSyncAuthorizationExpiredError as error:
            if str(entitlement.get("reason") or "") == "guard_cloud_connect_required":
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=now_iso,
                    reason=str(error),
                )
            break
        except (runner.GuardSyncNotAvailableError, runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
            continue
    return entitlement_module.resolve_package_firewall_entitlement(store)


def _build_package_manager_protection(store: _api.Any) -> dict[str, object]:
    context = _api.HarnessContext(
        home_dir=_api.Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
    status = _api.package_shim_dashboard_status(context)
    shim_dir = _api.Path(str(status.get("shim_dir") or store.guard_home / "package-shims" / "bin"))
    installed_managers = sorted(set(_api._string_items(status.get("installed_managers"))))
    active_managers = sorted(set(_api._string_items(status.get("active_managers"))))
    missing_shims = sorted(set(_api._string_items(status.get("missing_managers"))))
    supported_managers = list(_api.package_shim_supported_managers())
    detected_managers = sorted(set(_api._string_items(status.get("detected_managers"))))
    protected_managers = sorted(set(_api._string_items(status.get("protected_managers"))))
    protected_set = set(protected_managers)
    path_status = str(status.get("path_status") or "missing_from_path")
    coverage_managers = set(detected_managers)
    staged_managers = (
        set(installed_managers).intersection(coverage_managers) if path_status == "restart_required" else set()
    )
    unprotected_managers = [
        manager for manager in detected_managers if manager not in protected_set and manager not in staged_managers
    ]
    return {
        "path_status": path_status,
        "path_contains_shim_dir": bool(status.get("path_contains_shim_dir")),
        "restart_shell_required": bool(status.get("restart_shell_required")),
        "process_path_status": str(status.get("process_path_status") or "missing"),
        "process_restart_required": bool(status.get("process_restart_required")),
        "shell_profile_configured": bool(status.get("shell_profile_configured")),
        "shell_profile_path": status.get("shell_profile_path"),
        "shim_dir": str(shim_dir),
        "supported_managers": supported_managers,
        "detected_managers": detected_managers,
        "installed_managers": installed_managers,
        "active_managers": active_managers,
        "missing_shims": missing_shims,
        "protected_managers": protected_managers,
        "unprotected_managers": unprotected_managers,
    }


def _posture_status(
    *,
    credentials_present: bool,
    workspace_id: str | None,
    summary: dict[str, object],
    bundle_payload: dict[str, object],
    expires_at: _api.datetime | None,
    snapshot_now: _api.datetime,
) -> str:
    if not credentials_present:
        return "not_connected"
    if workspace_id is None:
        return "workspace_required"
    if not summary and not bundle_payload:
        return "sync_required"
    if expires_at is not None and expires_at <= snapshot_now:
        return "expired"
    summary_status = _api._string_value(summary.get("status"))
    if summary_status:
        return summary_status
    if bundle_payload:
        return "synced"
    return "degraded"


def _posture_detail(status: str) -> str:
    details = {
        "not_connected": (
            "Local package protection is active. Guard Cloud is optional and adds live package intelligence, "
            "synced policy, and cross-device evidence."
        ),
        "workspace_required": "Finish Guard Cloud pairing to fetch workspace-specific supply-chain bundles.",
        "sync_required": "Run `hol-guard supply-chain sync` to fetch the latest signed bundle.",
        "expired": "The cached signed bundle expired. Run `hol-guard supply-chain sync` before the next install.",
        "synced": "Signed supply-chain bundle is ready for local install protection.",
        "degraded": "Supply-chain protection is degraded. Refresh the signed bundle before trusting new installs.",
    }
    return details.get(status, "Supply-chain protection status is available.")


def _posture_health_status(
    *,
    status: str,
    next_refresh_at: str | None,
    snapshot_now: _api.datetime,
) -> str:
    if status == "expired":
        return "stale"
    if status == "not_connected":
        return "local"
    if status in {"workspace_required", "sync_required", "degraded"}:
        return "degraded"
    next_refresh_timestamp = _api._parse_timestamp(next_refresh_at)
    if (
        status == "synced"
        and next_refresh_timestamp is not None
        and next_refresh_timestamp + _api.timedelta(seconds=_api._STALE_REFRESH_GRACE_SECONDS) <= snapshot_now
    ):
        return "stale"
    if status == "synced":
        return "protected"
    return "degraded"


def _resolve_next_refresh_at(
    *,
    summary: dict[str, object],
    synced_at: str | None,
) -> str | None:
    explicit_next_refresh = _api._parse_timestamp(_api._string_value(summary.get("next_refresh_at")))
    if explicit_next_refresh is not None:
        return explicit_next_refresh.isoformat()
    synced_timestamp = _api._parse_timestamp(synced_at)
    if synced_timestamp is None:
        return None
    return (synced_timestamp + _api.timedelta(seconds=_api._DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS)).isoformat()


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
