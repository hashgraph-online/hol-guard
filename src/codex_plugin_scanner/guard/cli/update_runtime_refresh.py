"""Trusted package-shim and daemon refresh after an update."""

from __future__ import annotations

from ..adapters.base import HarnessContext
from .update_subprocess import TrustedUpdateContext


def _standalone_update_context(context: HarnessContext) -> TrustedUpdateContext:
    state = _update.load_managed_policy()
    if state.status != "absent" and state.policy is None:
        raise _update.UpdateSubprocessError("update_source_invalid")
    policy = state.policy
    network = policy.network if policy is not None else _update.ManagedNetworkPolicy()
    index_url = policy.update.index_url if policy is not None else None
    if not network.allow_public_registries and index_url is None:
        raise _update.UpdateSubprocessError("update_source_unconfigured")
    return _update.build_trusted_update_context(
        guard_home=context.guard_home,
        workspace_dir=context.workspace_dir,
        installer_kind=_update._installer_kind(),
        source_url=index_url,
        source_kind="managed_index" if index_url is not None else "pypi",
        proxy_mode=network.proxy_mode,
        proxy_url=network.proxy_url,
        ca_bundle_path=network.ca_bundle_path,
    )


def _refresh_package_shims_after_update(
    *,
    context: HarnessContext | None,
    dry_run: bool,
    update_context: TrustedUpdateContext | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    if dry_run or context is None or not _update._package_shim_manifest_has_installed_managers(context):
        return None, None
    refresh_context = {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir) if context.workspace_dir is not None else None,
        "guard_home": str(context.guard_home),
        # This value is diagnostic input only; it is never installed as the child PATH.
        "diagnostic_path": _update.os.environ.get("PATH", ""),
    }
    try:
        active_context = update_context or _update._standalone_update_context(context)
        result = active_context.run(
            active_context.python_command(_update._PACKAGE_SHIM_REFRESH_SCRIPT),
            input_text=_update.json.dumps(refresh_context),
            timeout_seconds=_update._PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS,
        )
    except _update.UpdateSubprocessError as error:
        return None, f"Could not refresh package firewall shims during update: {error.reason_code}"
    stdout = _update._normalize_output_text(result.stdout)
    stderr = _update._normalize_output_text(result.stderr)
    if result.output_limited:
        return None, "Could not refresh package firewall shims during update: update_installer_output_limit"
    if result.returncode != 0:
        details = stderr or stdout or f"exit code {result.returncode}"
        return None, f"Could not refresh package firewall shims during update: {details}"
    try:
        refresh_payload = _update.json.loads(stdout) if stdout else {}
    except _update.json.JSONDecodeError as error:
        return None, f"Could not parse package firewall refresh output during update: {error}"
    if not isinstance(refresh_payload, dict):
        return None, "Could not parse package firewall refresh output during update: invalid payload"
    after_status = refresh_payload.get("after")
    if not isinstance(after_status, dict):
        return None, "Could not parse package firewall refresh output during update: missing status"
    installed_managers = _update._string_list(after_status.get("installed_managers"))
    if not installed_managers:
        return None, None
    return refresh_payload, _update._package_shim_refresh_note(refresh_payload)


def refresh_guard_daemon_after_update(
    context: HarnessContext,
    *,
    update_context: TrustedUpdateContext | None = None,
    minimum_version: str | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Restart a resident daemon in a fresh interpreter after a CLI package update."""

    if not (context.guard_home / "daemon-state.json").is_file():
        return None, None
    newer_runtime = _update._verified_newer_guard_daemon(
        context.guard_home,
        minimum_version=minimum_version,
    )
    if newer_runtime is not None:
        return (
            newer_runtime,
            "Kept the newer HOL Guard runtime active while updating the shell CLI.",
        )
    desktop_owner = _update.retained_desktop_owner_payload(context.guard_home)
    if desktop_owner is not None:
        return desktop_owner, _update.retained_desktop_owner_note(desktop_owner.get("daemon_version"))
    active_context: _update.TrustedUpdateContext | None = None
    try:
        active_context = update_context or _update._standalone_update_context(context)
        result = active_context.run(
            active_context.python_command(_update._DAEMON_REFRESH_BOOTSTRAP_SCRIPT),
            input_text=_update.json.dumps(
                {
                    "guard_home": str(context.guard_home),
                    "home_dir": str(context.home_dir),
                }
            ),
            timeout_seconds=_update._DAEMON_REFRESH_TIMEOUT_SECONDS,
            allow_windows_job_breakaway=True,
        )
    except _update.UpdateSubprocessError as error:
        cleanup_verified = True
        if active_context is not None:
            cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _update._daemon_refresh_failure_note(
            f"Could not restart the Guard daemon after update: {error.reason_code}",
            cleanup_verified=cleanup_verified,
        )
    stdout = _update._normalize_output_text(result.stdout)
    stderr = _update._normalize_output_text(result.stderr)
    if result.output_limited:
        cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _update._daemon_refresh_failure_note(
            "Could not restart the Guard daemon after update: update_installer_output_limit",
            cleanup_verified=cleanup_verified,
        )
    if result.returncode != 0:
        cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        details = stderr or stdout or f"exit code {result.returncode}"
        return None, _update._daemon_refresh_failure_note(
            f"Could not restart the Guard daemon after update: {details}",
            cleanup_verified=cleanup_verified,
        )
    try:
        payload = _update.json.loads(stdout) if stdout else {}
    except _update.json.JSONDecodeError as error:
        cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _update._daemon_refresh_failure_note(
            f"Could not parse the Guard daemon restart result after update: {error}",
            cleanup_verified=cleanup_verified,
        )
    if not isinstance(payload, dict):
        cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _update._daemon_refresh_failure_note(
            "Could not parse the Guard daemon restart result after update: invalid payload",
            cleanup_verified=cleanup_verified,
        )
    status = payload.get("status")
    if status == "not_running":
        return payload, "The Guard daemon was not running before the update; nothing to restart."
    if status == "retained_desktop_owner" and payload.get("runtime_verified") is True:
        return payload, _update.retained_desktop_owner_note(payload.get("daemon_version"))
    if status != "restarted" or payload.get("runtime_verified") is not True:
        cleanup_verified = _update._cleanup_failed_guard_daemon_refresh(active_context, context)
        return payload, _update._daemon_refresh_failure_note(
            "Could not restart the Guard daemon after update: updated runtime was not confirmed",
            cleanup_verified=cleanup_verified,
        )
    return payload, "Restarted the Guard daemon to load the updated package."


def _cleanup_failed_guard_daemon_refresh(
    update_context: TrustedUpdateContext,
    context: HarnessContext,
) -> bool:
    """Best-effort retirement for a daemon that may have escaped a Windows Job."""

    try:
        result = update_context.run(
            update_context.python_command(_update._DAEMON_REFRESH_CLEANUP_SCRIPT),
            input_text=_update.json.dumps({"guard_home": str(context.guard_home)}),
            timeout_seconds=_update._DAEMON_REFRESH_CLEANUP_TIMEOUT_SECONDS,
        )
    except _update.UpdateSubprocessError:
        return False
    if result.returncode != 0 or result.output_limited or result.stderr or not result.stdout:
        return False
    lines = result.stdout.strip().splitlines()
    if len(lines) != 1:
        return False
    try:
        payload = _update.json.loads(lines[0])
    except _update.json.JSONDecodeError:
        return False
    if not isinstance(payload, dict) or set(payload) != {"remaining", "retired", "status"}:
        return False
    remaining = payload.get("remaining")
    retired = payload.get("retired")
    return (
        payload.get("status") == "cleaned"
        and isinstance(remaining, list)
        and not remaining
        and isinstance(retired, list)
        and all(type(pid) is int and pid > 0 for pid in retired)
    )


def _daemon_refresh_failure_note(message: str, *, cleanup_verified: bool) -> str:
    if cleanup_verified:
        return message
    return f"{message}. Guard daemon cleanup could not be verified."


def _package_shim_manifest_has_installed_managers(context: HarnessContext) -> bool:
    manifest_path = context.guard_home / "package-shims" / "manifest.json"
    try:
        raw_manifest = manifest_path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        manifest = _update.json.loads(raw_manifest)
    except _update.json.JSONDecodeError:
        return False
    if not isinstance(manifest, dict):
        return False
    return bool(_update._string_list(manifest.get("installed_managers")))


def _package_shim_refresh_note(refresh_payload: dict[str, object]) -> str | None:
    after_status = refresh_payload.get("after")
    if not isinstance(after_status, dict):
        return None
    manager_details = after_status.get("manager_details")
    detail_items = manager_details if isinstance(manager_details, list) else []
    unhealthy_managers = [
        str(detail.get("manager"))
        for detail in detail_items
        if isinstance(detail, dict) and detail.get("integrity") in {"missing", "stale", "tampered"}
    ]
    path_repair_required = _update._string_list(after_status.get("path_repair_required"))
    if unhealthy_managers:
        return f"Package firewall shims still need repair after update for {', '.join(unhealthy_managers)}."
    repair_result = refresh_payload.get("repair")
    repaired = _update._string_list(repair_result.get("repaired")) if isinstance(repair_result, dict) else []
    if repaired:
        note = f"Refreshed package firewall shims during update for {', '.join(repaired)}."
        if path_repair_required:
            note += f" Restart your shell to reactivate {', '.join(path_repair_required)}."
        return note
    if path_repair_required:
        return (
            "Package firewall shims are current, but PATH repair is still required for "
            f"{', '.join(path_repair_required)}."
        )
    return None


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
