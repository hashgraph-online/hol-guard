"""Admission and planning for an installed HOL Guard update."""

from __future__ import annotations

from pathlib import Path

from ..adapters.base import HarnessContext
from ..store import GuardStore


def _read_direct_url_dir_info(direct_url: dict[str, object] | None) -> dict[str, object]:
    if direct_url is None:
        return {}
    dir_info = direct_url.get("dir_info")
    return dir_info if isinstance(dir_info, dict) else {}


def _authority_blocks_downgrade(
    store: GuardStore | None,
    *,
    guard_home: Path,
    current_version: str,
    candidate_version: str | None,
) -> bool:
    if candidate_version is None:
        return False
    try:
        if _update.Version(candidate_version) >= _update.Version(current_version):
            return False
    except _update.InvalidVersion:
        return False
    authority_store = store or _update.GuardStore(guard_home)
    authority = authority_store.read_extension_control_authority_for_registry(
        _update.BUILT_IN_COMMAND_EXTENSION_REGISTRY
    )
    return authority.health is not _update.AuthorityHealth.UNENROLLED


def run_guard_update(
    *,
    dry_run: bool,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    workspace: str | None = None,
    now: str | None = None,
    force_pypi_reinstall: bool = False,
    wheel: str | None = None,
    guard_home: Path | None = None,
    include_alpha: bool = False,
) -> tuple[dict[str, object], int]:
    installer = "desktop" if _update._is_desktop_managed_runtime() else _update._installer_kind()
    payload: dict[str, object] = {
        "installer": installer,
        "dry_run": dry_run,
    }
    managed_policy_state = _update.load_managed_policy()
    managed_update_blocked = managed_policy_state.status != "absent" and (
        managed_policy_state.policy is None or managed_policy_state.policy.update.owner == "mdm"
    )
    if managed_update_blocked:
        payload.update(
            {
                "status": "skipped",
                "changed": False,
                "reason_code": "mdm_update_owned",
                "message": "HOL Guard updates are managed by the organization.",
            }
        )
        return payload, 0
    managed_policy = managed_policy_state.policy
    network_policy = managed_policy.network if managed_policy is not None else _update.ManagedNetworkPolicy()
    configured_index_url = managed_policy.update.index_url if managed_policy is not None else None
    if not network_policy.allow_public_registries and configured_index_url is None:
        payload.update(
            {
                "status": "blocked",
                "changed": False,
                "reason_code": "update_source_unconfigured",
                "message": "HOL Guard update requires an organization-configured package source.",
            }
        )
        return payload, 1
    requested_wheel_path, requested_wheel_error = _update._resolve_requested_wheel_path(wheel)
    if requested_wheel_error is not None:
        payload["status"] = "failed"
        payload["changed"] = False
        payload["reason_code"] = "update_artifact_invalid"
        payload["error"] = requested_wheel_error
        payload["message"] = "HOL Guard update failed before the installer started."
        return payload, 1
    if requested_wheel_path is not None:
        payload["requested_wheel"] = str(requested_wheel_path)
    if guard_home is not None:
        resolved_guard_home = guard_home.expanduser().resolve()
    elif context is not None:
        resolved_guard_home = context.guard_home.expanduser().resolve()
    else:
        resolved_guard_home = _update.resolve_guard_home()
    daemon_refresh_required = context is not None and (resolved_guard_home / "daemon-state.json").is_file()
    if context is not None:
        trusted_workspace = context.workspace_dir
    elif workspace:
        trusted_workspace = _update.Path(workspace).expanduser()
    else:
        trusted_workspace = _update.Path.cwd()
    if installer == "desktop":
        return _update.run_desktop_managed_update(
            payload,
            dry_run=dry_run,
            include_alpha=include_alpha,
            force_pypi_reinstall=force_pypi_reinstall,
            requested_wheel_path=requested_wheel_path,
            context=context,
            store=store,
            workspace=workspace,
            now=now,
            network_policy=network_policy,
            daemon_refresh_required=daemon_refresh_required,
        )
    try:
        update_context = _update.build_trusted_update_context(
            guard_home=resolved_guard_home,
            workspace_dir=trusted_workspace,
            installer_kind=installer,
            source_url=configured_index_url,
            source_kind="managed_index" if configured_index_url is not None else "pypi",
            proxy_mode=network_policy.proxy_mode,
            proxy_url=network_policy.proxy_url,
            ca_bundle_path=network_policy.ca_bundle_path,
        )
    except _update.UpdateSubprocessError as error:
        return _update._trusted_update_failure(payload, error)
    payload["trusted_update"] = _update._trusted_update_public_payload(update_context)
    try:
        installed_distribution = update_context.query_distribution()
    except _update.UpdateSubprocessError as error:
        return _update._trusted_update_failure(payload, error)
    current_version = installed_distribution.version
    direct_url = installed_distribution.direct_url
    local_source_install = _update._local_source_install_payload(direct_url)
    local_archive_install = _update._recover_local_archive_install(
        _update._local_archive_install_payload(direct_url),
        direct_url=direct_url,
        guard_home=resolved_guard_home,
        installed_version=current_version,
    )
    vcs_install = _update._vcs_install_payload(direct_url)
    payload["current_version"] = current_version
    if direct_url is not None:
        payload["direct_url"] = _update._public_direct_url_payload(direct_url)
        is_editable = bool(_update._read_direct_url_dir_info(direct_url).get("editable"))
        payload["editable_install"] = is_editable
        if local_source_install is not None:
            payload["source_install"] = local_source_install
        if local_archive_install is not None:
            payload["archive_install"] = local_archive_install
        if vcs_install is not None:
            payload["vcs_install"] = vcs_install
        if is_editable and requested_wheel_path is None:
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for editable installs. Re-run your local install workflow instead."
            )
            return payload, 0
        if (
            local_source_install is not None
            and bool(local_source_install.get("path_exists"))
            and not force_pypi_reinstall
            and requested_wheel_path is None
        ):
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for local source installs. Re-run your local install workflow instead."
            )
            return payload, 0
        if (
            local_archive_install is not None
            and str(local_archive_install.get("archive_type") or "") == "wheel"
            and not force_pypi_reinstall
            and requested_wheel_path is None
        ):
            payload["status"] = "skipped"
            payload["changed"] = False
            if bool(local_archive_install.get("path_exists")):
                payload["error"] = (
                    "Automatic update is disabled for local wheel installs. "
                    f"Re-run `{_update._local_archive_update_hint(local_archive_install)}` "
                    "or your local install workflow instead."
                )
            else:
                payload["error"] = (
                    "Automatic update is disabled for local wheel installs when the original wheel file is gone. "
                    "Pass a new wheel with `hol-guard update --wheel <wheel-or-directory>` "
                    "or re-run your local install workflow instead."
                )
            return payload, 0
        if local_source_install is not None and not bool(local_source_install.get("path_exists")):
            payload["recovery_source_install"] = True
    version_check = _update._version_check_payload(
        current_version,
        source_kind=update_context.source.public_name,
        network_policy=network_policy,
        include_alpha=include_alpha,
    )
    if requested_wheel_path is None and _update._python_runtime_blocks_update(version_check):
        payload.update(
            {
                "version_check": version_check,
                "status": "blocked",
                "changed": False,
                "python_update_required": True,
                "message": _update._python_runtime_block_message(version_check),
            }
        )
        return payload, 1
    use_pypi = force_pypi_reinstall or _update._should_upgrade_from_pypi(
        current_version=current_version,
        version_check=version_check,
        vcs_install=vcs_install,
        local_source_install=local_source_install,
    )
    target_version = None
    if version_check.get("update_available") is True:
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            target_version = latest_version.strip()
            use_pypi = True
    trusted_wheel: _update.TrustedWheelArtifact | None = None
    if requested_wheel_path is not None:
        try:
            trusted_wheel = _update.stage_trusted_wheel(
                requested_wheel_path,
                neutral_cwd=update_context.neutral_cwd,
            )
        except _update.UpdateArtifactError as error:
            return _update._trusted_update_failure(payload, _update.UpdateSubprocessError(error.reason_code))
    downgrade_candidate = trusted_wheel.version if trusted_wheel is not None else target_version
    if _update._authority_blocks_downgrade(
        store,
        guard_home=resolved_guard_home,
        current_version=current_version,
        candidate_version=downgrade_candidate,
    ):
        if trusted_wheel is not None:
            trusted_wheel.cleanup()
        payload.update(
            {
                "status": "blocked",
                "changed": False,
                "reason_code": "extension_control_authority_downgrade_blocked",
                "message": "HOL Guard cannot downgrade while extension-control authority is active.",
            }
        )
        return payload, 1
    command = _update._update_command(
        installer,
        use_pypi=use_pypi,
        target_version=target_version,
        wheel_path=requested_wheel_path,
    )
    execution_display_command = _update._update_command(
        installer,
        use_pypi=use_pypi,
        target_version=target_version,
        wheel_path=trusted_wheel.staged_path if trusted_wheel is not None else None,
    )
    try:
        execution_command = update_context.build_installer_command(execution_display_command)
    except _update.UpdateSubprocessError as error:
        return _update._trusted_update_failure(payload, error, trusted_wheel=trusted_wheel)
    if force_pypi_reinstall:
        payload["recovery_reinstall"] = True
    payload.update(
        {
            "command": command,
            "retry_command": _update._safe_update_retry_command(requested_wheel_path, include_alpha=include_alpha),
            "binary_diagnostics": _update._binary_diagnostics(command, installer),
            "version_check": version_check,
        }
    )
    if requested_wheel_path is not None:
        payload["upgrade_source"] = "local_wheel"
        if trusted_wheel is not None:
            payload["wheel_sha256"] = trusted_wheel.sha256
            payload["wheel_version"] = trusted_wheel.version
    else:
        payload["upgrade_source"] = update_context.source.public_name
        if include_alpha:
            payload["release_channel"] = "alpha"
    already_current = (
        requested_wheel_path is None
        and not force_pypi_reinstall
        and version_check.get("update_available") is False
        and str(version_check.get("status") or "") == "current"
        and local_source_install is None
        and local_archive_install is None
        and vcs_install is None
    )
    if dry_run:
        if already_current:
            payload["status"] = "current"
            payload["changed"] = False
            payload["resulting_version"] = current_version
            payload["message"] = _update.already_current_update_message(version_check)
            if trusted_wheel is not None:
                trusted_wheel.cleanup()
            return payload, 0
        payload["status"] = "planned"
        payload["changed"] = False
        payload["message"] = _update._planned_update_message(
            version_check=version_check,
            use_pypi=use_pypi,
            wheel_path=requested_wheel_path,
        )
        if trusted_wheel is not None:
            trusted_wheel.cleanup()
        return payload, 0
    if already_current:
        payload["status"] = "current"
        payload["changed"] = False
        payload["resulting_version"] = current_version
        payload["message"] = _update.already_current_update_message(version_check)
        newer_runtime = (
            _update._verified_newer_guard_daemon(
                context.guard_home,
                minimum_version=current_version,
            )
            if context is not None
            else None
        )
        if newer_runtime is not None:
            payload["daemon_refresh"] = newer_runtime
            payload["runtime_artifact_owner"] = "newer_runtime"
            _update._append_payload_note(
                payload,
                "Kept newer-runtime package shims and harness hooks unchanged.",
            )
            return payload, 0
        # Skip force-reinstall/upgrade noise when PyPI already reports current.
        package_shims, package_shim_note = _update._refresh_package_shims_after_update(
            context=context,
            dry_run=dry_run,
            update_context=update_context,
        )
        if package_shims is not None:
            payload["package_shims"] = package_shims
        _update._append_payload_note(payload, package_shim_note)
        repaired_installs, repair_notes = _update._repair_supported_harnesses(
            context=context,
            store=store,
            workspace=workspace,
            now=now,
            dry_run=dry_run,
            update_context=update_context,
        )
        if repair_notes:
            payload["notes"] = [*_update._payload_notes(payload), *repair_notes]
        if repaired_installs:
            payload["managed_installs"] = repaired_installs
            if len(repaired_installs) == 1:
                payload["managed_install"] = repaired_installs[0]
        return payload, 0
    return _update._execute_update(
        payload=payload,
        installer=installer,
        dry_run=dry_run,
        context=context,
        store=store,
        workspace=workspace,
        now=now,
        force_pypi_reinstall=force_pypi_reinstall,
        include_alpha=include_alpha,
        resolved_guard_home=resolved_guard_home,
        network_policy=network_policy,
        requested_wheel_path=requested_wheel_path,
        trusted_wheel=trusted_wheel,
        target_version=target_version,
        update_context=update_context,
        current_version=current_version,
        command=command,
        execution_command=execution_command,
        daemon_refresh_required=daemon_refresh_required,
    )


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
