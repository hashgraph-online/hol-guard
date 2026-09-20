"""Installer retries and finalization after update admission."""

from __future__ import annotations

from pathlib import Path

from ..adapters.base import HarnessContext
from ..mdm.contracts import ManagedNetworkPolicy
from ..store import GuardStore
from .update_artifact import TrustedWheelArtifact
from .update_subprocess import TrustedUpdateContext


def _execute_update(
    *,
    payload: dict[str, object],
    installer: str,
    dry_run: bool,
    context: HarnessContext | None,
    store: GuardStore | None,
    workspace: str | None,
    now: str | None,
    force_pypi_reinstall: bool,
    include_alpha: bool,
    resolved_guard_home: Path,
    network_policy: ManagedNetworkPolicy,
    requested_wheel_path: Path | None,
    trusted_wheel: TrustedWheelArtifact | None,
    target_version: str | None,
    update_context: TrustedUpdateContext,
    current_version: str,
    command: list[str],
    execution_command: list[str],
    daemon_refresh_required: bool,
) -> tuple[dict[str, object], int]:
    active_command = execution_command
    active_display_command = command
    attempted_force_retry = False

    def finish_update(result: tuple[dict[str, object], int]) -> tuple[dict[str, object], int]:
        return result

    attempted_pipx_recovery = False
    propagation_retries = 0
    installer_execution_started = False
    while True:
        try:
            if trusted_wheel is not None:
                trusted_wheel.revalidate()
            installer_execution_started = True
            result = update_context.run(active_command)
        except _update.UpdateArtifactError as error:
            return finish_update(
                _update._trusted_update_failure(
                    payload,
                    _update.UpdateSubprocessError(error.reason_code),
                    trusted_wheel=trusted_wheel,
                    retain_trusted_wheel=installer_execution_started,
                )
            )
        except _update.UpdateSubprocessError as error:
            return finish_update(
                _update._trusted_update_failure(
                    payload,
                    error,
                    trusted_wheel=trusted_wheel,
                    retain_trusted_wheel=installer_execution_started,
                )
            )
        payload["command"] = active_display_command
        payload["stdout"] = _update._normalize_output_text(result.stdout)
        payload["stderr"] = _update._normalize_output_text(result.stderr)
        payload["return_code"] = result.returncode
        if result.output_limited:
            return finish_update(
                _update._trusted_update_failure(
                    payload,
                    _update.UpdateSubprocessError("update_installer_output_limit"),
                    trusted_wheel=trusted_wheel,
                    retain_trusted_wheel=installer_execution_started,
                )
            )
        _update.importlib.invalidate_caches()
        try:
            payload["resulting_version"] = _update._current_version_from_subprocess(update_context)
        except _update.UpdateSubprocessError as error:
            return finish_update(
                _update._trusted_update_failure(
                    payload,
                    error,
                    trusted_wheel=trusted_wheel,
                    retain_trusted_wheel=installer_execution_started,
                )
            )
        initial_version_check = payload.get("version_check")
        resulting_version = str(payload.get("resulting_version") or current_version)
        if result.returncode != 0:
            installer_output = _update._installer_output_text(payload.get("stdout"), payload.get("stderr"))
            if (
                installer == "pipx"
                and not attempted_pipx_recovery
                and _update._contains_any(installer_output, _update._PIPX_LAUNCHER_FAILURE_HINTS)
            ):
                pip_display_command = _update._update_command(
                    "pip",
                    use_pypi=trusted_wheel is None,
                    target_version=target_version,
                    wheel_path=requested_wheel_path if trusted_wheel is not None else None,
                )
                pip_execution_display_command = _update._update_command(
                    "pip",
                    use_pypi=trusted_wheel is None,
                    target_version=target_version,
                    wheel_path=trusted_wheel.staged_path if trusted_wheel is not None else None,
                )
                try:
                    active_command = update_context.build_python_pip_command(pip_execution_display_command)
                except _update.UpdateSubprocessError as error:
                    return _update._trusted_update_failure(payload, error, trusted_wheel=trusted_wheel)
                attempted_pipx_recovery = True
                active_display_command = pip_display_command
                payload["installer_recovery"] = "trusted_python_pip"
                continue
            if requested_wheel_path is None and _update._is_pypi_propagation_failure(installer_output):
                if propagation_retries < _update._PYPI_PROPAGATION_RETRY_LIMIT:
                    propagation_retries += 1
                    payload["propagation_retries"] = propagation_retries
                    _update.time.sleep(_update._PYPI_PROPAGATION_RETRY_DELAY_SECONDS)
                    continue
                payload["status"] = "deferred"
                payload["changed"] = False
                payload["reason_code"] = "update_release_propagating"
                payload["message"] = (
                    "The newest HOL Guard release is still reaching PyPI. "
                    "Your current installation remains active; try the update again shortly."
                )
                payload.pop("retry_command", None)
                return payload, 0
            conflict_message = _update._dependency_conflict_message(
                installer_output,
            )
            if conflict_message:
                payload["status"] = "blocked"
                payload["changed"] = False
                payload["dependency_conflict"] = True
                payload["message"] = conflict_message
                payload.pop("retry_command", None)
                if trusted_wheel is not None:
                    _update._retain_local_wheel_staging(payload)
                return finish_update((payload, 1))
            payload["status"] = "failed"
            payload["changed"] = False
            payload["reason_code"] = "update_installer_failed"
            payload["message"] = "HOL Guard update failed."
            if trusted_wheel is not None:
                _update._retain_local_wheel_staging(payload)
            return finish_update((payload, 1))
        if trusted_wheel is not None:
            try:
                if _update.Version(resulting_version) != _update.Version(trusted_wheel.version):
                    return finish_update(
                        _update._trusted_update_failure(
                            payload,
                            _update.UpdateSubprocessError("update_version_mismatch"),
                            trusted_wheel=trusted_wheel,
                            retain_trusted_wheel=installer_execution_started,
                        )
                    )
            except _update.InvalidVersion:
                return finish_update(
                    _update._trusted_update_failure(
                        payload,
                        _update.UpdateSubprocessError("update_version_output_invalid"),
                        trusted_wheel=trusted_wheel,
                        retain_trusted_wheel=installer_execution_started,
                    )
                )
        if trusted_wheel is not None:
            _update._record_verified_local_wheel_receipt(
                payload,
                update_context=update_context,
                trusted_wheel=trusted_wheel,
                guard_home=resolved_guard_home,
                installed_version=resulting_version,
            )
        post_version_check = _update._version_check_payload(
            resulting_version,
            source_kind=update_context.source.public_name,
            network_policy=network_policy,
            include_alpha=include_alpha,
        )
        payload["post_version_check"] = post_version_check
        payload["version_check"] = _update._merge_version_checks(
            initial_version_check,
            post_version_check,
            resulting_version,
        )
        payload["status"] = _update._success_status(payload)
        payload["changed"] = (
            _update._version_changed(current_version, resulting_version) or payload["status"] == "updated"
        )
        if (
            not attempted_force_retry
            and not force_pypi_reinstall
            and requested_wheel_path is None
            and payload.get("status") == "stale"
        ):
            target_version = None
            active_version_check = payload.get("version_check")
            if isinstance(active_version_check, dict):
                latest = active_version_check.get("latest_version")
                if isinstance(latest, str) and latest.strip():
                    target_version = latest.strip()
            retry_command = _update._update_command(installer, use_pypi=True, target_version=target_version)
            if retry_command != active_display_command:
                attempted_force_retry = True
                active_display_command = retry_command
                try:
                    active_command = update_context.build_installer_command(retry_command)
                except _update.UpdateSubprocessError as error:
                    return finish_update(_update._trusted_update_failure(payload, error, trusted_wheel=trusted_wheel))
                payload["upgrade_source"] = update_context.source.public_name
                continue
        break
    conflict_message = _update._dependency_conflict_message(
        _update._installer_output_text(payload.get("stdout"), payload.get("stderr")),
    )
    if payload.get("status") == "stale" and conflict_message:
        payload["status"] = "blocked"
        payload["dependency_conflict"] = True
        payload["message"] = conflict_message
        payload.pop("retry_command", None)
    stale_retry_command = "" if payload.get("status") == "blocked" else _update._stale_retry_command(payload)
    if stale_retry_command:
        payload["retry_command"] = stale_retry_command
    if payload.get("status") != "blocked":
        payload["message"] = _update._success_message(
            status=str(payload["status"]),
            current_version=current_version,
            resulting_version=resulting_version,
            version_check=payload.get("version_check"),
            retry_command=stale_retry_command,
        )
    notes = _update._success_notes(payload)
    if notes:
        payload["notes"] = [*_update._payload_notes(payload), *notes]
    daemon_refresh: dict[str, object] | None = None
    if context is not None:
        daemon_refresh, daemon_refresh_note = _update.refresh_guard_daemon_after_update(
            context,
            update_context=update_context,
            minimum_version=resulting_version,
        )
        if daemon_refresh is not None:
            payload["daemon_refresh"] = daemon_refresh
        _update._append_payload_note(payload, daemon_refresh_note)
    newer_runtime_owns_artifacts = (
        isinstance(daemon_refresh, dict)
        and daemon_refresh.get("status") == "retained_newer_runtime"
        and daemon_refresh.get("runtime_verified") is True
    )
    if newer_runtime_owns_artifacts:
        payload["runtime_artifact_owner"] = "newer_runtime"
        _update._append_payload_note(
            payload,
            "Deferred package shim and harness hook repair to the verified newer runtime.",
        )
    elif payload.get("changed") is True or payload.get("status") == "current":
        package_shims, package_shim_note = _update._refresh_package_shims_after_update(
            context=context,
            dry_run=dry_run,
            update_context=update_context,
        )
        if package_shims is not None:
            payload["package_shims"] = package_shims
        _update._append_payload_note(payload, package_shim_note)
    if not newer_runtime_owns_artifacts:
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
    if context is not None:
        daemon_refresh_succeeded = _update._daemon_refresh_outcome_succeeded(
            daemon_refresh,
            allow_not_running=True,
        )
        if daemon_refresh_required and not daemon_refresh_succeeded:
            payload.update(
                {
                    "status": "failed",
                    "reason_code": "update_daemon_refresh_failed",
                    "message": "HOL Guard was updated, but its daemon could not be restarted safely.",
                }
            )
            return finish_update((payload, 1))
    return finish_update((payload, 0))


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
