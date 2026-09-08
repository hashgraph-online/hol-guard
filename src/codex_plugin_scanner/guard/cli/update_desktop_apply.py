"""Apply signed Core updates for Desktop-managed HOL Guard installs."""

from __future__ import annotations

import sys
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..adapters.base import HarnessContext
from ..daemon.runtime_peer import (
    daemon_refresh_outcome_succeeded,
    retained_desktop_owner_note,
    retained_desktop_owner_payload,
)
from ..mdm.contracts import ManagedNetworkPolicy
from ..store import GuardStore
from .update_desktop_core import (
    DesktopCoreUpdateError,
    apply_desktop_core_update,
    desktop_core_updates_supported,
    desktop_core_uses_alpha_channel,
    pypi_desktop_core_versions,
    select_desktop_core_latest,
)

_DAEMON_REFRESH_FAILED = "HOL Guard was updated, but its daemon could not be restarted safely."
_APPLY_FAILURE_FALLBACK = "HOL Guard could not apply the signed Core update. The installed version stays in place."
_APPLY_FAILURE_MESSAGES = {
    "desktop_core_download_failed": (
        "This Core build is not available for Desktop yet. The installed version stays in place."
    ),
    "desktop_core_integrity_mismatch": (
        "The downloaded Core did not match its signed manifest. The installed version stays in place."
    ),
    "desktop_core_signature_invalid": (
        "Desktop could not verify the Core signature. The installed version stays in place."
    ),
    "desktop_core_signature_mismatch": (
        "Desktop could not verify the Core signature. The installed version stays in place."
    ),
    "desktop_core_desktop_too_old": (
        "This Desktop app is too old for the latest Core. Install the newest Desktop, then update Guard again."
    ),
}


def desktop_update_status_state(
    *,
    current_version: str,
    requested_alpha: bool,
) -> tuple[bool, bool, str | None]:
    if not desktop_core_updates_supported():
        return (
            requested_alpha,
            False,
            "This platform receives Core updates with HOL Guard Desktop releases.",
        )
    include_alpha = desktop_core_uses_alpha_channel(current_version, requested_alpha=requested_alpha)
    return include_alpha, True, None


def refine_desktop_version_check(
    current_version: str,
    version_check: dict[str, object],
    *,
    candidates: list[str],
    include_alpha: bool,
) -> dict[str, object]:
    status = str(version_check.get("status") or "")
    source = str(version_check.get("source") or "")
    if status == "unavailable" or source not in {"pypi", "desktop_core"}:
        return version_check
    known = [item.strip() for item in candidates if item.strip()]
    latest = version_check.get("latest_version")
    if isinstance(latest, str) and latest.strip() and latest.strip() not in known:
        known.append(latest.strip())
    current = current_version.strip()
    if current and current not in known:
        known.append(current)
    selected = select_desktop_core_latest(current_version, known, include_alpha=include_alpha)
    refined = dict(version_check)
    refined["source"] = "desktop_core"
    if selected is None:
        refined["latest_version"] = current_version
        refined["update_available"] = False
        refined["status"] = "current"
        return refined
    try:
        newer = Version(selected) > Version(current_version)
    except InvalidVersion:
        newer = False
    refined["latest_version"] = selected
    refined["update_available"] = newer
    refined["status"] = "stale" if newer else "current"
    return refined


def desktop_core_apply_failure_message(reason_code: str) -> str:
    return _APPLY_FAILURE_MESSAGES.get(reason_code, _APPLY_FAILURE_FALLBACK)


def finalize_desktop_update_status(
    payload: dict[str, object],
    *,
    pypi_payload: object,
) -> dict[str, object]:
    if payload.get("installer") != "desktop":
        return payload
    version_check = payload.get("version_check")
    if not isinstance(version_check, dict):
        return payload
    include_alpha = payload.get("release_channel") == "alpha"
    candidates = pypi_desktop_core_versions(pypi_payload, include_alpha=include_alpha)
    current_version = str(payload.get("current_version") or "")
    refined = refine_desktop_version_check(
        current_version,
        version_check,
        candidates=candidates,
        include_alpha=include_alpha,
    )
    latest_version = refined.get("latest_version")
    payload["version_check"] = refined
    payload["latest_version"] = latest_version if isinstance(latest_version, str) else None
    payload["update_available"] = payload.get("auto_updatable") is True and refined.get("update_available") is True
    return payload


def run_desktop_managed_update(
    payload: dict[str, object],
    *,
    dry_run: bool,
    include_alpha: bool,
    force_pypi_reinstall: bool,
    requested_wheel_path: Path | None,
    context: HarnessContext | None,
    store: GuardStore | None,
    workspace: str | None,
    now: str | None,
    network_policy: ManagedNetworkPolicy,
    daemon_refresh_required: bool,
) -> tuple[dict[str, object], int]:
    blocked = _desktop_update_preflight(
        payload,
        include_alpha=include_alpha,
        force_pypi_reinstall=force_pypi_reinstall,
        requested_wheel_path=requested_wheel_path,
    )
    if blocked is not None:
        return blocked
    from . import update_commands as commands

    include_alpha = payload.get("release_channel") == "alpha"
    current_version = str(payload["current_version"])
    version_check = refine_desktop_version_check(
        current_version,
        commands._version_check_payload(
            current_version,
            source_kind="pypi",
            network_policy=network_policy,
            include_alpha=include_alpha,
        ),
        candidates=pypi_desktop_core_versions(
            commands._last_pypi_payload,
            include_alpha=include_alpha,
        ),
        include_alpha=include_alpha,
    )
    payload["version_check"] = version_check
    already_current = (
        version_check.get("update_available") is False and str(version_check.get("status") or "") == "current"
    )
    latest_version = version_check.get("latest_version")
    target_version = latest_version.strip() if isinstance(latest_version, str) and latest_version.strip() else None
    if dry_run:
        if not already_current and target_version is None:
            return _unavailable_desktop_version(payload)
        payload["status"] = "current" if already_current else "planned"
        payload["changed"] = False
        payload["resulting_version"] = current_version if already_current else target_version
        payload["message"] = (
            commands.already_current_update_message(version_check)
            if already_current
            else "Review the planned signed Core update before applying it."
        )
        return payload, 0
    if already_current:
        return _desktop_already_current(
            payload,
            current_version=current_version,
            version_check=version_check,
            context=context,
            daemon_refresh_required=daemon_refresh_required,
        )
    if target_version is None:
        return _unavailable_desktop_version(payload)
    return _desktop_apply_target(
        payload,
        current_version=current_version,
        target_version=target_version,
        include_alpha=include_alpha,
        network_policy=network_policy,
        version_check=version_check,
        context=context,
        store=store,
        workspace=workspace,
        now=now,
        daemon_refresh_required=daemon_refresh_required,
    )


def refresh_desktop_core_daemon(
    context: HarnessContext,
    *,
    executable: Path,
    minimum_version: str | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    from ..daemon.manager import (
        ensure_guard_daemon_after_update,
        guard_daemon_retirement_is_complete,
        retire_all_guard_daemons_for_home,
    )

    try:
        retire_all_guard_daemons_for_home(context.guard_home)
        if not guard_daemon_retirement_is_complete(context.guard_home):
            # The Guard Desktop supervisor can respawn a retired daemon faster
            # than retirement completes. When the respawn already serves the
            # applied version, keeping it is success instead of a failed update.
            retained = retained_desktop_owner_payload(
                context.guard_home,
                minimum_version=minimum_version,
            )
            if retained is not None:
                return retained, retained_desktop_owner_note(retained.get("daemon_version"))
            return None, "Could not stop the running Guard daemon before launching the updated Core."
        url = ensure_guard_daemon_after_update(
            context.guard_home,
            home_dir=context.home_dir,
            executable=executable,
        )
    except (OSError, RuntimeError) as error:
        return None, f"Could not restart the Guard daemon after update: {error}"
    # ensure_guard_daemon_after_update only returns once the restarted daemon
    # answers, so the outcome carries the same verification marker as the
    # CLI refresh path.
    return {"status": "restarted", "url": url, "runtime_verified": True}, None


def _desktop_update_preflight(
    payload: dict[str, object],
    *,
    include_alpha: bool,
    force_pypi_reinstall: bool,
    requested_wheel_path: Path | None,
) -> tuple[dict[str, object], int] | None:
    from . import update_commands as commands

    payload["upgrade_source"] = "desktop_core"
    if force_pypi_reinstall or requested_wheel_path is not None:
        return _blocked_desktop_payload(
            payload,
            "desktop_core_uses_signed_feed",
            "This HOL Guard install updates from the signed Core feed.",
        )
    if not desktop_core_updates_supported():
        return _blocked_desktop_payload(
            payload,
            "desktop_core_platform_unsupported",
            "This platform receives Core updates with HOL Guard Desktop releases.",
        )
    current_version = commands._current_version()
    payload["current_version"] = current_version
    include_alpha = desktop_core_uses_alpha_channel(current_version, requested_alpha=include_alpha)
    payload["retry_command"] = commands._safe_update_retry_command(None, include_alpha=include_alpha)
    payload["release_channel"] = "alpha" if include_alpha else "stable"
    return None


def _desktop_already_current(
    payload: dict[str, object],
    *,
    current_version: str,
    version_check: dict[str, object],
    context: HarnessContext | None,
    daemon_refresh_required: bool,
) -> tuple[dict[str, object], int]:
    from . import update_commands as commands

    payload["status"] = "current"
    payload["changed"] = False
    payload["resulting_version"] = current_version
    payload["message"] = commands.already_current_update_message(version_check)
    if context is not None and daemon_refresh_required:
        return _refresh_or_fail(
            payload,
            context=context,
            executable=Path(sys.executable).resolve(),
            minimum_version=current_version,
            required=True,
        )
    return payload, 0


def _desktop_apply_target(
    payload: dict[str, object],
    *,
    current_version: str,
    target_version: str,
    include_alpha: bool,
    network_policy: ManagedNetworkPolicy,
    version_check: dict[str, object],
    context: HarnessContext | None,
    store: GuardStore | None,
    workspace: str | None,
    now: str | None,
    daemon_refresh_required: bool,
) -> tuple[dict[str, object], int]:
    from . import update_commands as commands

    try:
        applied = apply_desktop_core_update(
            current_version=current_version,
            target_version=target_version,
            include_alpha=include_alpha,
            network_policy=network_policy,
        )
    except DesktopCoreUpdateError as error:
        payload.update(
            {
                "status": "failed",
                "changed": False,
                "reason_code": error.reason_code,
                "error": str(error),
                "message": desktop_core_apply_failure_message(error.reason_code),
            }
        )
        return payload, 1
    payload["resulting_version"] = applied.version
    payload["changed"] = applied.changed
    payload["status"] = "updated" if applied.changed else "current"
    payload["message"] = (
        f"HOL Guard updated to {applied.version}."
        if applied.changed
        else commands.already_current_update_message(version_check)
    )
    if context is not None and store is not None and now is not None:
        repaired_installs, repair_notes = commands._repair_supported_harnesses_in_process(
            context=context,
            store=store,
            workspace=workspace,
            now=now,
            dry_run=False,
        )
        if repair_notes:
            payload["notes"] = [*commands._payload_notes(payload), *repair_notes]
        if repaired_installs:
            payload["managed_installs"] = repaired_installs
    if context is not None and (applied.changed or daemon_refresh_required):
        return _refresh_or_fail(
            payload,
            context=context,
            executable=applied.executable,
            minimum_version=applied.version,
            required=daemon_refresh_required,
        )
    return payload, 0


def _refresh_or_fail(
    payload: dict[str, object],
    *,
    context: HarnessContext,
    executable: Path,
    minimum_version: str,
    required: bool,
) -> tuple[dict[str, object], int]:
    from . import update_commands as commands

    daemon_refresh, daemon_refresh_note = refresh_desktop_core_daemon(
        context,
        executable=executable,
        minimum_version=minimum_version,
    )
    if daemon_refresh is not None:
        payload["daemon_refresh"] = daemon_refresh
    commands._append_payload_note(payload, daemon_refresh_note)
    if required and not daemon_refresh_outcome_succeeded(daemon_refresh):
        payload.update(
            {
                "status": "failed",
                "reason_code": "update_daemon_refresh_failed",
                "message": _DAEMON_REFRESH_FAILED,
            }
        )
        return payload, 1
    return payload, 0


def _unavailable_desktop_version(payload: dict[str, object]) -> tuple[dict[str, object], int]:
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": "desktop_core_version_unavailable",
            "message": "HOL Guard could not determine the latest Core version.",
        }
    )
    return payload, 1


def _blocked_desktop_payload(
    payload: dict[str, object],
    reason_code: str,
    message: str,
) -> tuple[dict[str, object], int]:
    payload.update(
        {
            "status": "blocked",
            "changed": False,
            "reason_code": reason_code,
            "message": message,
        }
    )
    return payload, 1
