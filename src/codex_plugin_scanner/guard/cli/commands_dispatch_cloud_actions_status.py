"""`cloud-actions status` and `cloud-actions doctor`.

Both read the saved sign-in (profile) and ask Guard Cloud whether it still
accepts it (`cloud_actions_health`); `status --offline` does not ask. `doctor`
also checks that the saved files are private and which AI tools are set up,
and can save its results, without any credential, to a new private file.
The health modules are imported only when one of these commands runs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .commands_dispatch_cloud_actions import (
    CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
    CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
    CLOUD_ACTIONS_UNAVAILABLE_EXIT,
    _login_hint,  # pyright: ignore[reportPrivateUsage]
    _profile_fields,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from .cloud_actions_health import HealthCheck
    from .cloud_actions_session import CloudActionsProfile, CloudActionsSecrets, CloudActionsSessionStore
    from .commands_dispatch_cloud_actions import _Reply  # pyright: ignore[reportPrivateUsage]

CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA = "guard.cloud-actions.diagnostics.v1"


def _live_checks(profile: CloudActionsProfile, access_token: str, *, offline: bool) -> tuple[HealthCheck, HealthCheck]:
    from .cloud_actions_health import HealthCheck, check_connection, check_service

    if offline:
        skipped = HealthCheck("not_checked", "Not checked (--offline).")
        return skipped, skipped
    service = check_service(profile)
    if service.state in {"offline", "not_turned_on", "profile_damaged"}:
        return service, HealthCheck(service.state, service.message, service.http_status)
    return service, check_connection(profile, access_token)


def status(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply) -> int:
    from .cloud_actions_health import checked_at

    profile = store.load(args.profile)
    requested = args.cloud_workspace
    secrets = store.load_secrets(args.profile) if profile is not None else None
    if profile is None or secrets is None:
        return reply(
            0,
            f"Not signed in (profile {args.profile}). Run `{_login_hint(args.profile, requested)}`.",
            state="signed_out",
            profile=args.profile,
            accounts="not_available_yet",
            included_actions="not_available_yet",
        )
    state = "expired" if profile.is_expired() else "signed_in"
    service, connection = _live_checks(profile, secrets.access_token, offline=args.offline)
    fields: dict[str, object] = {
        "state": state,
        **_profile_fields(profile),
        "checked_at": checked_at(),
        "service": service.as_dict(),
        "connection": connection.as_dict(),
        "included_actions": "not_available_yet",
        "accounts": "not_available_yet",
    }
    lines = [
        f"Profile {profile.name}: {'sign-in expired' if state == 'expired' else 'signed in'}",
        f"Guard Cloud: {profile.issuer}",
        f"Workspace: {profile.workspace_id}",
        f"Cloud actions: {service.message}",
        f"Sign-in: {connection.message}",
        "Included actions: not available yet",
        "Connected accounts: not available yet",
    ]
    if requested is not None:
        fields["workspace_matches"] = requested == profile.workspace_id
        if requested != profile.workspace_id:
            lines.append(f"Workspace {requested} needs its own sign-in: `{_login_hint(args.profile, requested)}`.")
    if connection.state in _SIGN_IN_AGAIN or service.state == "changed":
        lines.append(f"Sign in again: `{_login_hint(profile.name, profile.workspace_id)}`.")
    return reply(0, "\n".join(lines), **fields)


_SIGN_IN_AGAIN = frozenset({"sign_in_expired", "sign_in_again"})
_AI_TOOL_STATES = {
    "unchanged": "configured",
    "already_configured": "configured",
    "create_file": "not_configured",
    "add": "not_configured",
    "update": "points_elsewhere",
    "conflict": "conflict",
    "unreadable": "unreadable",
}


def _private_files(store: CloudActionsSessionStore, profile_name: str) -> HealthCheck:
    from .cloud_actions_health import HealthCheck

    if os.name == "nt":
        return HealthCheck("not_checked", "File permissions are not checked on Windows.")
    guard_home = store.root.parent
    profile_file = store.root / "profiles" / f"{profile_name}.json"
    # The Guard home may be readable by others, but if they can write to it they can
    # replace the Cloud actions folder beneath it, whatever that folder's own mode.
    replaceable = guard_home.exists() and guard_home.stat().st_mode & 0o022
    too_open = (["."] if replaceable else []) + [
        str(path.relative_to(guard_home))
        for path in (store.root, profile_file.parent, profile_file)
        if path.exists() and path.stat().st_mode & 0o077
    ]
    if too_open:
        return HealthCheck(
            "too_open",
            "Other users on this computer can read or replace Cloud actions files.",
            details=(("paths", too_open),),
        )
    return HealthCheck("private", "Cloud actions files are readable only by you.")


def _ai_tool_states(args: argparse.Namespace, url: str | None) -> dict[str, dict[str, object]]:
    from .cloud_actions_health import redact_home
    from .cloud_actions_host_config import SUPPORTED_AI_TOOLS, plan_host_config, settings_path

    explicit_home = getattr(args, "home", None)
    home = Path(explicit_home).expanduser() if explicit_home else Path.home()
    states: dict[str, dict[str, object]] = {}
    for ai_tool in SUPPORTED_AI_TOOLS:
        path = settings_path(ai_tool, home=home, environ=None if explicit_home else os.environ)
        entry: dict[str, object] = {"settings_file": redact_home(str(path), str(home))}
        if url is None:
            entry["state"] = "not_checked"
        else:
            plan = plan_host_config(ai_tool, path=path, url=url)
            entry["state"] = _AI_TOOL_STATES[plan.action]
            if plan.configured_as:
                entry["configured_as"] = list(plan.configured_as)
            if plan.action == "update" and plan.previous_url is not None:
                entry["points_to"] = plan.previous_url
        states[ai_tool] = entry
    return states


def doctor(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply) -> int:
    import platform

    from ...version import __version__
    from .cloud_actions_health import HealthCheck, checked_at

    profile = store.load(args.profile)
    secrets = store.load_secrets(args.profile) if profile is not None else None
    checks: dict[str, HealthCheck]
    if profile is None:
        sign_in = HealthCheck("signed_out", f"Not signed in (profile {args.profile}).")
    elif secrets is None:
        sign_in = HealthCheck("saved_sign_in_unreadable", "The saved sign-in could not be read. Sign in again.")
    elif profile.is_expired():
        sign_in = HealthCheck("expired", "The saved sign-in has expired. Sign in again.")
    else:
        sign_in = HealthCheck("signed_in", f"Signed in to workspace {profile.workspace_id}.")
    checks = {"sign_in": sign_in, "files": _private_files(store, args.profile)}
    if profile is not None and secrets is not None:
        checks["service"], checks["connection"] = _live_checks(profile, secrets.access_token, offline=False)
    else:
        skipped = HealthCheck("not_checked", "Not checked: no saved sign-in.")
        checks["service"], checks["connection"] = skipped, skipped
    url = profile.resource if profile is not None else None
    ai_tools = _ai_tool_states(args, url)

    if (
        sign_in.state != "signed_in"
        or checks["connection"].state in _SIGN_IN_AGAIN
        or checks["service"].state == "changed"
    ):
        result, code = "needs_sign_in", CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT
    elif not all(checks[name].ok for name in ("service", "connection")) or checks["files"].state == "too_open":
        result, code = "problems_found", CLOUD_ACTIONS_UNAVAILABLE_EXIT
    else:
        result, code = "ok", 0
    fields: dict[str, object] = {
        "result": result,
        "profile": args.profile,
        "checked_at": checked_at(),
        "hol_guard_version": __version__,
        "system": {"os": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "checks": {name: check.as_dict() for name, check in checks.items()},
        "ai_tools": ai_tools,
        "included_actions": "not_available_yet",
        "accounts": "not_available_yet",
    }
    if profile is not None:
        fields.update(_profile_fields(profile))
        fields["signed_in_at"] = profile.signed_in_at
    lines = [f"Cloud actions doctor (profile {args.profile}): {result.replace('_', ' ')}"]
    for name, title in (
        ("sign_in", "Sign-in"),
        ("files", "Saved files"),
        ("service", "Cloud actions"),
        ("connection", "Guard Cloud"),
    ):
        check = checks[name]
        lines.append(
            f"  {'ok ' if check.ok or check.state in {'signed_in', 'private'} else '!! '}{title}: {check.message}"
        )
    for ai_tool, entry in ai_tools.items():
        lines.append(f"  AI tool {ai_tool}: {str(entry['state']).replace('_', ' ')} ({entry['settings_file']})")
    if result == "needs_sign_in":
        lines.append(f"Sign in: `{_login_hint(args.profile, profile.workspace_id if profile is not None else None)}`.")
    if args.bundle:
        written = _write_bundle(Path(args.bundle).expanduser(), fields, secrets)
        if written is not None:
            return reply(
                CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
                f"{written} Nothing was saved.",
                state="failed",
                reason="bundle_not_written",
                message=written,
                profile=args.profile,
            )
        fields["bundle"] = str(Path(args.bundle).expanduser())
        lines.append(f"Saved the results to {fields['bundle']}. It holds no sign-in or AI tool settings.")
    return reply(code, "\n".join(lines), **fields)


def _write_bundle(
    path: Path,
    fields: dict[str, object],
    secrets: CloudActionsSecrets | None,
) -> str | None:
    """Write the doctor results to a new private file; return a reason when it was not written."""

    text = json.dumps({"schema": CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA, **fields}, indent=2, sort_keys=True) + "\n"
    forbidden = [value for value in (secrets.access_token, secrets.refresh_token) if value] if secrets else []
    if any(value in text for value in forbidden):
        return "The results held part of the saved sign-in, so they were not saved to a file."
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return f"{path} already exists; choose a new file name."
    except OSError as error:
        return f"{path} could not be created ({error.strerror or 'error'})."
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    return None


__all__ = ["CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA", "doctor", "status"]
