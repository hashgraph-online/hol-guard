"""`cloud-actions status` and `cloud-actions doctor`.

Both read this computer's `hol-guard connect` pairing and what the last
connect said about Cloud actions. `status` also asks Guard Cloud whether it
offers Cloud actions (`cloud_actions_health`); `status --offline` does not ask.
`doctor` checks which AI tools are set up and, for the first one that is,
exchanges the pairing for that AI tool's access and asks Guard Cloud whether it
accepts it, exactly as the AI tool would. It can save its results, without any
access, to a new private file. The health modules are imported only when one
of these commands runs.
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
)
from .connect_cloud_actions import CLOUD_ACTIONS_RECONNECT_COMMAND

if TYPE_CHECKING:
    from ..store import GuardStore
    from .cloud_actions_access import CloudActionsPairing
    from .cloud_actions_health import HealthCheck
    from .commands_dispatch_cloud_actions import _Reply  # pyright: ignore[reportPrivateUsage]
    from .connect_cloud_actions import CloudActionsConnectSummary

CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA = "guard.cloud-actions.diagnostics.v2"
_NOT_PAIRED = f"This computer is not connected to Guard Cloud. Run `{CLOUD_ACTIONS_RECONNECT_COMMAND}`."
# Access refusals that only connecting again (or a workspace admin) can fix.
_RECONNECT_STATES = frozenset(
    {"reconnect", "not_paired", "pairing_expired", "cloud_actions_off", "cloud_actions_not_allowed"}
)


def _paired(args: argparse.Namespace) -> tuple[GuardStore, CloudActionsPairing, CloudActionsConnectSummary] | None:
    from . import cloud_actions_access
    from .commands_dispatch_cloud_actions_ai_tools import settings_guard_home
    from .connect_cloud_actions import cloud_actions_connect_summary, read_cloud_actions_connect_report

    try:
        store = cloud_actions_access.open_paired_store(settings_guard_home(args))
        pairing = cloud_actions_access.read_cloud_actions_pairing(store)
    except cloud_actions_access.CloudActionsAccessError:
        return None
    grant_id = store.get_oauth_local_credential_health().get("grant_id")
    report = read_cloud_actions_connect_report(store, grant_id=grant_id if isinstance(grant_id, str) else None)
    return store, pairing, cloud_actions_connect_summary(report, paired=True)


def _pairing_fields(pairing: CloudActionsPairing, summary: CloudActionsConnectSummary) -> dict[str, object]:
    return {
        "cloud_url": pairing.origin,
        "cloud_workspace": pairing.workspace_id or summary["workspace_id"],
        "cloud_actions": summary["status"],
    }


def _workspace_line(requested: str | None, workspace: object) -> str | None:
    if requested is None or workspace is None or requested == workspace:
        return None
    return (
        f"This computer is connected to workspace {workspace}. To use workspace {requested}, "
        f"run `{CLOUD_ACTIONS_RECONNECT_COMMAND} --cloud-workspace {requested}`."
    )


def status(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_health import HealthCheck, check_service, checked_at

    paired = _paired(args)
    if paired is None:
        return reply(
            0,
            _NOT_PAIRED,
            state="not_paired",
            accounts="not_available_yet",
            included_actions="not_available_yet",
        )
    _store, pairing, summary = paired
    service = HealthCheck("not_checked", "Not checked (--offline).") if args.offline else check_service(pairing)
    fields = _pairing_fields(pairing, summary)
    fields.update(
        {
            "state": "paired",
            "checked_at": checked_at(),
            "service": service.as_dict(),
            "included_actions": "not_available_yet",
            "accounts": "not_available_yet",
        }
    )
    lines = [
        f"Guard Cloud: {pairing.origin}",
        f"Workspace: {fields['cloud_workspace'] or 'not reported'}",
        f"Cloud actions on this computer: {summary['message']}",
        f"Guard Cloud service: {service.message}",
        "Included actions: not available yet",
        "Connected accounts: not available yet",
    ]
    requested = getattr(args, "cloud_workspace", None)
    if requested is not None:
        fields["workspace_matches"] = requested == fields["cloud_workspace"]
        mismatch = _workspace_line(requested, fields["cloud_workspace"])
        if mismatch is not None:
            lines.append(mismatch)
    if service.state == "changed":
        lines.append(f"Connect again: `{CLOUD_ACTIONS_RECONNECT_COMMAND}`.")
    return reply(0, "\n".join(lines), **fields)


_AI_TOOL_STATES = {
    "unchanged": "configured",
    "already_configured": "configured",
    "create_file": "not_configured",
    "add": "not_configured",
    "update": "points_elsewhere",
    "conflict": "conflict",
    "unreadable": "unreadable",
}


def _ai_tool_states(args: argparse.Namespace, url: str | None) -> dict[str, dict[str, object]]:
    from .cloud_actions_health import redact_home
    from .cloud_actions_host_config import SUPPORTED_AI_TOOLS, bridge_entry, plan_host_config, settings_path
    from .commands_dispatch_cloud_actions_ai_tools import settings_guard_home

    explicit_home = getattr(args, "home", None)
    home = Path(explicit_home).expanduser() if explicit_home else Path.home()
    guard_home = settings_guard_home(args)
    states: dict[str, dict[str, object]] = {}
    for ai_tool in SUPPORTED_AI_TOOLS:
        path = settings_path(ai_tool, home=home, environ=None if explicit_home else os.environ)
        entry: dict[str, object] = {"settings_file": redact_home(str(path), str(home))}
        if url is None:
            entry["state"] = "not_checked"
        else:
            plan = plan_host_config(ai_tool, path=path, entry=bridge_entry(ai_tool, guard_home=guard_home), url=url)
            entry["state"] = _AI_TOOL_STATES[plan.action]
            if plan.configured_as:
                entry["configured_as"] = list(plan.configured_as)
            if plan.action == "update" and plan.previous_url is not None:
                entry["points_to"] = plan.previous_url
        states[ai_tool] = entry
    return states


def _access_check(
    store: GuardStore, pairing: CloudActionsPairing, ai_tools: dict[str, dict[str, object]]
) -> tuple[HealthCheck, str | None]:
    """Exchange the pairing for the first set-up AI tool's access and ask Guard Cloud whether it accepts it."""

    from . import cloud_actions_access
    from .cloud_actions_health import HealthCheck, check_connection

    ai_tool = next((name for name, entry in ai_tools.items() if entry["state"] == "configured"), None)
    if ai_tool is None:
        return HealthCheck("not_checked", "Not checked: no AI tool is set up for Cloud actions yet."), None
    try:
        access = cloud_actions_access.exchange_cloud_actions_access(store, ai_tool=ai_tool)
    except cloud_actions_access.CloudActionsAccessError as error:
        return HealthCheck(error.reason, str(error), details=(("ai_tool", ai_tool),)), None
    check = check_connection(pairing, access.access_token, access.workspace_id)
    return HealthCheck(check.state, check.message, check.http_status, (*check.details, ("ai_tool", ai_tool))), (
        access.access_token
    )


def doctor(args: argparse.Namespace, reply: _Reply) -> int:
    import platform

    from ...version import __version__
    from .cloud_actions_health import HealthCheck, check_service, checked_at

    paired = _paired(args)
    fields: dict[str, object] = {}
    access_token: str | None = None
    if paired is None:
        skipped = HealthCheck("not_checked", "Not checked: this computer is not connected to Guard Cloud.")
        connection = HealthCheck("not_paired", _NOT_PAIRED)
        checks = {"connection": connection, "service": skipped, "access": skipped}
        ai_tools = _ai_tool_states(args, None)
    else:
        store, pairing, summary = paired
        fields.update(_pairing_fields(pairing, summary))
        if summary["status"] == "off":
            connection = HealthCheck("cloud_actions_off", summary["message"])
        else:
            connection = HealthCheck("paired", f"Connected to workspace {fields['cloud_workspace'] or 'unknown'}.")
        ai_tools = _ai_tool_states(args, pairing.gateway_url)
        service = check_service(pairing)
        if service.state in {"offline", "not_turned_on"}:
            access = HealthCheck("not_checked", f"Not checked: {service.message}")
        elif connection.state == "cloud_actions_off":
            access = HealthCheck("not_checked", "Not checked: Cloud actions are off for this computer.")
        else:
            access, access_token = _access_check(store, pairing, ai_tools)
        checks = {"connection": connection, "service": service, "access": access}

    if (
        checks["connection"].state != "paired"
        or checks["access"].state in _RECONNECT_STATES
        or (checks["service"].state == "changed")
    ):
        result, code = "needs_connect", CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT
    elif not checks["service"].ok or not (checks["access"].ok or checks["access"].state == "not_checked"):
        result, code = "problems_found", CLOUD_ACTIONS_UNAVAILABLE_EXIT
    else:
        result, code = "ok", 0
    fields.update(
        {
            "result": result,
            "checked_at": checked_at(),
            "hol_guard_version": __version__,
            "system": {"os": platform.system(), "release": platform.release(), "machine": platform.machine()},
            "checks": {name: check.as_dict() for name, check in checks.items()},
            "ai_tools": ai_tools,
            "included_actions": "not_available_yet",
            "accounts": "not_available_yet",
        }
    )
    lines = [f"Cloud actions doctor: {result.replace('_', ' ')}"]
    for name, title in (("connection", "This computer"), ("service", "Guard Cloud"), ("access", "AI tool access")):
        check = checks[name]
        mark = "ok " if check.ok or check.state in {"paired", "not_checked"} else "!! "
        lines.append(f"  {mark}{title}: {check.message}")
    for ai_tool, entry in ai_tools.items():
        lines.append(f"  AI tool {ai_tool}: {str(entry['state']).replace('_', ' ')} ({entry['settings_file']})")
    if result == "needs_connect":
        lines.append(f"Connect again: `{CLOUD_ACTIONS_RECONNECT_COMMAND}`.")
    if args.bundle:
        written = _write_bundle(Path(args.bundle).expanduser(), fields, access_token)
        if written is not None:
            return reply(
                CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
                f"{written} Nothing was saved.",
                state="failed",
                reason="bundle_not_written",
                message=written,
            )
        fields["bundle"] = str(Path(args.bundle).expanduser())
        lines.append(f"Saved the results to {fields['bundle']}. It holds no access or AI tool settings.")
    return reply(code, "\n".join(lines), **fields)


def _write_bundle(path: Path, fields: dict[str, object], access_token: str | None) -> str | None:
    """Write the doctor results to a new private file; return a reason when it was not written."""

    text = json.dumps({"schema": CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA, **fields}, indent=2, sort_keys=True) + "\n"
    if access_token and access_token in text:
        return "The results held part of the Cloud actions access, so they were not saved to a file."
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
