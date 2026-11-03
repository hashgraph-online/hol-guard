"""`cloud-actions ai-tools configure` and `ai-tools restore`.

Both work from this computer's `hol-guard connect` pairing; there is no other
Cloud actions sign-in. `configure --dry-run` previews the one settings entry
that adds Cloud actions to an AI tool. `--apply` first obtains that AI tool's
Cloud actions access from the pairing, so a pairing without Cloud actions
changes nothing, then writes the entry and keeps a copy of the previous file.
`restore` undoes that change and ends the AI tool's access in Guard Cloud. The
settings modules are imported only when one of these commands runs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import resolve_guard_home, resolve_guard_home_for_user_home
from .commands_dispatch_cloud_actions import (
    CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
    CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
    CLOUD_ACTIONS_UNAVAILABLE_EXIT,
)

if TYPE_CHECKING:
    from ..store import GuardStore
    from .cloud_actions_access import CloudActionsAccessError, CloudActionsPairing
    from .cloud_actions_host_config import HostConfigPlan
    from .commands_dispatch_cloud_actions import _Reply  # pyright: ignore[reportPrivateUsage]


def _ai_tool_settings_path(args: argparse.Namespace) -> Path | None:
    from .cloud_actions_host_config import AiToolNotSupportedError, settings_path

    explicit_home = getattr(args, "home", None)
    home = Path(explicit_home).expanduser() if explicit_home else Path.home()
    try:
        return settings_path(args.ai_tool, home=home, environ=None if explicit_home else os.environ)
    except AiToolNotSupportedError:
        return None


def settings_guard_home(args: argparse.Namespace) -> Path:
    """The Guard home the AI tool's entry names; under `--home` when it is given.

    Absolute, because the AI tool starts the bridge from its own working folder.
    """

    override = getattr(args, "guard_home", None)
    explicit_home = getattr(args, "home", None)
    if override or not explicit_home:
        return Path(os.path.abspath(resolve_guard_home(override)))
    return Path(os.path.abspath(resolve_guard_home_for_user_home(Path(explicit_home).expanduser())))


def _ai_tool_not_supported(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_host_config import SUPPORTED_AI_TOOLS

    supported = ", ".join(SUPPORTED_AI_TOOLS)
    return reply(
        CLOUD_ACTIONS_UNAVAILABLE_EXIT,
        f"Cloud actions setup is not available for {args.ai_tool}. Supported AI tools: {supported}.",
        state="unavailable",
        reason="ai_tool_not_supported",
        ai_tool=args.ai_tool,
        supported_ai_tools=list(SUPPORTED_AI_TOOLS),
    )


def _access_refused(error: CloudActionsAccessError, reply: _Reply, **fields: object) -> int:
    if error.reason in {"not_paired", "pairing_expired", "cloud_actions_off", "cloud_actions_not_allowed"}:
        code = CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT
    elif error.reason in {"not_available", "cloud_unreachable", "rate_limited"}:
        code = CLOUD_ACTIONS_UNAVAILABLE_EXIT
    else:
        code = CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT
    return reply(
        code, f"{error} Nothing was changed.", state="failed", reason=error.reason, message=str(error), **fields
    )


def _apply_ai_tool(plan: HostConfigPlan, store: GuardStore, reply: _Reply) -> int:
    from . import cloud_actions_access
    from .cloud_actions_host_apply import HostConfigWriteError, apply_host_config

    fields: dict[str, object] = {
        "mode": "apply",
        "ai_tool": plan.ai_tool,
        "settings_file": str(plan.path),
        "action": plan.action,
        "server_name": plan.server_name,
        "url": plan.url,
    }
    refused = plan.action in {"conflict", "unreadable"}
    if refused:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            _preview_text(plan).replace("Nothing was written.", "Nothing was changed."),
            state="refused",
            configured_as=list(plan.configured_as),
            problem=plan.problem,
            written=False,
            **fields,
        )
    try:
        # Guard Cloud decides here, before anything is written; the access is
        # not kept: the bridge obtains its own each time the AI tool starts it.
        access = cloud_actions_access.exchange_cloud_actions_access(store, ai_tool=plan.ai_tool)
    except cloud_actions_access.CloudActionsAccessError as error:
        return _access_refused(error, reply, written=False, **fields)
    fields["cloud_workspace"] = access.workspace_id
    if not plan.changes:
        return reply(
            0,
            _preview_text(plan).replace("Nothing was written.", "Nothing was changed."),
            state="unchanged",
            configured_as=list(plan.configured_as),
            problem=plan.problem,
            written=False,
            **fields,
        )
    try:
        _ = apply_host_config(plan, guard_home=store.guard_home)
    except HostConfigWriteError as error:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            str(error) if error.reason != "write_not_verified" else f"{error} The previous file was put back.",
            state="failed",
            reason=error.reason,
            message=str(error),
            written=False,
            **fields,
        )
    if plan.action == "create_file":
        done = f"Created {plan.path} with only the {plan.server_name} entry."
    else:
        verb = "Changed" if plan.action == "update" else "Added"
        done = f"{verb} the {plan.server_name} entry in {plan.path}. Everything else in the file stays as it is."
    lines = [
        f"Set up {plan.display_name} for Cloud actions in workspace {access.workspace_id}.",
        done,
        f"{plan.display_name} uses this computer's Guard Cloud connection; it does not sign in separately.",
        plan.reload_hint,
        f"To undo, run `hol-guard cloud-actions ai-tools restore {plan.ai_tool}`.",
    ]
    return reply(0, "\n".join(lines), state="applied", previous_url=plan.previous_url, written=True, **fields)


def restore_ai_tool(args: argparse.Namespace, reply: _Reply) -> int:
    from . import cloud_actions_access
    from .cloud_actions_host_apply import HostConfigWriteError, restore_host_config

    path = _ai_tool_settings_path(args)
    if path is None:
        return _ai_tool_not_supported(args, reply)
    guard_home = settings_guard_home(args)
    fields: dict[str, object] = {"ai_tool": args.ai_tool, "settings_file": str(path)}
    # End the access before touching the file. Restoring consumes a saved copy,
    # so a retry after a failed end must not put back an older one. Without a
    # pairing, or with an expired one, this computer cannot use the access, so
    # the file is put back without asking Guard Cloud.
    ended: list[str] | None
    unpaired_reason: str | None = None
    try:
        store = cloud_actions_access.open_paired_store(guard_home)
        ended = cloud_actions_access.revoke_cloud_actions_access(store, ai_tool=args.ai_tool)
    except cloud_actions_access.CloudActionsAccessError as error:
        if error.reason not in {"not_paired", "pairing_expired"}:
            return reply(
                CLOUD_ACTIONS_UNAVAILABLE_EXIT,
                f"Guard Cloud did not confirm that Cloud actions access for this AI tool ended: {error} "
                "Nothing was changed. Run this command again once Guard Cloud can be reached.",
                state="access_not_ended",
                reason=error.reason,
                message=str(error),
                restored=False,
                access_ended=False,
                **fields,
            )
        ended = None
        unpaired_reason = error.reason
    try:
        restored = restore_host_config(args.ai_tool, path=path, guard_home=guard_home)
    except HostConfigWriteError as error:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            str(error),
            state="failed",
            reason=error.reason,
            message=str(error),
            restored=False,
            access_ended=ended is not None and args.ai_tool in ended,
            **fields,
        )
    if restored is None:
        text = f"Guard has no earlier copy of {path} to put back, so the file was not changed."
    elif restored.removed_file:
        text = f"Removed {path}, which Guard had created."
    elif restored.scope == "file":
        text = f"Put back {path} as it was before Guard changed it."
    else:
        change = "Removed the" if restored.entry_removed else "Put back the earlier"
        text = (
            f"{change} hol-guard-cloud entry in {path}. The file changed after Guard wrote it, "
            "so everything else in it stays as it is now."
        )
    restore_fields: dict[str, object] = {"restored": False}
    if restored is not None:
        restore_fields = {
            "restored": True,
            "scope": restored.scope,
            "removed_file": restored.removed_file,
            "entry_removed": restored.entry_removed,
        }
    # Report only what Guard Cloud confirmed it ended.
    if unpaired_reason == "pairing_expired":
        note = (
            "This computer's Guard Cloud connection has expired, so it can no longer use Cloud actions. "
            "Run `hol-guard connect` to pair again."
        )
    elif ended is None:
        note = "This computer is not paired with Guard Cloud, so there was no Cloud actions access to end."
    elif args.ai_tool in ended:
        note = "Guard Cloud ended Cloud actions access for this AI tool."
    else:
        note = "Guard Cloud had no Cloud actions access for this AI tool to end."
    return reply(
        0,
        f"{text}\n{note}",
        state="restored" if restored is not None else "nothing_to_restore",
        access_ended=ended is not None and args.ai_tool in ended,
        pairing="expired" if unpaired_reason == "pairing_expired" else ("none" if ended is None else "paired"),
        **restore_fields,
        **fields,
    )


def _configure_pairing(
    args: argparse.Namespace, guard_home: Path, reply: _Reply
) -> tuple[GuardStore, CloudActionsPairing] | int:
    """This computer's pairing, or the exit code after explaining why there is none to use."""

    from . import cloud_actions_access

    try:
        store = cloud_actions_access.open_paired_store(guard_home)
        pairing = cloud_actions_access.read_cloud_actions_pairing(store)
    except cloud_actions_access.CloudActionsAccessError as error:
        return _access_refused(error, reply)
    wanted = getattr(args, "cloud_workspace", None)
    if wanted and pairing.workspace_id is not None and wanted.lower() != pairing.workspace_id:
        return reply(
            CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
            f"This computer is paired with workspace {pairing.workspace_id}, not {wanted}. "
            f"Run `hol-guard connect --cloud-workspace {wanted}` to pair it with that workspace. Nothing was changed.",
            state="failed",
            reason="workspace_mismatch",
            cloud_workspace=wanted,
            paired_workspace=pairing.workspace_id,
        )
    return store, pairing


def configure_ai_tool(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_host_config import bridge_entry, plan_host_config

    path = _ai_tool_settings_path(args)
    if path is None:
        return _ai_tool_not_supported(args, reply)
    guard_home = settings_guard_home(args)
    paired = _configure_pairing(args, guard_home, reply)
    if isinstance(paired, int):
        return paired
    store, pairing = paired
    entry = bridge_entry(args.ai_tool, guard_home=guard_home)
    plan = plan_host_config(args.ai_tool, path=path, entry=entry, url=pairing.gateway_url)
    if args.apply:
        return _apply_ai_tool(plan, store, reply)
    return reply(
        CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT if plan.action in {"conflict", "unreadable"} else 0,
        _preview_text(plan),
        state="preview",
        mode="dry-run",
        ai_tool=plan.ai_tool,
        cloud_workspace=pairing.workspace_id,
        settings_file=str(plan.path),
        action=plan.action,
        server_name=plan.server_name,
        url=plan.url,
        previous_url=plan.previous_url,
        configured_as=list(plan.configured_as),
        other_entries=plan.other_entries,
        problem=plan.problem,
        written=False,
    )


def _preview_text(plan: HostConfigPlan) -> str:
    lines = [f"Preview for {plan.display_name}: {plan.path}"]
    others = f"{plan.other_entries} other MCP server{'s' if plan.other_entries != 1 else ''}"
    if plan.action == "unreadable":
        lines.append(f"Guard cannot change this file: {plan.problem}")
    elif plan.action == "conflict":
        lines.append(f"{plan.problem} Guard will not replace it; rename or remove that entry first.")
    elif plan.action == "already_configured":
        lines.append(f"Already set up as {', '.join(plan.configured_as)}. Nothing would change.")
    elif plan.action == "unchanged":
        lines.append(f"Already set up as {plan.server_name}. Nothing would change.")
    else:
        if plan.action == "create_file":
            lines.append("The file does not exist yet; it would be created with only this entry:")
        elif plan.action == "update":
            previous = f" from {plan.previous_url}" if plan.previous_url else ""
            lines.append(f"Would change {plan.server_name}{previous} to:")
        else:
            lines.append("Would add this entry:")
        lines.extend(f"+ {line}" for line in plan.entry_lines)
        if plan.action != "create_file":
            lines.append(f"Everything else in the file stays as it is, including {others}.")
        lines.append(
            f"{plan.display_name} would use this computer's Guard Cloud connection; it does not sign in separately."
        )
    lines.append("Nothing was written.")
    return "\n".join(lines)


__all__ = ["configure_ai_tool", "restore_ai_tool"]
