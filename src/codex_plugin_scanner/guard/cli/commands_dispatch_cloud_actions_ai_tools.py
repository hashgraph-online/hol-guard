"""`cloud-actions ai-tools configure` and `ai-tools restore`.

`configure --dry-run` previews the one settings entry that adds Cloud actions
to an AI tool, `--apply` writes it and keeps a copy of the previous file, and
`restore` undoes that change. The settings modules are imported only when one
of these commands runs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import resolve_guard_home, resolve_guard_home_for_user_home
from .commands_dispatch_cloud_actions import CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT, CLOUD_ACTIONS_UNAVAILABLE_EXIT

if TYPE_CHECKING:
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


def _settings_guard_home(args: argparse.Namespace) -> Path:
    """Where copies of changed settings are kept; under `--home` when it is given."""

    override = getattr(args, "guard_home", None)
    explicit_home = getattr(args, "home", None)
    if override or not explicit_home:
        return resolve_guard_home(override)
    return resolve_guard_home_for_user_home(Path(explicit_home).expanduser())


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


def _apply_ai_tool(args: argparse.Namespace, plan: HostConfigPlan, reply: _Reply) -> int:
    from .cloud_actions_host_apply import HostConfigWriteError, apply_host_config

    fields: dict[str, object] = {
        "mode": "apply",
        "ai_tool": plan.ai_tool,
        "cloud_workspace": args.cloud_workspace,
        "settings_file": str(plan.path),
        "action": plan.action,
        "server_name": plan.server_name,
        "url": plan.url,
    }
    if not plan.changes:
        refused = plan.action in {"conflict", "unreadable"}
        text = _preview_text(plan, args.cloud_workspace).replace("Nothing was written.", "Nothing was changed.")
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT if refused else 0,
            text,
            state="refused" if refused else "unchanged",
            configured_as=list(plan.configured_as),
            problem=plan.problem,
            written=False,
            **fields,
        )
    guard_home = _settings_guard_home(args)
    try:
        _ = apply_host_config(plan, guard_home=guard_home)
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
        done = f"{verb} the {plan.server_name} entry in {plan.path}. Everything else in the file stays as it was."
    lines = [
        f"Set up {plan.display_name} for Cloud actions.",
        done,
        f"To undo, run `hol-guard cloud-actions ai-tools restore {plan.ai_tool}`.",
        f"The AI tool signs in to Guard Cloud itself; choose workspace {args.cloud_workspace} when it asks. "
        f"{plan.sign_in_hint}",
    ]
    return reply(0, "\n".join(lines), state="applied", previous_url=plan.previous_url, written=True, **fields)


def restore_ai_tool(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_host_apply import HostConfigWriteError, restore_host_config

    path = _ai_tool_settings_path(args)
    if path is None:
        return _ai_tool_not_supported(args, reply)
    guard_home = _settings_guard_home(args)
    fields: dict[str, object] = {"ai_tool": args.ai_tool, "settings_file": str(path)}
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
            **fields,
        )
    if restored is None:
        return reply(
            0,
            f"Guard has no earlier copy of {path} to put back. Nothing was changed.",
            state="nothing_to_restore",
            restored=False,
            **fields,
        )
    if restored.removed_file:
        text = f"Removed {path}, which Guard had created."
    elif restored.scope == "file":
        text = f"Put back {path} as it was before Guard changed it."
    else:
        change = "Removed the" if restored.entry_removed else "Put back the earlier"
        text = (
            f"{change} hol-guard-cloud entry in {path}. The file changed after Guard wrote it, "
            "so everything else in it stays as it is now."
        )
    return reply(
        0,
        text,
        state="restored",
        scope=restored.scope,
        removed_file=restored.removed_file,
        entry_removed=restored.entry_removed,
        restored=True,
        **fields,
    )


def configure_ai_tool(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_host_config import gateway_url, plan_host_config
    from .cloud_actions_oauth import CloudActionsSignInError, resolve_cloud_origin

    try:
        url = gateway_url(resolve_cloud_origin(args.cloud_url))
    except CloudActionsSignInError as error:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            f"{error} Nothing was changed.",
            state="failed",
            reason=error.reason,
            message=str(error),
        )
    path = _ai_tool_settings_path(args)
    if path is None:
        return _ai_tool_not_supported(args, reply)
    plan = plan_host_config(args.ai_tool, path=path, url=url)
    if args.apply:
        return _apply_ai_tool(args, plan, reply)
    return reply(
        CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT if plan.action in {"conflict", "unreadable"} else 0,
        _preview_text(plan, args.cloud_workspace),
        state="preview",
        mode="dry-run",
        ai_tool=plan.ai_tool,
        cloud_workspace=args.cloud_workspace,
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


def _preview_text(plan: HostConfigPlan, workspace: str) -> str:
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
    # An existing entry under another name is already how the AI tool signs in.
    if plan.action not in {"unreadable", "conflict", "already_configured"}:
        lines.append(
            f"The AI tool signs in to Guard Cloud itself; choose workspace {workspace} when it asks. "
            f"{plan.sign_in_hint}"
        )
    lines.append("Nothing was written.")
    return "\n".join(lines)


__all__ = ["configure_ai_tool", "restore_ai_tool"]
