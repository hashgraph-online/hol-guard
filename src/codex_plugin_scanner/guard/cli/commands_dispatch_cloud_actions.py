"""Early dispatch for `cloud-actions`.

`login`, `logout`, `status` and `workspace select` act on a saved sign-in
(profile). `ai-tools configure --dry-run` previews an AI tool's settings change
without writing it. The other commands still report, without touching this device or
the network, that they cannot act yet, and echo the contexts they parsed so
scripts and tests can see which one each value landed in.

The commands_support facade imports this module on every hook, so the sign-in
modules are imported only when a sign-in command runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..browser_opener import open_browser_url
from ..config import resolve_guard_home

if TYPE_CHECKING:
    from .cloud_actions_host_config import HostConfigPlan
    from .cloud_actions_session import CloudActionsProfile, CloudActionsSessionStore

CLOUD_ACTIONS_SCHEMA = "guard.cloud-actions.v1"
CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT = 1
# Distinct from argparse's usage error (2): the command was understood.
CLOUD_ACTIONS_UNAVAILABLE_EXIT = 3
CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT = 4
CLOUD_ACTIONS_CANCELLED_EXIT = 130


def _command_path(args: argparse.Namespace) -> str:
    parts = [str(args.cloud_actions_command)]
    for attribute in (
        "cloud_actions_workspace_command",
        "cloud_actions_accounts_command",
        "cloud_actions_ai_tools_command",
    ):
        value = getattr(args, attribute, None)
        if value is not None:
            parts.append(str(value))
    return " ".join(parts)


def _context(args: argparse.Namespace) -> dict[str, object]:
    context: dict[str, object] = {
        "cloud_workspace": getattr(args, "cloud_workspace", None),
        "provider": getattr(args, "provider", None),
        "connected_account": getattr(args, "connected_account", None),
        "ai_tool": getattr(args, "ai_tool", None),
    }
    if getattr(args, "dry_run", False):
        context["mode"] = "dry-run"
    elif getattr(args, "apply", False):
        context["mode"] = "apply"
    return context


class _Reply:
    def __init__(self, args: argparse.Namespace, stream: TextIO) -> None:
        self._json = bool(getattr(args, "json", False))
        self._command = _command_path(args)
        self._stream = stream

    def __call__(self, code: int, text: str, **fields: object) -> int:
        if self._json:
            payload = {"schema": CLOUD_ACTIONS_SCHEMA, "command": self._command, **fields}
            print(json.dumps(payload, sort_keys=True), file=self._stream)
        else:
            print(text, file=self._stream)
        return code


def _profile_fields(profile: CloudActionsProfile) -> dict[str, object]:
    return {
        "profile": profile.name,
        "cloud_url": profile.issuer,
        "cloud_workspace": profile.workspace_id,
        "scopes": list(profile.scopes),
        "expires_at": profile.expires_at,
    }


def _login_hint(profile: str, workspace: str | None) -> str:
    command = "hol-guard cloud-actions login"
    if workspace is not None:
        command += f" --cloud-workspace {workspace}"
    if profile != "default":
        command += f" --profile {profile}"
    return command


def _login(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply, notice: TextIO) -> int:
    from .cloud_actions_login import sign_in
    from .cloud_actions_oauth import CloudActionsSignInError

    opener: Callable[[str], bool] | None = None if args.no_browser else open_browser_url
    try:
        profile = sign_in(
            store=store,
            profile_name=args.profile,
            cloud_url=args.cloud_url,
            workspace_id=args.cloud_workspace,
            timeout_seconds=args.timeout,
            open_browser=opener,
            notice=notice,
        )
    except CloudActionsSignInError as error:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            f"Sign-in did not finish: {error} Nothing was saved.",
            state="failed",
            reason=error.reason,
            message=str(error),
            profile=args.profile,
        )
    return reply(
        0,
        f"Signed in to Cloud actions for workspace {profile.workspace_id} (profile {profile.name}).",
        state="signed_in",
        **_profile_fields(profile),
    )


def _logout(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply) -> int:
    from .cloud_actions_login import sign_out
    from .cloud_actions_oauth import CloudActionsSignInError

    try:
        was_signed_in, revoked = sign_out(store=store, profile_name=args.profile)
    except CloudActionsSignInError as error:
        return reply(
            CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT,
            f"Sign-out did not finish: {error} Nothing was removed.",
            state="failed",
            reason=error.reason,
            message=str(error),
            profile=args.profile,
        )
    if not was_signed_in:
        text = f"Profile {args.profile} was not signed in. Nothing to remove."
    elif revoked:
        text = f"Signed out of Cloud actions (profile {args.profile}). Guard Cloud ended the sign-in."
    else:
        text = (
            f"Removed the saved sign-in (profile {args.profile}). Guard Cloud did not confirm that it ended "
            "the sign-in; it stops working when it expires, or you can end it from Guard Cloud."
        )
    return reply(0, text, state="signed_out", profile=args.profile, was_signed_in=was_signed_in, revoked=revoked)


def _status(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply) -> int:
    profile = store.load(args.profile)
    requested = args.cloud_workspace
    if profile is None or store.load_secrets(args.profile) is None:
        return reply(
            0,
            f"Not signed in (profile {args.profile}). Run `{_login_hint(args.profile, requested)}`.",
            state="signed_out",
            profile=args.profile,
            accounts="not_available_yet",
        )
    state = "expired" if profile.is_expired() else "signed_in"
    fields = {"state": state, **_profile_fields(profile), "accounts": "not_available_yet"}
    lines = [
        f"Profile {profile.name}: {'sign-in expired' if state == 'expired' else 'signed in'}",
        f"Guard Cloud: {profile.issuer}",
        f"Workspace: {profile.workspace_id}",
        "Connected accounts: not available yet",
    ]
    if requested is not None:
        fields["workspace_matches"] = requested == profile.workspace_id
        if requested != profile.workspace_id:
            lines.append(f"Workspace {requested} needs its own sign-in: `{_login_hint(args.profile, requested)}`.")
    if state == "expired":
        lines.append(f"Sign in again: `{_login_hint(profile.name, profile.workspace_id)}`.")
    return reply(0, "\n".join(lines), **fields)


def _workspace_select(args: argparse.Namespace, store: CloudActionsSessionStore, reply: _Reply) -> int:
    requested = args.cloud_workspace
    profile = store.load(args.profile)
    hint = _login_hint(args.profile, requested)
    if profile is None or store.load_secrets(args.profile) is None:
        return reply(
            CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
            f"Not signed in (profile {args.profile}). Run `{hint}`.",
            state="signed_out",
            reason="not_signed_in",
            profile=args.profile,
            cloud_workspace=requested,
        )
    if profile.workspace_id != requested:
        return reply(
            CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
            f"Profile {profile.name} is signed in to workspace {profile.workspace_id}. "
            f"A sign-in covers one workspace; run `{hint}`, or use another --profile.",
            state="signed_in",
            reason="workspace_needs_sign_in",
            profile=profile.name,
            cloud_workspace=requested,
            signed_in_workspace=profile.workspace_id,
        )
    return reply(
        0,
        f"Profile {profile.name} uses workspace {profile.workspace_id}.",
        state="selected",
        **_profile_fields(profile),
    )


def _configure_ai_tool(args: argparse.Namespace, reply: _Reply) -> int:
    from .cloud_actions_host_config import (
        SUPPORTED_AI_TOOLS,
        AiToolNotSupportedError,
        gateway_url,
        plan_host_config,
        settings_path,
    )
    from .cloud_actions_oauth import CloudActionsSignInError, resolve_cloud_origin

    if args.apply:
        return reply(
            CLOUD_ACTIONS_UNAVAILABLE_EXIT,
            "Applying AI tool settings is not available yet. Nothing was changed. Use --dry-run to preview.",
            state="unavailable",
            reason="not_available_yet",
            context=_context(args),
        )
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
    explicit_home = getattr(args, "home", None)
    home = Path(explicit_home).expanduser() if explicit_home else Path.home()
    try:
        path = settings_path(args.ai_tool, home=home, environ=None if explicit_home else os.environ)
    except AiToolNotSupportedError:
        supported = ", ".join(SUPPORTED_AI_TOOLS)
        return reply(
            CLOUD_ACTIONS_UNAVAILABLE_EXIT,
            f"Cloud actions setup is not available for {args.ai_tool}. Supported AI tools: {supported}.",
            state="unavailable",
            reason="ai_tool_not_supported",
            ai_tool=args.ai_tool,
            supported_ai_tools=list(SUPPORTED_AI_TOOLS),
        )
    plan = plan_host_config(args.ai_tool, path=path, url=url)
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
            lines.append(f"Would change {plan.server_name} from {plan.previous_url} to:")
        else:
            lines.append("Would add this entry:")
        lines.extend(f"+ {line}" for line in plan.entry_lines)
        if plan.action != "create_file":
            lines.append(f"Everything else in the file stays as it is, including {others}.")
    if plan.action not in {"unreadable", "conflict"}:
        lines.append(
            f"The AI tool signs in to Guard Cloud itself; choose workspace {workspace} when it asks. "
            f"{plan.sign_in_hint}"
        )
    lines.append("Nothing was written.")
    return "\n".join(lines)


def _run_guard_cloud_actions_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    notice_stream: TextIO | None = None,
) -> int:
    del input_text
    stream = output_stream if output_stream is not None else sys.stdout
    reply = _Reply(args, stream)
    command = args.cloud_actions_command
    workspace_command = getattr(args, "cloud_actions_workspace_command", None)
    if command in {"login", "logout", "status"} or workspace_command == "select":
        from .cloud_actions_session import CloudActionsSessionStore

        store = CloudActionsSessionStore(resolve_guard_home(getattr(args, "guard_home", None)))
        if command == "login":
            notice = notice_stream if notice_stream is not None else sys.stderr
            try:
                return _login(args, store, reply, notice)
            except KeyboardInterrupt:
                return reply(
                    CLOUD_ACTIONS_CANCELLED_EXIT,
                    "Sign-in cancelled. Nothing was saved.",
                    state="cancelled",
                    profile=args.profile,
                )
        if command == "logout":
            return _logout(args, store, reply)
        if command == "status":
            return _status(args, store, reply)
        return _workspace_select(args, store, reply)
    if getattr(args, "cloud_actions_ai_tools_command", None) == "configure":
        return _configure_ai_tool(args, reply)
    return reply(
        CLOUD_ACTIONS_UNAVAILABLE_EXIT,
        f"`hol-guard cloud-actions {_command_path(args)}` is not available yet. Nothing was changed.",
        state="unavailable",
        reason="not_available_yet",
        context=_context(args),
    )


__all__ = [
    "CLOUD_ACTIONS_CANCELLED_EXIT",
    "CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT",
    "CLOUD_ACTIONS_SCHEMA",
    "CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT",
    "CLOUD_ACTIONS_UNAVAILABLE_EXIT",
    "_run_guard_cloud_actions_command",
]
