"""Early dispatch for `cloud-actions`.

Cloud actions have no sign-in of their own: every command uses this
computer's `hol-guard connect` pairing. `status` and `doctor` read it and ask
Guard Cloud whether it accepts it (`cloud_actions_health`); `status --offline`
does not ask. `ai-tools configure --dry-run` previews an AI tool's settings
change without writing it, `--apply` gets that AI tool's access from the
pairing and writes the change, keeping a copy of the previous file, and
`ai-tools restore` undoes the change and ends the access. `accounts connect`
opens the workspace's connected accounts in Guard Cloud, where the member
signs in with the provider in the browser; no provider password or key passes
through this command. `login`, `logout` and `workspace select` existed only in
alpha builds; they now say to use `hol-guard connect`. The other commands still
report, without touching this device or the network, that they cannot act
yet, and echo the contexts they parsed so scripts and tests can see which one
each value landed in.

The commands_support facade imports this module on every hook, so the Cloud
actions modules are imported only when a Cloud actions command runs.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from typing import TextIO

from ..browser_opener import open_browser_url
from ..config import resolve_guard_home

CLOUD_ACTIONS_SCHEMA = "guard.cloud-actions.v1"
CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT = 1
# Distinct from argparse's usage error (2): the command was understood.
CLOUD_ACTIONS_UNAVAILABLE_EXIT = 3
CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT = 4
_RECONNECT_COMMAND = "hol-guard connect"


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


def _removed(args: argparse.Namespace, reply: _Reply) -> int:
    """`login`, `logout` and `workspace select` from alpha builds point to `hol-guard connect`."""

    command = args.cloud_actions_command
    if command == "logout":
        text = (
            "Cloud actions no longer have a separate sign-in to sign out of. To stop an AI tool using Cloud actions, "
            "run `hol-guard cloud-actions ai-tools restore <ai-tool>`; to turn Cloud actions off for this computer, "
            f"run `{_RECONNECT_COMMAND}` and leave them off."
        )
    else:
        text = (
            "Cloud actions no longer have a separate sign-in. They use this computer's Guard Cloud connection: "
            f"run `{_RECONNECT_COMMAND}`, then `hol-guard cloud-actions ai-tools configure <ai-tool> --apply`."
        )
    return reply(
        CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
        f"`hol-guard cloud-actions {_command_path(args)}` was removed. {text}",
        state="removed",
        reason="use_hol_guard_connect",
        next_command=_RECONNECT_COMMAND,
    )


# Matches the provider names Guard Cloud shows, so the button named here is the one on the page.
_PROVIDER_NAMES = {
    "discord": "Discord",
    "github": "GitHub",
    "gitlab": "GitLab",
    "google": "Google",
    "hubspot": "HubSpot",
    "linear": "Linear",
    "notion": "Notion",
    "salesforce": "Salesforce",
    "slack": "Slack",
}


def provider_name(provider: str) -> str:
    known = _PROVIDER_NAMES.get(provider)
    if known is not None:
        return known
    words = provider.replace("_", " ").replace("-", " ").split()
    return " ".join(word[:1].upper() + word[1:] for word in words) or "Service"


def connected_accounts_url(origin: str, workspace: str) -> str:
    """The workspace's connected accounts in Guard Cloud settings."""

    from .oauth_client import guard_api_base_path

    query = urllib.parse.urlencode({"tab": "integrations", "workspaceId": workspace})
    return f"{origin}{guard_api_base_path(origin)}/guard/settings?{query}#connected-accounts"


def _connect_account(args: argparse.Namespace, reply: _Reply) -> int:
    from . import cloud_actions_access

    try:
        store = cloud_actions_access.open_paired_store(resolve_guard_home(getattr(args, "guard_home", None)))
        pairing = cloud_actions_access.read_cloud_actions_pairing(store)
    except cloud_actions_access.CloudActionsAccessError as error:
        return reply(
            CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
            f"{error} Nothing was changed.",
            state="failed",
            reason=error.reason,
            message=str(error),
        )
    workspace = args.cloud_workspace or pairing.workspace_id
    if workspace is None:
        return reply(
            CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT,
            "Guard Cloud did not say which workspace this computer is connected to. "
            "Name it with --cloud-workspace <id>. Nothing was changed.",
            state="failed",
            reason="workspace_unknown",
        )
    origin = pairing.origin
    url = connected_accounts_url(origin, workspace)
    # Provider sign-in happens in the browser, so nothing secret is typed here.
    opened = not args.no_browser and open_browser_url(url)
    name = provider_name(args.provider)
    step = (
        f"To connect a {name} account to workspace {workspace}, "
        f"choose Connect {name} under Connected accounts and sign in with {name} there."
    )
    lead = "Opened Guard Cloud in your browser." if opened else "Open this link in a browser where you use Guard Cloud:"
    return reply(
        0,
        f"{lead}\n{url}\n{step}",
        state="opened" if opened else "link",
        opened=opened,
        url=url,
        provider=args.provider,
        cloud_workspace=workspace,
    )


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
    if command == "bridge":
        from .cloud_actions_bridge import run_cloud_actions_bridge

        return run_cloud_actions_bridge(
            resolve_guard_home(getattr(args, "guard_home", None)),
            ai_tool=args.ai_tool,
            input_stream=sys.stdin,
            output_stream=stream,
        )
    from .cloud_actions_alpha_cleanup import ALPHA_SIGN_IN_REMOVED_NOTICE, remove_alpha_sign_ins
    from .commands_dispatch_cloud_actions_ai_tools import settings_guard_home

    # The two previews Guard admits as reads (`status --offline`, `ai-tools configure --dry-run`) change nothing.
    preview = (command == "status" and bool(getattr(args, "offline", False))) or bool(getattr(args, "dry_run", False))
    if not preview and remove_alpha_sign_ins(settings_guard_home(args)):
        print(ALPHA_SIGN_IN_REMOVED_NOTICE, file=notice_stream if notice_stream is not None else sys.stderr)
    if command in {"login", "logout", "workspace"}:
        return _removed(args, reply)
    if command in {"status", "doctor"}:
        from .commands_dispatch_cloud_actions_status import doctor, status

        return (status if command == "status" else doctor)(args, reply)
    ai_tools_command = getattr(args, "cloud_actions_ai_tools_command", None)
    if ai_tools_command in {"configure", "restore"}:
        from .commands_dispatch_cloud_actions_ai_tools import configure_ai_tool, restore_ai_tool

        return (configure_ai_tool if ai_tools_command == "configure" else restore_ai_tool)(args, reply)
    if getattr(args, "cloud_actions_accounts_command", None) == "connect":
        return _connect_account(args, reply)
    return reply(
        CLOUD_ACTIONS_UNAVAILABLE_EXIT,
        f"`hol-guard cloud-actions {_command_path(args)}` is not available yet. Nothing was changed.",
        state="unavailable",
        reason="not_available_yet",
        context=_context(args),
    )


__all__ = [
    "CLOUD_ACTIONS_NEEDS_SIGN_IN_EXIT",
    "CLOUD_ACTIONS_SCHEMA",
    "CLOUD_ACTIONS_SIGN_IN_FAILED_EXIT",
    "CLOUD_ACTIONS_UNAVAILABLE_EXIT",
    "_run_guard_cloud_actions_command",
]
