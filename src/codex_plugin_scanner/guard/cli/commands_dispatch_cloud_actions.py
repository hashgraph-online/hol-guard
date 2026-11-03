"""Early dispatch for `cloud-actions`.

Only the grammar exists so far. Every command reports, without touching this
device or the network, that it cannot act yet, and echoes the contexts it
parsed so scripts and tests can see which one each value landed in.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

CLOUD_ACTIONS_SCHEMA = "guard.cloud-actions.v1"
# Distinct from argparse's usage error (2): the command was understood.
CLOUD_ACTIONS_UNAVAILABLE_EXIT = 3


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


def _run_guard_cloud_actions_command(
    args: argparse.Namespace, *, input_text: str | None = None, output_stream: TextIO | None = None
) -> int:
    del input_text
    stream = output_stream if output_stream is not None else sys.stdout
    command = _command_path(args)
    if getattr(args, "json", False):
        payload = {
            "schema": CLOUD_ACTIONS_SCHEMA,
            "command": command,
            "state": "unavailable",
            "reason": "not_available_yet",
            "context": _context(args),
        }
        print(json.dumps(payload, sort_keys=True), file=stream)
    else:
        print(f"`hol-guard cloud-actions {command}` is not available yet. Nothing was changed.", file=stream)
    return CLOUD_ACTIONS_UNAVAILABLE_EXIT


__all__ = ["CLOUD_ACTIONS_SCHEMA", "CLOUD_ACTIONS_UNAVAILABLE_EXIT", "_run_guard_cloud_actions_command"]
