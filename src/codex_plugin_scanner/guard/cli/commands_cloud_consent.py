"""Explicit local command capability and per-job consent actions."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..runtime.command_capability import (
    READ_ONLY_COMMAND_OPERATIONS,
    CommandCapabilityError,
    approve_pending_command,
    issue_command_capability,
    revoke_command_capability,
)
from ..runtime.command_executors import SUPPORTED_COMMAND_OPERATIONS
from ..runtime.command_queue import command_queue_status
from ..store import GuardStore
from ._commands_shared import _require_guard_store
from .commands_support_interaction import _emit


def _run_guard_commands_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    store = _require_guard_store(store)
    commands_command = getattr(args, "commands_command", None)
    if commands_command == "status":
        _emit("commands", command_queue_status(store), getattr(args, "json", False))
        return 0
    if commands_command == "enable":
        operations: list[str] = []
        for value in getattr(args, "operations", []):
            for operation in str(value).split(","):
                normalized = operation.strip()
                if normalized == "read-only":
                    operations.extend(READ_ONLY_COMMAND_OPERATIONS)
                elif normalized:
                    operations.append(normalized)
        try:
            capability = issue_command_capability(
                store,
                operations=tuple(operations),
                supported_operations=SUPPORTED_COMMAND_OPERATIONS,
                share_policy_source=bool(getattr(args, "share_policy_source", False)),
                ttl_seconds=int(getattr(args, "expires_in_days", 30)) * 24 * 60 * 60,
            )
        except CommandCapabilityError as error:
            _emit(
                "commands",
                {"status": "error", "error": error.code},
                getattr(args, "json", False),
            )
            return 2
        _emit(
            "commands",
            {
                "status": "enabled" if capability.get("enabled") is True else "issued_disabled",
                "capability": capability,
                "daemon_restart_required": True,
                "restart_command": "hol-guard daemon repair",
            },
            getattr(args, "json", False),
        )
        return 0
    if commands_command == "approve":
        job_id = str(getattr(args, "job_id", ""))
        if getattr(args, "confirm", None) != job_id:
            _emit(
                "commands",
                {"status": "error", "error": "confirmation_mismatch", "job_id": job_id},
                getattr(args, "json", False),
            )
            return 2
        try:
            result = approve_pending_command(store, job_id)
        except CommandCapabilityError as error:
            _emit(
                "commands",
                {"status": "error", "error": error.code, "job_id": job_id},
                getattr(args, "json", False),
            )
            return 2
        _emit("commands", {"status": "approved", **result}, getattr(args, "json", False))
        return 0
    if commands_command == "revoke":
        capability = revoke_command_capability(store)
        _emit(
            "commands",
            {"status": "revoked", "capability": capability},
            getattr(args, "json", False),
        )
        return 0
    print("commands subcommand is required", file=sys.stderr)
    return 2
