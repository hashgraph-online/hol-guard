"""``hol-guard repair``: top-level, idempotent repair of the local Guard install."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..repair_engine import run_repair
from .commands_parser_helpers import _add_guard_common_args

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..store import GuardStore


def configure_guard_repair_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    repair_parser = guard_subparsers.add_parser(
        "repair",
        help="Repair the daemon, hooks, and stale Guard state in one idempotent pass",
    )
    repair_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be repaired and change nothing",
    )
    _add_guard_common_args(repair_parser)
    repair_parser.add_argument("--json", action="store_true")


def _run_guard_repair_command(
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
    del workspace, config, input_text
    if guard_home is None or context is None or store is None:
        raise RuntimeError("Guard home, context, and store are required")
    report = run_repair(
        guard_home=guard_home,
        context=context,
        store=store,
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    stream = output_stream or sys.stdout
    if bool(getattr(args, "json", False)):
        print(json.dumps(report, sort_keys=True), file=stream)
    else:
        print(report["summary"], file=stream)
    return 1 if report["status"] == "partial" else 0


__all__ = ["_run_guard_repair_command", "configure_guard_repair_parser"]
