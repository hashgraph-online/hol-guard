"""`hol-guard context usage`: model usage per tool, from each tool's own records.

Guard's background service counts the records and writes the text; this
command passes the folders it was run with and prints the answer.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, TextIO

SCHEMA = "guard-context-usage-meter.v1"
# The first count of a long history runs in the background; ask again until it ends.
POLL_SECONDS = 0.5
WAIT_SECONDS = 600.0


def configure(actions: argparse._SubParsersAction[Any]) -> None:
    usage = actions.add_parser(
        "usage",
        help="Show model usage per AI tool, read from each tool's own records on this computer",
        description=(
            "Adds up the usage Codex and Claude Code record for every model request in their session files. "
            "Usage is counted, not estimated; tools whose records it does not read are named, not counted. "
            "The tokens CIGAR saved are an estimate, shown apart and labeled as one."
        ),
    )
    usage.set_defaults(context_kind="usage")
    usage.add_argument("--guard-home", default=argparse.SUPPRESS)
    usage.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


def folder_setting(name: str) -> str | None:
    """A folder environment setting as the tools read it from this working folder.

    The runtime runs elsewhere, so a relative folder is made absolute here. A
    `~` folder is left for the runtime to expand against the home folder.
    """

    raw = os.environ.get(name)
    if not raw or not raw.strip():
        return None
    if raw.strip().startswith("~"):
        return raw
    return os.path.abspath(raw.strip())


def _read(guard_home: Path, *, text: bool) -> dict[str, Any] | None:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    args = {
        "op": "read",
        "home_dir": str(Path.home()),
        "codex_home": folder_setting("CODEX_HOME"),
        "claude_config_dir": folder_setting("CLAUDE_CONFIG_DIR"),
        "text": text,
    }
    deadline = time.monotonic() + WAIT_SECONDS
    told = False
    while True:
        try:
            answer = native_runner_authority("context_usage", args, guard_home)
        except (NativeRunnerAuthorityError, OSError):
            return None
        state = answer.get("usage") if isinstance(answer, dict) else None
        if not isinstance(state, dict):
            return None
        if state.get("state") != "counting" or time.monotonic() >= deadline:
            return answer
        if text and not told:
            print("Counting. The first count of a long history can take a minute.", file=sys.stderr)
            told = True
        time.sleep(POLL_SECONDS)


def run(args: argparse.Namespace, output: TextIO) -> int:
    from ..config import resolve_guard_home

    try:
        guard_home = resolve_guard_home(args.guard_home)
    except (OSError, RuntimeError, ValueError):
        answer = None
    else:
        answer = _read(guard_home, text=not args.json)
    state = answer.get("usage") if answer is not None else None
    if answer is None or not isinstance(state, dict) or state.get("state") != "ready":
        if args.json:
            print(json.dumps({"schema": SCHEMA, "state": "unavailable"}), file=output)
        else:
            print("Guard could not read the usage records on this computer.", file=output)
        return 1
    if args.json:
        print(json.dumps({**state, "savings": answer.get("savings")}, sort_keys=True), file=output)
    else:
        output.write(str(answer.get("text") or ""))
    return 0
