"""`hol-guard context usage`: model usage per tool, from each tool's own records."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TextIO

NAMES = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "copilot": "Copilot",
    "cursor": "Cursor",
    "gemini": "Gemini",
    "opencode": "OpenCode",
    "pi": "Pi",
}
ROWS = (
    ("uncached_input_tokens", "Input at full price"),
    ("cached_input_tokens", "Input read from cache"),
    ("cache_write_tokens", "Input written to cache"),
    ("output_tokens", "Output"),
    ("requests", "Model requests"),
    ("compactions", "Chat summaries"),
)


def configure(actions: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    usage = actions.add_parser(
        "usage",
        help="Show model usage per AI tool, read from each tool's own records on this computer",
        description=(
            "Adds up the usage Codex and Claude Code record for every model request in their session files. "
            "Guard does not estimate; tools whose records it does not read are named, not counted."
        ),
    )
    usage.set_defaults(context_kind="usage")
    usage.add_argument("--guard-home", default=argparse.SUPPRESS)
    usage.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


def run(args: argparse.Namespace, output: TextIO) -> int:
    from ..config import resolve_guard_home
    from ..context_usage_meter import CACHE_NAME, scan, summarize

    guard_home = resolve_guard_home(args.guard_home)
    if not args.json and not (guard_home / CACHE_NAME).exists():
        print("Counting. The first count of a long history can take a minute.", file=sys.stderr)
    try:
        state = summarize(scan(Path.home(), guard_home, os.environ))
    except (OSError, ValueError):
        if args.json:
            print(json.dumps({"schema": "guard-context-usage-meter.v1", "state": "unavailable"}), file=output)
        else:
            print("Guard could not read the usage records on this computer.", file=output)
        return 1
    if args.json:
        print(json.dumps(state, sort_keys=True), file=output)
    else:
        render(state, output)
    return 0


def render(state: dict, output: TextIO) -> None:
    print(
        f"Model usage from each tool's own records on this computer, today and over the last "
        f"{state['window_days']} days.",
        file=output,
    )
    today = {tool["harness"]: tool for tool in state["today"]}
    for tool in state["week"]:
        name = NAMES.get(tool["harness"], tool["harness"])
        print(file=output)
        if not tool["sessions"]:
            print(f"{name}: no sessions in the last {state['window_days']} days.", file=output)
            continue
        print(f"{name}: {tool['sessions']:,} {'session' if tool['sessions'] == 1 else 'sessions'}", file=output)
        print(f"  {'':24}{'Today':>18}{'Last ' + str(state['window_days']) + ' days':>20}", file=output)
        for field, label in ROWS:
            now = today.get(tool["harness"], {}).get("totals", {}).get(field, 0)
            print(f"  {label:24}{now:>18,}{tool['totals'][field]:>20,}", file=output)
    names = [NAMES.get(name, name) for name in state["unread"]]
    unread = ", ".join(names[:-1]) + " or " + names[-1] if len(names) > 1 else "".join(names)
    print(file=output)
    print(f"Guard does not read usage records from {unread}, so they are not counted here.", file=output)
