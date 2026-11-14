"""`hol-guard context usage`: model usage per tool, from each tool's own records."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

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


def run(args: argparse.Namespace, output: TextIO) -> int:
    from ..config import resolve_guard_home
    from ..context_usage_meter import CACHE_NAME, scan, summarize
    from ..native_context_assistance import ContextAssistanceError, savings

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
    try:
        state["savings"] = savings(guard_home=guard_home)
    except ContextAssistanceError:
        state["savings"] = None
    if args.json:
        print(json.dumps(state, sort_keys=True), file=output)
    else:
        render(state, output)
        render_savings(state["savings"], output)
    return 0


def render(state: dict[str, Any], output: TextIO) -> None:
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
    names = [NAMES.get(name) or str(name) for name in state["unread"]]
    unread = ", ".join(names[:-1]) + " or " + names[-1] if len(names) > 1 else "".join(names)
    print(file=output)
    print(f"Guard does not read usage records from {unread}, so they are not counted here.", file=output)


def render_savings(report: dict[str, Any] | None, output: TextIO) -> None:
    def say(line: str) -> None:
        print(line, file=output)

    say("")
    if report is None:
        say("Guard's background service did not answer, so it cannot estimate what CIGAR saved.")
        return
    total, days = report["total"], report["window_days"]
    if not total["sessions"]:
        say(f"CIGAR has not handed code to a prompt in the last {days} days, so there is nothing to estimate.")
        return
    measured, sessions = total["measured_sessions"], total["sessions"]
    if not measured:
        say("CIGAR helped, but Guard could not read those sessions' records, so it cannot estimate yet.")
    elif not total["used_tokens"]:
        say("CIGAR helped, but those sessions' records show no tokens used, so Guard cannot estimate yet.")
    else:
        saved = total["estimated_saved_tokens"]
        say(f"CIGAR saved about {saved:,} tokens in the last {days} days. This is an estimate.")
        if measured < sessions:
            say(f"  The estimate covers {measured:,} of {sessions:,} sessions. Guard could not read the rest.")
    prompts = "prompt" if total["prompts"] == 1 else "prompts"
    say(f"  It handed {total['prompts']:,} {prompts} about {total['context_tokens']:,} tokens of code.")
    checked, opened = total.get("files_checked", 0), total["files_opened_anyway"]
    if checked:
        say(f"  Of {checked:,} files it showed, the agent opened {opened:,} again anyway.")
    rates = ", ".join(f"{NAMES.get(app['app'], app['app'])} {app['rate_percent']}%" for app in report["apps"])
    say(f"  How: the tokens those sessions used, and the share CIGAR saved on Guard's benchmark ({rates}).")
