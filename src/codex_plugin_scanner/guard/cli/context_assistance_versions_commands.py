"""Argument and output framing for built-in CIGAR engine setup jobs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, TextIO


def configure(actions: Any) -> None:
    definitions = (
        ("jobs", "jobs", "List built-in engine setup progress without starting CIGAR"),
        ("job", "job", "Inspect one setup job"),
        (
            "switch",
            "prepare_switch",
            "Prepare a replacement while preserving the current running or off state; commit separately",
        ),
        ("commit", "commit", "Commit a Ready selection; keep CIGAR off or acknowledge a running runtime interruption"),
        ("cancel", "cancel", "Cancel a setup job and retain cleanup ownership"),
        ("recover", "recover", "Reconcile a job explicitly; never restore grants from progress records"),
    )
    for name, operation, description in definitions:
        parser = actions.add_parser(name, help=description, description=description)
        parser.set_defaults(context_kind="versions", context_version_action=operation)
        parser.add_argument("--guard-home", default=argparse.SUPPRESS)
        parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if operation in {"job", "commit", "cancel", "recover"}:
            parser.add_argument("job_id")
        elif operation == "prepare_switch":
            parser.add_argument("--job-id", required=True)
            parser.add_argument("target_runtime_id")
        if operation in {"prepare_switch", "commit", "recover"}:
            parser.add_argument(
                "--generation",
                required=operation != "recover",
                help="Exact generation string from context status (required for switch recovery)",
            )
        if operation == "commit":
            parser.add_argument(
                "--acknowledge-reconnect",
                action="store_true",
                help="Required when switching a running runtime; acknowledge interruption and fresh app/source grants",
            )


def execute(args: argparse.Namespace, home: Path) -> dict[str, Any]:
    from ..native_context_assistance import versions

    payload: dict[str, object] = {"action": args.context_version_action}
    for field in ("job_id", "target_runtime_id"):
        if hasattr(args, field):
            payload[field] = getattr(args, field)
    if getattr(args, "generation", None) is not None:
        payload["expected_generation"] = args.generation
    if args.context_version_action == "commit":
        payload["reconnect"] = args.acknowledge_reconnect
    return versions(guard_home=home, payload=payload)


def render(answer: dict[str, Any], output: TextIO) -> None:
    state, result = answer["state"], answer["result"]
    print(f"CIGAR: {state['availability']} · generation {state['generation']}", file=output)
    if "job_id" in result:
        print(f"{result['job_id']}: {result['operation']} · {result['phase']} ({result['code']})", file=output)
        if result.get("can_commit"):
            if result.get("keeps_disabled") is True and result.get("reconnect_required") is False:
                print("Ready to select. CIGAR stays off; enable it separately when needed.", file=output)
            else:
                print(
                    "Ready to commit. Committing reconnects applications and requires fresh source grants.", file=output
                )
        elif result.get("cleanup_pending"):
            print("Cleanup is still in progress; retry job inspection before another lifecycle operation.", file=output)
        elif result.get("recovery_available"):
            print("Explicit recovery is required; progress alone does not start a runtime.", file=output)
    elif "jobs" in result:
        for job in result["jobs"]:
            print(f"  {job['job_id']}: {job['operation']} · {job['phase']} ({job['code']})", file=output)
        if not result["jobs"]:
            print("No setup jobs.", file=output)
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=output)
