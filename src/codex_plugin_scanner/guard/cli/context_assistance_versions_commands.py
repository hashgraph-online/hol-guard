"""Argument and output framing for native CIGAR versions and update jobs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO


def configure(actions: Any) -> None:
    definitions = (
        ("catalog", "catalog", "Inspect catalog trust, freshness and withdrawal metadata without probing"),
        (
            "catalog-import",
            "import_catalog",
            "Read a signed catalog from stdin; preserve runtime selection and enablement",
        ),
        ("catalog-refresh", "refresh_catalog", "Refresh the configured signed catalog in a cancellable native job"),
        ("versions", "releases", "List authenticated release metadata; do not install or switch"),
        (
            "preferences",
            "preferences",
            "Inspect native update preferences, restrictions and revision without starting CIGAR",
        ),
        ("pin", "pin", "Pin explicit selection changes to one exact catalog build; keep the current runtime running"),
        ("unpin", "unpin", "Remove the local update pin; retain managed restrictions and the current selection"),
        (
            "update-policy",
            "update_policy",
            "Save manual/notification and channel preferences; do not install or switch",
        ),
        ("interpreters", "interpreters", "List previously verified private Python metadata without probing"),
        ("jobs", "jobs", "List installation and runtime-switch progress without starting CIGAR"),
        ("job", "job", "Inspect one native update job"),
        ("setup-python", "setup_interpreter", "Prepare an approved private Python build; keep CIGAR off"),
        ("install", "install", "Install or reverify an exact approved build without selecting or starting it"),
        (
            "switch",
            "prepare_switch",
            "Prepare a replacement while preserving the current running or off state; commit separately",
        ),
        ("rollback", "prepare_rollback", "Prepare the authenticated last-good runtime using current data"),
        ("commit", "commit", "Commit a Ready selection; keep CIGAR off or acknowledge a running runtime interruption"),
        ("cancel", "cancel", "Cancel an update job and retain cleanup ownership"),
        ("recover", "recover", "Reconcile a job explicitly; never restore grants from progress records"),
    )
    for name, operation, description in definitions:
        parser = actions.add_parser(name, help=description, description=description)
        parser.set_defaults(context_kind="versions", context_version_action=operation)
        parser.add_argument("--guard-home", default=argparse.SUPPRESS)
        parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if operation in {"pin", "unpin", "update_policy"}:
            parser.add_argument(
                "--revision", required=True, help="Exact revision from context preferences; reload after a conflict"
            )
            if operation == "pin":
                parser.add_argument("pinned_build")
            if operation == "update_policy":
                parser.add_argument("--mode", choices=("manual", "notify"))
                parser.add_argument("--channel", choices=("stable", "preview"))
        if operation in {"job", "commit", "cancel", "recover", "refresh_catalog"}:
            parser.add_argument("job_id")
        elif operation in {"install", "setup_interpreter"}:
            parser.add_argument("build_id")
            parser.add_argument("--job-id", required=True)
            if operation == "install":
                parser.add_argument("--interpreter-id", required=True)
        elif operation in {"prepare_switch", "prepare_rollback"}:
            parser.add_argument("--job-id", required=True)
            if operation == "prepare_switch":
                parser.add_argument("target_runtime_id")
        if operation in {"prepare_switch", "prepare_rollback", "commit", "recover"}:
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


def execute(args: argparse.Namespace, home: Path, *, input_text: str | None = None) -> dict[str, Any]:
    from ..native_context_assistance import ContextAssistanceError, versions

    operation = args.context_version_action
    payload: dict[str, object] = {"action": operation}
    if operation in {"pin", "unpin", "update_policy"}:
        current = versions(guard_home=home, payload={"action": "preferences"})
        requested = current["result"].get("requested")
        if not isinstance(requested, dict):
            raise ContextAssistanceError("native_context_assistance_response_invalid")
        preferences = dict(requested)
        if operation in {"pin", "unpin"}:
            preferences["pinned_build"] = args.pinned_build if operation == "pin" else None
        else:
            if args.mode is not None:
                preferences["mode"] = args.mode
            if args.channel is not None:
                preferences["allow_preview"] = args.channel == "preview"
        return versions(
            guard_home=home,
            payload={
                "action": "set_preferences",
                "expected_revision": args.revision,
                "preferences": preferences,
            },
        )
    if operation == "import_catalog":
        signed = input_text if input_text is not None else sys.stdin.read(1024 * 1024 + 1)
        if len(signed.encode("utf-8")) > 1024 * 1024:
            raise ContextAssistanceError("native_context_assistance_cigar_catalog_too_large")
        payload["signed_catalog"] = signed
    for field in ("job_id", "build_id", "interpreter_id", "target_runtime_id"):
        if hasattr(args, field):
            payload[field] = getattr(args, field)
    if getattr(args, "generation", None) is not None:
        payload["expected_generation"] = args.generation
    if operation == "commit":
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
            print("No update jobs.", file=output)
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=output)
