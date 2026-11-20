"""Small, read-only Codex incident report, assembled by the native runtime."""

from __future__ import annotations

import json
import sys
from typing import TextIO

from ..codex_harness_client import live_hook_ask
from ..harness_context import HarnessContext


def run_codex_incident_export(args: object, context: HarnessContext, output_stream: TextIO | None = None) -> int:
    output = output_stream or sys.stdout
    if getattr(args, "harness", None) != "codex" or any(
        bool(getattr(args, flag, False))
        for flag in ("repair", "harnesses", "perf", "notifications", "force_notification_settings")
    ):
        print(json.dumps({"error": "incident_export_requires_codex_without_other_doctor_actions"}), file=output)
        return 2
    try:
        answer = live_hook_ask("incident_report", context)
    except (OSError, ValueError, RuntimeError) as error:
        # A broken Guard config, a refused op or a missing runtime are states
        # this report is for: name the failure and keep its reason instead of
        # failing with a traceback.
        failure = {"error": "incident_report_failed", "detail": type(error).__name__, "reason": str(error)[:256]}
        print(json.dumps(failure), file=output)
        return 2
    report = answer.get("report")
    if not isinstance(report, str):
        print(json.dumps({"error": str(answer.get("error") or "incident_report_unavailable")}), file=output)
        return 2
    print(report, file=output)
    return 0
