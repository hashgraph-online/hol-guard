"""Dispatch the privacy-safe local risk report command."""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..mdm.runtime_request import runtime_answer
from ..store import GuardStore
from .product import build_guard_status_payload


def _package_version() -> str:
    try:
        return version("hol-guard")
    except PackageNotFoundError:
        return "unknown"


# The only status fields the report reads; nothing else leaves this process.
_REPORT_FIELDS = ("generated_at", "runtime_status", "managed_harnesses", "pending_approvals", "receipt_count")
_HARNESS_FIELDS = ("harness", "installed", "review_count")


def _report_status(status_payload: dict[str, object]) -> dict[str, object]:
    status: dict[str, object] = {name: status_payload.get(name) for name in _REPORT_FIELDS}
    status["sync_configured"] = bool(status_payload.get("sync_configured"))
    harnesses = status_payload.get("harnesses")
    if isinstance(harnesses, list):
        status["harnesses"] = [
            {name: item.get(name) for name in _HARNESS_FIELDS if name in item}
            for item in harnesses
            if isinstance(item, dict)
        ]
    return status


def run_guard_risk_report_command(
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
    del guard_home, workspace, input_text
    if context is None or store is None or config is None:
        raise RuntimeError("Guard context, store, and config are required")

    status_payload = build_guard_status_payload(context, store, config)
    stream = output_stream or sys.stdout
    # ``local_risk_report.rs`` builds, signs and renders the report.
    answer = runtime_answer(
        "native-local-risk-report-v1",
        "local-risk-report",
        {
            "schema": "local-risk-report.v1",
            "status": _report_status(status_payload),
            "guard_version": _package_version(),
            "format": str(getattr(args, "format", "json")),
        },
        output_limit=1024 * 1024,
        timeout_seconds=10.0,
        # A cold runtime's first capability probe may take up to 20 seconds.
        status_timeout_seconds=20.0,
    )
    body = None if answer is None else answer.get("body")
    if not isinstance(body, str):
        print("Guard's native runtime is unavailable, so the risk report was not built.", file=sys.stderr)
        return 1

    output = getattr(args, "output", None)
    if isinstance(output, str) and output.strip():
        destination = Path(output).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")
        print(f"Wrote sanitized local risk report: {destination}", file=stream)
        return 0

    print(body, end="", file=stream)
    return 0


__all__ = ["run_guard_risk_report_command"]
