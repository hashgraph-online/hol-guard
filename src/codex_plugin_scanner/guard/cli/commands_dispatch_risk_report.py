"""Dispatch the privacy-safe local risk report command."""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..local_risk_report import (
    build_local_risk_report,
    local_risk_report_json,
    render_local_risk_report_html,
)
from ..store import GuardStore
from .product import build_guard_status_payload


def _package_version() -> str:
    try:
        return version("hol-guard")
    except PackageNotFoundError:
        return "unknown"


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
    report = build_local_risk_report(status_payload, guard_version=_package_version())
    report_format = str(getattr(args, "format", "json"))
    body = render_local_risk_report_html(report) if report_format == "html" else local_risk_report_json(report)
    stream = output_stream or sys.stdout

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
