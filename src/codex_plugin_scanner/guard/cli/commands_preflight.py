"""Bounded preflight command entrypoint for broad local scan safety."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import TextIO

from .commands_support_interaction import _emit, _run_consumer_scan_with_mode


def _unsafe_broad_preflight_target(target: Path, *, home_dir: Path) -> bool:
    """Reject roots that make preflight traverse an entire account or filesystem."""

    try:
        resolved_target = target.resolve()
        resolved_home = home_dir.resolve()
    except (OSError, RuntimeError):
        return True
    filesystem_root = Path(resolved_target.anchor).resolve()
    if resolved_target == filesystem_root:
        return True
    try:
        resolved_home.relative_to(resolved_target)
    except ValueError:
        return False
    return True


def _emit_preflight(
    payload: dict[str, object],
    *,
    json_output: bool,
    output_stream: TextIO | None,
) -> None:
    """Preserve the canonical renderer while honoring an explicit output stream."""

    if output_stream is None:
        _emit("preflight", payload, json_output)
        return
    with redirect_stdout(output_stream):
        _emit("preflight", payload, json_output)


def _run_guard_safe_preflight_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Run preflight without recursively scanning a whole home directory by accident."""

    del input_text
    json_output = bool(getattr(args, "json", False))
    raw_target = str(getattr(args, "target", ".") or ".")
    try:
        target = Path(raw_target).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        message = f"unable to resolve preflight target: {error}"
        if json_output:
            print(
                json.dumps(
                    {
                        "error": "preflight_target_unresolvable",
                        "message": message,
                    },
                    sort_keys=True,
                ),
                file=output_stream or sys.stdout,
            )
        else:
            print(f"Error: {message}", file=sys.stderr)
        return 2
    if _unsafe_broad_preflight_target(target, home_dir=Path.home()):
        message = (
            "Choose a project directory or file instead of scanning your entire home directory or filesystem root."
        )
        if json_output:
            print(
                json.dumps(
                    {
                        "error": "preflight_target_too_broad",
                        "message": message,
                    },
                    sort_keys=True,
                ),
                file=output_stream or sys.stdout,
            )
        else:
            print(f"Error: {message}", file=sys.stderr)
        return 2

    payload = _run_consumer_scan_with_mode(
        target,
        intended_harness=getattr(args, "harness", None),
        cisco_mode=args.cisco_mode,
    )
    _emit_preflight(payload, json_output=json_output, output_stream=output_stream)
    if getattr(args, "enforce", False):
        install_verdict = payload.get("install_verdict")
        if isinstance(install_verdict, dict) and str(install_verdict.get("action")) != "allow":
            return 2
    return 0


__all__ = ["_run_guard_safe_preflight_command", "_unsafe_broad_preflight_target"]
