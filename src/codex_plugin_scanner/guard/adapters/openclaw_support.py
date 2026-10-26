"""OpenClaw adapter support helpers."""

from __future__ import annotations

import sys
from pathlib import Path

from ..models import HarnessDetection
from .base import HarnessContext
from .bounded_cli_hook_bridge import bounded_cli_hook_command

_GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS = 3
_GUARD_PRETOOL_HOST_TIMEOUT_SECONDS = 5


def config_path(context: HarnessContext) -> Path:
    return context.home_dir / ".openclaw" / "openclaw.json"


def managed_root(context: HarnessContext) -> Path:
    return context.guard_home / "openclaw"


def overlay_payload(detection: HarnessDetection) -> dict[str, object]:
    return {
        "harness": "openclaw",
        "config_paths": list(detection.config_paths),
        "artifact_count": len(detection.artifacts),
        "artifact_ids": [artifact.artifact_id for artifact in detection.artifacts],
    }


def pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    cli_args = [
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "openclaw",
        "--home",
        str(context.home_dir),
    ]
    if context.workspace_dir is not None:
        cli_args.extend(["--workspace", str(context.workspace_dir)])
    cli_args.append("--json")
    command = bounded_cli_hook_command(
        python_executable=sys.executable,
        package_root=Path(__file__).resolve().parents[3],
        guard_home=context.guard_home,
        cli_args=cli_args,
        harness="openclaw",
        timeout_seconds=_GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS,
    )
    return {
        "command": list(command),
        "harness": "openclaw",
        "timeout_seconds": _GUARD_PRETOOL_HOST_TIMEOUT_SECONDS,
        "fail_open": False,
    }


def install_state(
    *,
    existing_manifest: dict[str, object],
    overlay_path: Path,
    pretool_path: Path,
) -> str:
    if len(existing_manifest) == 0:
        return "installed"
    if overlay_path.exists() and pretool_path.exists():
        return "already_managed"
    return "repaired_managed_install"
