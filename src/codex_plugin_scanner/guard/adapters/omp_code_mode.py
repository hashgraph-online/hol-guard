"""Detect Oh My Pi's Codex code mode, which routes every tool call through ``eval``."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from .base import HarnessContext


def omp_code_mode_warnings(
    home_dir: Path, workspace_dir: Path | None = None, environ: Mapping[str, str] | None = None
) -> list[str]:
    """Warn when the effective Oh My Pi settings turn Codex code mode on.

    The native ``omp_code_mode`` kind reads the settings layers. Without an answer
    there is no warning, since the warning is only advice.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    env = os.environ if environ is None else environ
    agent_dir = env.get("PI_CODING_AGENT_DIR")
    # The resident has its own working directory, so every relative path is
    # resolved here, against the caller's.
    request = {
        "home": str(home_dir.absolute()),
        "workspace": None if workspace_dir is None else str(workspace_dir.absolute()),
        "agentDir": str(Path(agent_dir).expanduser().absolute()) if agent_dir else None,
        "configDir": env.get("PI_CONFIG_DIR"),
    }
    try:
        answer = native_runner_authority("omp_code_mode", request)
    except NativeRunnerAuthorityError:
        return []
    warnings = answer.get("warnings")
    if not isinstance(warnings, list):
        return []
    return [warning for warning in warnings if isinstance(warning, str)]


def with_omp_code_mode_warnings(payload: dict[str, object], context: HarnessContext) -> dict[str, object]:
    # An explicit doctor home describes another installation, so the caller's OMP env does not apply.
    environ: Mapping[str, str] | None = {} if context.home_override_explicit else None
    extra = omp_code_mode_warnings(context.home_dir, context.workspace_dir, environ)
    if extra:
        existing = payload.get("warnings")
        payload["warnings"] = [*(existing if isinstance(existing, list) else []), *extra]
    return payload
