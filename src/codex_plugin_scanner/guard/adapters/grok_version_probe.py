"""Run a bounded version probe in a private Grok working directory."""

import os
from collections.abc import Callable, Mapping

from .base import HarnessContext
from .grok_executable import GrokExecutableResolution


def probe_grok_version(
    context: HarnessContext,
    resolution: GrokExecutableResolution,
    *,
    run_probe: Callable[..., dict[str, object]],
    sanitize_environment: Callable[[HarnessContext, Mapping[str, str]], dict[str, str]],
) -> dict[str, object]:
    executable = resolution.executable
    if executable is None:
        return {
            "command": [],
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": resolution.error or "trusted Grok executable not found",
        }
    probe_cwd = context.guard_home / "runtime" / "grok-probe"
    try:
        probe_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            probe_cwd.chmod(0o700)
    except OSError as error:
        return {
            "command": [str(executable.path), "--no-auto-update", "--version"],
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": f"trusted probe directory unavailable: {error}",
        }
    return run_probe(
        [str(executable.path), "--no-auto-update", "--version"],
        timeout_seconds=8,
        cwd=probe_cwd,
        env=sanitize_environment(context, os.environ),
    )
