"""Path-bound, syntax-only validation of the managed Cline plugin."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping

from ..codex_hook_launch_runtime import isolated_hook_environment
from .base import HarnessContext
from .cline_paths import cline_plugin_root


def probe_cline_plugin_syntax(context: HarnessContext, state: Mapping[str, object]) -> dict[str, object]:
    """Validate generated JavaScript without executing plugin code when Node is available."""

    path_value = state.get("index_path")
    if not isinstance(path_value, str):
        return {"ok": False, "reason": "plugin_state_missing"}
    try:
        index_path = cline_plugin_root(context) / "index.js"
    except (OSError, RuntimeError, ValueError):
        return {"ok": False, "reason": "plugin_path_unsafe"}
    if path_value != str(index_path):
        return {"ok": False, "reason": "plugin_state_path_mismatch"}
    node = shutil.which("node")
    if node is None:
        return {"ok": True, "skipped": True, "reason": "node_not_available"}
    try:
        result = subprocess.run(
            [node, "--check", "--", str(index_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env=isolated_hook_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    return {"ok": result.returncode == 0, "return_code": result.returncode}
