"""The native ``desktop_hook_proxy`` kind's launch script, for tests that render its launch.

The kind's own path, bundle and signature checks are covered by its Rust tests.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority


def launch_script() -> tuple[str, str]:
    """The kind's launch script and its ``$0``."""
    answer = native_runner_authority("desktop_hook_proxy", {"op": "script"})
    return str(answer["script"]), str(answer["name"])
