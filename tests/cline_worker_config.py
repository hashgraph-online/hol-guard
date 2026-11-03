"""The native Cline hook worker configuration, for tests that drive the worker directly.

Production renders it through the native ``cline_hook_files`` kind; the golden
vectors under ``rust/crates/guard-runtime/testdata/cline`` pin that rendering.
"""

from __future__ import annotations

import json

from codex_plugin_scanner.guard.adapters.base import HarnessContext


def worker_config(context: HarnessContext, *, event_name: str, guard_cli: list[str]) -> str:
    managed = context.guard_home / "managed" / "cline"
    config = {
        "marker": "HOL_GUARD_MANAGED_CLINE_HOOK_V1",
        "schema": "cline-hook-worker.v1",
        "event": event_name,
        "guard": guard_cli,
        "proof": str(managed / "proofs" / f"native-{event_name.lower()}.json"),
        "adapter_state": str(managed / "adapter-state.json"),
    }
    return json.dumps(config, indent=2, sort_keys=True) + "\n"
