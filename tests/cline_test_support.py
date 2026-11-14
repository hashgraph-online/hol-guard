"""Cline helpers for tests, answered by the native runtime.

The plugin source comes from the ``cline_plugin_render`` kind the install
uses; transport state and removal go through the ``harness_adapter`` ops the
adapter asks.
"""

from __future__ import annotations

from typing import Any

from codex_plugin_scanner.guard.adapters import cline_runtime
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_runtime import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.native_harness import ask
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority


def plugin_source(context: HarnessContext, guard_cli: list[str], hook_argv: list[str] | None = None) -> str:
    """The managed plugin source for ``guard_cli``."""
    managed = context.guard_home / "managed" / "cline"
    args: dict[str, object] = {
        "guard_cli": list(guard_cli),
        "hook_argv": list(hook_argv if hook_argv is not None else [*guard_cli, "--harness", "cline", "--json"]),
        "adapter_state": str(managed / "adapter-state.json"),
        "proof_loaded": str(managed / "proofs" / "plugin-loaded.json"),
        "proof_pretool": str(managed / "proofs" / "plugin-pretool.json"),
        "proof_posttool": str(managed / "proofs" / "plugin-posttool.json"),
    }
    return str(native_runner_authority("cline_plugin_render", args, guard_home=context.guard_home)["source"])


def runtime_probe(context: HarnessContext) -> dict[str, Any]:
    probe = ClineHarnessAdapter().runtime_probe(context)
    assert probe is not None
    return probe


def plugin_state(context: HarnessContext) -> dict[str, Any]:
    return runtime_probe(context)["plugin"]


def hook_state(context: HarnessContext) -> dict[str, Any]:
    return runtime_probe(context)["native_hooks"]


def install_plugin(context: HarnessContext) -> dict[str, Any]:
    """Write the managed plugin the way an install does, without confirming it."""
    facts = cline_runtime._facts(context, "plugin")
    answer = ask("install_transport", context, harness="cline", transport="plugin", frozen=False, facts=facts)
    return answer["manifest"]


def uninstall(context: HarnessContext, surface: str) -> dict[str, Any]:
    return ask("uninstall", context, harness="cline", surface=surface)["manifest"]
