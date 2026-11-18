"""The facts only this process knows, handed to a native install op in one request.

The ``harness_adapter`` install ops run the whole install or uninstall inside the native runtime, so they are
told up front what a step would otherwise have asked this process for: the launcher interpreter, the shell
profile, the transition budget, the frozen-runtime flag, the Pi extension runtime, and the Claude daemon facts.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import cast

from .harness_context import HarnessContext


def _facts(
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    uninstall: bool = False,
) -> dict[str, object]:
    """The process facts a native install op takes for ``harnesses``.

    A removal renders no hook, so it asks the Guard daemon nothing: ``uninstall`` leaves out the daemon facts.
    """
    from . import native_transition_files
    from .frozen_runtime_commands import is_frozen_guard_runtime
    from .native_harness_client import describe
    from .shims import shell_profile_facts, shim_interpreter

    descriptions = {
        str(adapter.get("harness")): adapter for adapter in describe()["adapters"] if isinstance(adapter, dict)
    }
    facts: dict[str, object] = {
        "interpreter": shim_interpreter(),
        "shell_profile": shell_profile_facts(context),
        "transition": native_transition_files.transition_context(),
        "frozen": is_frozen_guard_runtime(),
        "runtime": None,
        "facts": {},
    }
    if any(descriptions.get(harness, {}).get("extension") for harness in harnesses):
        from .extension_runtime import extension_runtime

        facts["runtime"] = extension_runtime()
    harness_facts: dict[str, object] = {}
    if "claude-code" in harnesses and not uninstall:
        from .claude_hook_entry import claude_facts

        harness_facts["claude-code"] = claude_facts(context.guard_home)
    if "codex" in harnesses:
        from .codex_harness_client import codex_install_facts

        harness_facts["codex"] = codex_install_facts(context)
    facts["facts"] = harness_facts
    return facts


def install_facts(
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    uninstall: bool = False,
) -> dict[str, object]:
    """The process facts a native install op takes for ``harnesses``, and for the providers a harness delegates to.

    Paseo installs the native providers it delegates to for the daemon user, not for the caller's worktree, so
    their facts come from the context without a workspace, with which provider runtimes this host has.
    """
    from datetime import datetime, timezone

    from .native_harness_client import _native_context, describe
    from .native_harness_ops import resolved_executable

    descriptions = {
        str(adapter.get("harness")): adapter for adapter in describe()["adapters"] if isinstance(adapter, dict)
    }
    delegates = [
        str(name)
        for harness in harnesses
        if descriptions.get(harness, {}).get("install") == "delegated"
        for name in descriptions[harness].get("delegates", ())
    ]
    facts = _facts(context, harnesses, uninstall=uninstall)
    if not delegates:
        return facts
    native = _native_context(context)
    providers = _facts(native, [name for name in delegates if name not in harnesses], uninstall=uninstall)
    merged: dict[str, object] = dict(cast("dict[str, object]", providers["facts"]))
    merged.update(cast("dict[str, object]", facts["facts"]))
    facts["facts"] = merged
    facts["runtime"] = facts["runtime"] or providers["runtime"]
    facts["delegates"] = {name: resolved_executable(name, native) is not None for name in delegates}
    facts["now"] = datetime.now(timezone.utc).isoformat()
    facts["source"] = "default"
    return facts


def adapter_manifest(answer: dict[str, object]) -> dict[str, object]:
    """The manifest an ``adapter_install`` or ``adapter_uninstall`` answer carries."""
    manifest = answer.get("manifest")
    if not isinstance(manifest, str):
        raise ValueError("Harness adapter answer is malformed")
    decoded = json.loads(manifest)
    if not isinstance(decoded, dict):
        raise ValueError("Harness adapter answer is malformed")
    return decoded
