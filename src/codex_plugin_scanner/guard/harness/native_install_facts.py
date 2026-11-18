"""The facts only this process knows, handed to a native install op in one request.

The ``harness_adapter`` install ops run the whole install or uninstall inside the native runtime, so they are
told up front what a step would otherwise have asked this process for: the launcher interpreter, the shell
profile, the transition budget, the frozen-runtime flag, the Pi extension runtime, the Claude daemon facts and
the Windows workspace skills.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from .base import HarnessContext


def _facts(
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    workspaces: Mapping[str, Path | None] | None = None,
    uninstall: bool = False,
) -> dict[str, object]:
    """The process facts a native install op takes for ``harnesses``.

    A removal renders no hook, so it asks the Guard daemon nothing: ``uninstall`` leaves out the daemon facts.

    ``workspaces`` names the workspace each harness installs into when it is not the context's own, as an update
    repair reinstalls from the install record's workspace.
    """
    from .. import native_transition_files
    from ..aibom_detection import portable_workspace_skills
    from ..frozen_runtime_commands import is_frozen_guard_runtime
    from ..shims import shell_profile_facts, shim_interpreter
    from .native_harness import describe

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
        "workspace_skills": {
            harness: portable_workspace_skills(
                harness, context.workspace_dir if workspaces is None else workspaces.get(harness)
            )
            for harness in harnesses
        },
    }
    if any(descriptions.get(harness, {}).get("extension") for harness in harnesses):
        from .extension_runtime import extension_runtime

        facts["runtime"] = extension_runtime()
    harness_facts: dict[str, object] = {}
    if "claude-code" in harnesses and not uninstall:
        from ..claude_hook_entry import claude_facts

        harness_facts["claude-code"] = claude_facts(context.guard_home)
    if "codex" in harnesses:
        from ..codex_harness_client import codex_install_facts

        harness_facts["codex"] = codex_install_facts(context)
    facts["facts"] = harness_facts
    return facts


def ensure_store(context: HarnessContext) -> None:
    """Create the Guard store the native install ops write their records into.

    The runtime opens an existing store; creating its file and schema is still the Python store's first start.
    """
    from ..store import GuardStore

    GuardStore(context.guard_home)


def install_facts(
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    workspaces: Mapping[str, Path | None] | None = None,
    uninstall: bool = False,
) -> dict[str, object]:
    """The process facts a native install op takes for ``harnesses``, and for the providers a harness delegates to.

    Paseo installs the native providers it delegates to for the daemon user, not for the caller's worktree, so
    their facts come from the context without a workspace, with which provider runtimes this host has.
    """
    from datetime import datetime, timezone

    from .native_harness import _native_context, describe
    from .registry import get_adapter

    descriptions = {
        str(adapter.get("harness")): adapter for adapter in describe()["adapters"] if isinstance(adapter, dict)
    }
    delegates = [
        str(name)
        for harness in harnesses
        if descriptions.get(harness, {}).get("install") == "delegated"
        for name in descriptions[harness].get("delegates", ())
    ]
    facts = _facts(context, harnesses, workspaces=workspaces, uninstall=uninstall)
    if not delegates:
        return facts
    native = _native_context(context)
    providers = _facts(native, [name for name in delegates if name not in harnesses], uninstall=uninstall)
    for group in ("workspace_skills", "facts"):
        merged: dict[str, object] = dict(cast("dict[str, object]", providers[group]))
        merged.update(cast("dict[str, object]", facts[group]))
        facts[group] = merged
    facts["runtime"] = facts["runtime"] or providers["runtime"]
    facts["delegates"] = {name: get_adapter(name).resolved_executable(native) is not None for name in delegates}
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
