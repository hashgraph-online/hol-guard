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

from .base import HarnessContext


def install_facts(
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    workspaces: Mapping[str, Path | None] | None = None,
) -> dict[str, object]:
    """The process facts a native install op takes for ``harnesses``.

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
    if "claude-code" in harnesses:
        from ..claude_hook_entry import claude_facts

        facts["facts"] = {"claude-code": claude_facts(context.guard_home)}
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
