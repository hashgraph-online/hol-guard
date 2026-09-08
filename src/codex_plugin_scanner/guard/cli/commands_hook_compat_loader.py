"""Explicit loader for the Python hook compatibility oracle.

The Rust worker owns production hook decisions.  The modules listed here are
kept for named differential tests and the explicit ``off``/``shadow`` oracle
surface only; importing the CLI facade must not import them eagerly.
"""

from __future__ import annotations

from importlib import import_module

from ..native_mode import python_oracle_surface_enabled

_COMPATIBILITY_EXPORTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        ".commands_hook_claude",
        ("_run_hook_claude_permission_prompt_notification", "_run_hook_claude_permission_request"),
    ),
    (
        ".commands_hook_compatibility",
        ("maybe_handle_cursor_post_tool", "prepare_compatibility_hook_payload"),
    ),
    (
        ".commands_hook_copilot",
        ("_run_hook_copilot_permission_request", "_run_hook_copilot_pretool"),
    ),
    (".commands_hook_generic", ("_run_hook_generic_payload",)),
    (".commands_hook_runtime_eval", ("_evaluate_runtime_artifact_hook",)),
    (".commands_hook_runtime_finish", ("_finalize_runtime_artifact_hook",)),
    (".commands_hook_runtime_review", ("_review_runtime_artifact_hook",)),
    (".commands_hook_runtime_state", ("RuntimeArtifactHookState",)),
    ("..runtime.hook_payload_reference", ("hydrate_hook_payload_reference",)),
)
COMPATIBILITY_SURFACE_NAMES = frozenset(name for _, names in _COMPATIBILITY_EXPORTS for name in names)


def load_hook_compatibility_surface() -> dict[str, object] | None:
    """Load compatibility exports only inside the explicit test oracle.

    Returning ``None`` is intentional: callers can fail closed when a
    production process attempts to reach the retired Python decision path.
    """

    if not python_oracle_surface_enabled():
        return None
    surface: dict[str, object] = {}
    for module_name, names in _COMPATIBILITY_EXPORTS:
        module = import_module(module_name, package=__package__)
        for name in names:
            surface[name] = getattr(module, name)
    return surface


__all__ = ["COMPATIBILITY_SURFACE_NAMES", "load_hook_compatibility_surface"]
