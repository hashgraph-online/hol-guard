"""Guard CLI command support registry."""

# fmt: off
# ruff: noqa: I001

from __future__ import annotations



from collections.abc import Mapping
from types import ModuleType

from . import _commands_shared as __commands_shared
from . import commands_support_workspace as _commands_support_workspace
from . import commands_support_interaction as _commands_support_interaction
from . import commands_support_hook_state as _commands_support_hook_state
from . import commands_support_command_activity as _commands_support_command_activity
from . import commands_support_permission_store as _commands_support_permission_store
from . import commands_support_claude_approval as _commands_support_claude_approval
from . import commands_support_runtime_policy as _commands_support_runtime_policy
from . import commands_support_prompts as _commands_support_prompts
from . import commands_support_hook_payload as _commands_support_hook_payload
from . import commands_support_runtime_artifacts as _commands_support_runtime_artifacts
from . import commands_support_codex_commands as _commands_support_codex_commands
from . import commands_support_codex_reads as _commands_support_codex_reads
from . import commands_support_codex_git as _commands_support_codex_git
from . import commands_support_codex_paths as _commands_support_codex_paths
from . import commands_support_runtime_resolution as _commands_support_runtime_resolution
from . import commands_support_connect as _commands_support_connect
from . import commands_support_service as _commands_support_service
from . import commands_verified_read as _commands_verified_read
from . import commands_dispatch_local as _commands_dispatch_local
from . import commands_dispatch_mdm as _commands_dispatch_mdm
from . import commands_dispatch_proxy as _commands_dispatch_proxy
from . import commands_dispatch_records as _commands_dispatch_records
from . import commands_dispatch_trust as _commands_dispatch_trust
from . import commands_dispatch_admin as _commands_dispatch_admin
from . import commands_dispatch_cloud as _commands_dispatch_cloud
from . import commands_hook_copilot as _commands_hook_copilot
from . import commands_hook_claude as _commands_hook_claude
from . import commands_hook_runtime_state as _commands_hook_runtime_state
from . import commands_hook_runtime_eval as _commands_hook_runtime_eval
from . import commands_hook_runtime_review as _commands_hook_runtime_review
from . import commands_hook_runtime_finish as _commands_hook_runtime_finish
from . import commands_hook_generic as _commands_hook_generic
from . import commands_hook as _commands_hook
from . import commands_router as _commands_router

_SOURCE_MODULES: tuple[ModuleType, ...] = (
    __commands_shared,
    _commands_support_workspace,
    _commands_support_interaction,
    _commands_support_hook_state,
    _commands_support_command_activity,
    _commands_support_permission_store,
    _commands_support_claude_approval,
    _commands_support_runtime_policy,
    _commands_support_prompts,
    _commands_support_hook_payload,
    _commands_support_runtime_artifacts,
    _commands_support_codex_commands,
    _commands_support_codex_reads,
    _commands_support_codex_git,
    _commands_support_codex_paths,
    _commands_support_runtime_resolution,
    _commands_support_connect,
    _commands_support_service,
    _commands_verified_read,
    _commands_dispatch_local,
    _commands_dispatch_mdm,
    _commands_dispatch_proxy,
    _commands_dispatch_records,
    _commands_dispatch_trust,
    _commands_dispatch_admin,
    _commands_dispatch_cloud,
    _commands_hook_copilot,
    _commands_hook_claude,
    _commands_hook_runtime_state,
    _commands_hook_runtime_eval,
    _commands_hook_runtime_review,
    _commands_hook_runtime_finish,
    _commands_hook_generic,
    _commands_hook,
    _commands_router,
)


def _module_exports(module: ModuleType) -> dict[str, object]:
    exported = getattr(module, "__all__", None)
    if isinstance(exported, list):
        return {name: getattr(module, name) for name in exported}
    return {name: value for name, value in vars(module).items() if not name.startswith("__")}


def _build_export_map(
    overrides: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], dict[ModuleType, set[str]]]:
    export_map: dict[str, object] = {}
    module_export_names: dict[ModuleType, set[str]] = {}
    owners: dict[str, str] = {}
    collisions: dict[str, list[str]] = {}
    for module in _SOURCE_MODULES:
        module_exports = _module_exports(module)
        module_export_names[module] = set(module_exports)
        for name, value in module_exports.items():
            owner = owners.get(name)
            if owner is not None:
                collisions.setdefault(name, [owner]).append(module.__name__)
                continue
            owners[name] = module.__name__
            export_map[name] = value
    if collisions:
        formatted = ", ".join(
            f"{name} ({', '.join(module_names)})" for name, module_names in sorted(collisions.items())
        )
        raise RuntimeError(f"commands_support duplicate exports: {formatted}")
    if overrides is not None:
        export_map.update(overrides)
    return export_map, module_export_names


def _sync_namespace(overrides: Mapping[str, object] | None = None) -> None:
    export_map, module_export_names = _build_export_map(overrides)
    override_names = set(overrides or ())
    globals().update(export_map)
    for module in _SOURCE_MODULES:
        module_globals = vars(module)
        local_export_names = module_export_names[module]
        for name, value in export_map.items():
            if name not in local_export_names or name in override_names:
                module_globals[name] = value


def _apply_overrides(overrides: Mapping[str, object]) -> None:
    _sync_namespace(overrides)


_sync_namespace()

__all__ = [name for name in globals() if not name.startswith("__")]
