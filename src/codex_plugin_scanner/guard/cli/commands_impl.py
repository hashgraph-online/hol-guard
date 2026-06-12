"""Guard CLI command handlers."""

# fmt: off
# ruff: noqa: I001

from __future__ import annotations



from collections.abc import Mapping
from types import ModuleType

from . import _commands_shared as __commands_shared
from . import commands_parser_helpers as _commands_parser_helpers
from . import commands_impl_helpers_01 as _commands_impl_helpers_01
from . import commands_impl_helpers_02 as _commands_impl_helpers_02
from . import commands_impl_helpers_03 as _commands_impl_helpers_03
from . import commands_impl_helpers_04 as _commands_impl_helpers_04
from . import commands_impl_helpers_05 as _commands_impl_helpers_05
from . import commands_impl_helpers_06 as _commands_impl_helpers_06
from . import commands_impl_helpers_07 as _commands_impl_helpers_07
from . import commands_impl_helpers_08 as _commands_impl_helpers_08
from . import commands_impl_helpers_09 as _commands_impl_helpers_09
from . import commands_impl_helpers_10 as _commands_impl_helpers_10
from . import commands_impl_helpers_11 as _commands_impl_helpers_11
from . import commands_impl_helpers_12 as _commands_impl_helpers_12
from . import commands_impl_helpers_13 as _commands_impl_helpers_13
from . import commands_impl_helpers_14 as _commands_impl_helpers_14
from . import commands_impl_helpers_15 as _commands_impl_helpers_15
from . import commands_impl_helpers_16 as _commands_impl_helpers_16
from . import commands_impl_dispatch_local_core as _commands_impl_dispatch_local_core
from . import commands_impl_dispatch_local_proxy as _commands_impl_dispatch_local_proxy
from . import commands_impl_dispatch_records as _commands_impl_dispatch_records
from . import commands_impl_dispatch_admin as _commands_impl_dispatch_admin
from . import commands_impl_dispatch_cloud as _commands_impl_dispatch_cloud
from . import commands_impl_hook_copilot as _commands_impl_hook_copilot
from . import commands_impl_hook_claude as _commands_impl_hook_claude
from . import commands_impl_hook_runtime_state as _commands_impl_hook_runtime_state
from . import commands_impl_hook_runtime_eval as _commands_impl_hook_runtime_eval
from . import commands_impl_hook_runtime_review as _commands_impl_hook_runtime_review
from . import commands_impl_hook_runtime_finish as _commands_impl_hook_runtime_finish
from . import commands_impl_hook_generic as _commands_impl_hook_generic
from . import commands_impl_hook as _commands_impl_hook
from . import commands_impl_entry as _commands_impl_entry

_SOURCE_MODULES: tuple[ModuleType, ...] = (
    __commands_shared,
    _commands_parser_helpers,
    _commands_impl_helpers_01,
    _commands_impl_helpers_02,
    _commands_impl_helpers_03,
    _commands_impl_helpers_04,
    _commands_impl_helpers_05,
    _commands_impl_helpers_06,
    _commands_impl_helpers_07,
    _commands_impl_helpers_08,
    _commands_impl_helpers_09,
    _commands_impl_helpers_10,
    _commands_impl_helpers_11,
    _commands_impl_helpers_12,
    _commands_impl_helpers_13,
    _commands_impl_helpers_14,
    _commands_impl_helpers_15,
    _commands_impl_helpers_16,
    _commands_impl_dispatch_local_core,
    _commands_impl_dispatch_local_proxy,
    _commands_impl_dispatch_records,
    _commands_impl_dispatch_admin,
    _commands_impl_dispatch_cloud,
    _commands_impl_hook_copilot,
    _commands_impl_hook_claude,
    _commands_impl_hook_runtime_state,
    _commands_impl_hook_runtime_eval,
    _commands_impl_hook_runtime_review,
    _commands_impl_hook_runtime_finish,
    _commands_impl_hook_generic,
    _commands_impl_hook,
    _commands_impl_entry,
)


def _module_exports(module: ModuleType) -> dict[str, object]:
    exported = getattr(module, "__all__", None)
    if isinstance(exported, list):
        return {name: getattr(module, name) for name in exported}
    return {name: value for name, value in vars(module).items() if not name.startswith("__")}


def _sync_namespace(overrides: Mapping[str, object] | None = None) -> None:
    export_map: dict[str, object] = {}
    for module in _SOURCE_MODULES:
        export_map.update(_module_exports(module))
    if overrides is not None:
        export_map.update(overrides)
    globals().update(export_map)
    for module in _SOURCE_MODULES:
        vars(module).update(export_map)


def _apply_overrides(overrides: Mapping[str, object]) -> None:
    _sync_namespace(overrides)


_sync_namespace()

__all__ = [name for name in globals() if not name.startswith("__")]
