"""Load pinned Windows ownership primitives without replacing installed modules.

The installed baseline remains under its normal package name. Qualification
uses a separate namespace for the collector's existing handle/ACL routines,
whose source bytes are included in the collector certificate.
"""

from __future__ import annotations

import importlib
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

_ROOT = Path(__file__).resolve().parents[2] / "src/codex_plugin_scanner"
_NAMESPACE = "_hol_guard_transition_windows_api"


@cache
def _namespace() -> str:
    for suffix, path in (("", _ROOT), (".guard", _ROOT / "guard"), (".guard.mdm", _ROOT / "guard/mdm")):
        name = _NAMESPACE + suffix
        if name in sys.modules:
            raise RuntimeError("transition_windows_api_namespace_occupied")
        package = ModuleType(name)
        package.__path__ = [str(path)]
        sys.modules[name] = package
    return _NAMESPACE


def source_module(name: str) -> Any:
    return importlib.import_module(_namespace() + "." + name)


@cache
def private_file_api() -> Any:
    namespace = _namespace()
    facade = ModuleType(namespace + ".guard.native_policy_snapshot")
    sys.modules[facade.__name__] = facade
    for suffix in ("support", "acl", "atomic", "io", "state"):
        module = source_module("guard.native_policy_snapshot_windows_" + suffix)
        for name, value in vars(module).items():
            if name.startswith("_windows_"):
                setattr(facade, name, value)
    storage = source_module("guard.native_policy_snapshot_storage_windows")
    vars(facade)["_windows_read_snapshot_bytes"] = storage._windows_read_snapshot_bytes
    return facade
