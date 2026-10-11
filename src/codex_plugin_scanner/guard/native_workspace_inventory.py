"""Resident bridge for the ``workspace_inventory`` op.

The resident discovers the workspace manifests and lockfiles, parses their
dependencies, merges SBOM components, summarizes manifest diffs and reports
lockfile parse warnings. This module only transports one request and strictly
validates the reply. A missing, mismatched or malformed answer raises
:class:`NativeWorkspaceInventoryError`; there is no Python fallback.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .native_context import _resolve_digest_home
from .native_package_approval_hash import _transport

_INVENTORY_FEATURE = "workspace-inventory-v1"
_PAYLOAD_KEYS = frozenset(
    {"manifest_paths", "lockfile_paths", "sbom_paths", "inventory", "next_offset", "diff", "lockfile_warnings"}
)
_MAX_PAGES = 1024
_ITEM_KEYS = ("ecosystem", "namespace", "name", "direct", "range", "version")
_WARNING_KEYS = frozenset({"code", "message", "path"})
_DIFF_KEYS = frozenset({"changed_package_count", "changed_paths"})


class NativeWorkspaceInventoryError(RuntimeError):
    """No authoritative native workspace inventory was available."""


@dataclass(frozen=True)
class WorkspaceInventory:
    manifest_paths: tuple[str, ...]
    lockfile_paths: tuple[str, ...]
    sbom_paths: tuple[str, ...]
    inventory: tuple[dict[str, object], ...]
    diff: dict[str, object] | None
    lockfile_warnings: tuple[dict[str, object], ...]


def _invalid() -> NativeWorkspaceInventoryError:
    return NativeWorkspaceInventoryError("Native workspace_inventory payload invalid")


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _invalid()
    return tuple(value)


def _item(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(_ITEM_KEYS):
        raise _invalid()
    if not all(isinstance(value[key], str) for key in ("ecosystem", "name")):
        raise _invalid()
    if not isinstance(value["direct"], bool):
        raise _invalid()
    if not all(value[key] is None or isinstance(value[key], str) for key in ("namespace", "range", "version")):
        raise _invalid()
    return {key: value[key] for key in _ITEM_KEYS}


def _warning(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _WARNING_KEYS:
        raise _invalid()
    if not all(isinstance(value[key], str) for key in _WARNING_KEYS):
        raise _invalid()
    return {key: value[key] for key in ("code", "message", "path")}


def _diff(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _DIFF_KEYS:
        raise _invalid()
    count = value["changed_package_count"]
    if not isinstance(count, int) or isinstance(count, bool):
        raise _invalid()
    return {"changed_package_count": count, "changed_paths": list(_strings(value["changed_paths"]))}


def native_workspace_inventory(
    store: Any,
    workspace_dir: Path,
    *,
    sbom_paths: Sequence[str] = (),
    before_workspace_dir: Path | None = None,
    files_only: bool = False,
    include_lockfile_warnings: bool = False,
) -> WorkspaceInventory:
    """Return the resident-derived inventory of ``workspace_dir``."""

    # The resident resolves paths against its own working directory, so send
    # absolute paths rather than the caller's relative ones.
    request: dict[str, object] = {
        "workspace_dir": str(Path(workspace_dir).expanduser().absolute()),
        "sbom_paths": [str(path) for path in sbom_paths],
        "files_only": files_only,
        "include_lockfile_warnings": include_lockfile_warnings,
    }
    if before_workspace_dir is not None:
        request["before_workspace_dir"] = str(Path(before_workspace_dir).expanduser().absolute())
    guard_home = _resolve_digest_home(Path(store.guard_home) if getattr(store, "guard_home", None) else None)
    first: dict[str, Any] | None = None
    items: list[object] = []
    offset = 0
    for _ in range(_MAX_PAGES):
        payload = _transport(
            {**request, "inventory_offset": offset},
            guard_home,
            operation="workspace_inventory",
            feature=_INVENTORY_FEATURE,
            error=NativeWorkspaceInventoryError,
        )
        if set(payload) != _PAYLOAD_KEYS:
            raise _invalid()
        page = payload["inventory"]
        next_offset = payload["next_offset"]
        if not isinstance(page, list):
            raise _invalid()
        if first is None:
            first = payload
        items.extend(page)
        if next_offset is None:
            break
        if not isinstance(next_offset, int) or isinstance(next_offset, bool) or next_offset <= offset:
            raise _invalid()
        offset = next_offset
    else:
        raise _invalid()
    warnings = first["lockfile_warnings"]
    if not isinstance(warnings, list):
        raise _invalid()
    return WorkspaceInventory(
        manifest_paths=_strings(first["manifest_paths"]),
        lockfile_paths=_strings(first["lockfile_paths"]),
        sbom_paths=_strings(first["sbom_paths"]),
        inventory=tuple(_item(item) for item in items),
        diff=_diff(first["diff"]),
        lockfile_warnings=tuple(_warning(item) for item in warnings),
    )
