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
from .runtime.package_intent_common import PackageIntentTarget

_INVENTORY_FEATURE = "workspace-inventory-v1"
_PAYLOAD_KEYS = frozenset(
    {
        "manifest_paths",
        "lockfile_paths",
        "sbom_paths",
        "inventory",
        "diff",
        "lockfile_warnings",
        "scan_targets",
        "package_target",
    }
)
_TARGET_OPTIONAL_STRINGS = (
    "package_name",
    "requested_specifier",
    "source_url",
    "source_kind",
    "source_repository",
    "source_revision_kind",
    "source_identity",
    "source_invalid_reason",
    "alias",
    "dependency_group",
)
_TARGET_KEYS = frozenset({"ecosystem", "raw_spec", "extras", "editable", *_TARGET_OPTIONAL_STRINGS})
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
    scan_targets: tuple[PackageIntentTarget, ...]
    package_target: PackageIntentTarget | None


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


def _target(value: object) -> PackageIntentTarget:
    if not isinstance(value, dict) or set(value) != _TARGET_KEYS:
        raise _invalid()
    extras = value["extras"]
    if not isinstance(value["ecosystem"], str) or not isinstance(value["raw_spec"], str):
        raise _invalid()
    if not isinstance(value["editable"], bool) or not isinstance(extras, list):
        raise _invalid()
    if not all(isinstance(extra, str) for extra in extras):
        raise _invalid()
    if not all(value[key] is None or isinstance(value[key], str) for key in _TARGET_OPTIONAL_STRINGS):
        raise _invalid()
    return PackageIntentTarget(
        ecosystem=value["ecosystem"],
        raw_spec=value["raw_spec"],
        extras=tuple(extras),
        editable=value["editable"],
        **{key: value[key] for key in _TARGET_OPTIONAL_STRINGS},
    )


def native_workspace_inventory(
    store: Any,
    workspace_dir: Path,
    *,
    sbom_paths: Sequence[str] = (),
    before_workspace_dir: Path | None = None,
    files_only: bool = False,
    include_lockfile_warnings: bool = False,
    targets_only: bool = False,
    package_spec: tuple[str, str] | None = None,
) -> WorkspaceInventory:
    """Return the resident-derived inventory of ``workspace_dir``."""

    request: dict[str, object] = {
        "workspace_dir": str(workspace_dir),
        "sbom_paths": [str(path) for path in sbom_paths],
        "files_only": files_only,
        "include_lockfile_warnings": include_lockfile_warnings,
        "targets_only": targets_only,
    }
    if package_spec is not None:
        request["package_spec"] = {"ecosystem": package_spec[0], "spec": package_spec[1]}
    if before_workspace_dir is not None:
        request["before_workspace_dir"] = str(before_workspace_dir)
    guard_home = _resolve_digest_home(Path(store.guard_home) if getattr(store, "guard_home", None) else None)
    payload = _transport(
        request,
        guard_home,
        operation="workspace_inventory",
        feature=_INVENTORY_FEATURE,
        error=NativeWorkspaceInventoryError,
    )
    if set(payload) != _PAYLOAD_KEYS:
        raise _invalid()
    inventory = payload["inventory"]
    warnings = payload["lockfile_warnings"]
    targets = payload["scan_targets"]
    if not isinstance(inventory, list) or not isinstance(warnings, list) or not isinstance(targets, list):
        raise _invalid()
    if (package_spec is None) != (payload["package_target"] is None) or (targets_only and inventory):
        raise _invalid()
    if targets and not targets_only:
        raise _invalid()
    return WorkspaceInventory(
        manifest_paths=_strings(payload["manifest_paths"]),
        lockfile_paths=_strings(payload["lockfile_paths"]),
        sbom_paths=_strings(payload["sbom_paths"]),
        inventory=tuple(_item(item) for item in inventory),
        diff=_diff(payload["diff"]),
        lockfile_warnings=tuple(_warning(item) for item in warnings),
        scan_targets=tuple(_target(item) for item in targets),
        package_target=None if package_spec is None else _target(payload["package_target"]),
    )
