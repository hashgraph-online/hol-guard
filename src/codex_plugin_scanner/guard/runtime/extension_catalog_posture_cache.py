"""Reuse one prepared catalog view across connected syncs.

Preparing the installed catalog view costs one resident call per extension.
The daemon advertises catalog posture on every cloud sync, so it keeps the last
prepared view for a Guard home and rebuilds it only when the enforcement
catalog, the Guard version or the discovery handle changes, when the resident
no longer holds the view, or when the entry ages out.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .extension_catalog_pages import PreparedCatalogView

if TYPE_CHECKING:
    from .extension_catalog_sync import ExtensionCatalogWire

_MAX_AGE_SECONDS = 600.0

_lock = threading.Lock()
_entries: dict[str, _Entry] = {}


@dataclass(frozen=True)
class _Entry:
    enforcement_digest: str
    guard_version: str
    view: PreparedCatalogView
    catalog: ExtensionCatalogWire | None
    stored_at: float


def reusable(
    guard_home: Path, *, enforcement_digest: str, guard_version: str
) -> tuple[PreparedCatalogView, ExtensionCatalogWire | None] | None:
    """The cached view and legacy catalog, or None when they must be rebuilt."""

    key = str(guard_home.absolute())
    with _lock:
        entry = _entries.get(key)
    if entry is None:
        return None
    if (
        entry.enforcement_digest != enforcement_digest
        or entry.guard_version != guard_version
        or time.monotonic() - entry.stored_at > _MAX_AGE_SECONDS
    ):
        forget(guard_home)
        return None
    from ..catalog_delivery import discovery

    try:
        handle = discovery.installed_discovery(guard_home)
        if (handle.root, handle.authority) != (entry.view.discovery_root, entry.view.discovery_authority):
            forget(guard_home)
            return None
        discovery.require_handle(handle, guard_home)
        # A view the resident evicted cannot back a later upload request.
        with entry.view.pinned():
            pass
    except (OSError, RuntimeError, TypeError, ValueError):
        forget(guard_home)
        return None
    return entry.view, entry.catalog


def remember(
    guard_home: Path,
    *,
    enforcement_digest: str,
    guard_version: str,
    view: object,
    catalog: ExtensionCatalogWire | None,
) -> None:
    if not isinstance(view, PreparedCatalogView):
        return
    entry = _Entry(enforcement_digest, guard_version, view, catalog, time.monotonic())
    with _lock:
        _entries[str(guard_home.absolute())] = entry


def forget(guard_home: Path) -> None:
    with _lock:
        _entries.pop(str(guard_home.absolute()), None)
