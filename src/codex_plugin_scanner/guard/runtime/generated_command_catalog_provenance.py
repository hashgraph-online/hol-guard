"""Where a loaded command catalog came from, recorded so the field can tell.

A Guard store records the catalog digest it migrated to, but not which install
produced that catalog. Several Guard versions can share one store — a Desktop
bundle, a pipx install and a uv tool install all resolve ``~/.hol-guard`` — and
each one migrates the extension-control authority to its own catalog. Without
provenance the store shows a digest alternating between two values and no way
to attribute either, which is exactly how this class of defect stays open.

Nothing here records a user's name or home directory. The absolute resource
root is reduced to a digest, which distinguishes two installs without naming
either, and the install kind is derived from the path's shape.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import PurePath
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from .generated_command_catalog import GeneratedCommandCatalog

_MAX_PATH_BYTES: Final = 4_096
_ROOT_DIGEST_DOMAIN: Final = b"hol-guard.catalog-resource-root.v1\0"


def _resource_root_digest(resource_path: str) -> str:
    """A stable, non-identifying id for the directory an install loaded from."""

    root = str(PurePath(resource_path).parent).encode("utf-8", "replace")[:_MAX_PATH_BYTES]
    return hashlib.sha256(_ROOT_DIGEST_DOMAIN + root).hexdigest()


def _frozen() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))


def _install_kind(resource_path: str) -> str:
    """Classify the install from the shape of the path, never its contents."""

    normalized = resource_path.replace("\\", "/")
    if _frozen():
        # A frozen bundle is what the Desktop app ships; the marker only refines
        # which bundle produced it.
        return "desktop-bundle" if "org.hol.guard.desktop" in normalized else "frozen-bundle"
    if "/pipx/" in normalized:
        return "pipx"
    if "/uv/tools/" in normalized:
        return "uv-tool"
    if "/site-packages/" in normalized:
        return "site-packages"
    if "/src/codex_plugin_scanner/" in normalized:
        return "source-checkout"
    return "unknown"


def version_ordinal(version: str) -> tuple[int, ...]:
    """The leading numeric components of a version, for ordering only.

    ``3.47.0a2`` orders as ``(3, 47, 0)``. Pre-release suffixes are dropped
    rather than parsed: this only has to answer "is the writer older", and an
    alpha of the same release is not a downgrade worth recording.
    """

    parts: list[int] = []
    for component in version.split("."):
        digits = ""
        for character in component:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def catalog_provenance(
    *,
    catalog_digest: str,
    catalog: GeneratedCommandCatalog | None = None,
    trigger: str,
    writer: bool = False,
) -> dict[str, object]:
    """Describe the catalog being written and the process doing the writing.

    ``trigger`` names the code path asking, so a store holding two provenances
    for one revision shows which write won rather than only that one did. A
    caller without the catalog object in hand passes the digest alone; the
    process-wide catalog describes it only when the two agree, so one install's
    record is never attributed to another's resource.

    ``guard_version`` is the process that recorded this, which is not always the
    install that produced the revision: a store can be read long after another
    Guard migrated it, and the reader backfills the missing event. Only a caller
    that is itself performing the migration passes ``writer``, and only then is
    ``writer_version`` recorded. A reader stamping its own version there would
    make an old revision look like the newest install's work, and the downgrade
    check reading it back would then miss the regression it exists to catch.
    """

    from ...version import __version__
    from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from .generated_command_catalog_loader import resolved_catalog_resource

    provenance: dict[str, object] = {
        "trigger": trigger,
        "guard_version": __version__,
        "frozen": _frozen(),
        "resource_root_digest": None,
    }
    if writer:
        provenance["writer_version"] = __version__
    built_in = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    source = catalog if catalog is not None else (built_in if built_in.catalog_digest == catalog_digest else None)
    if source is None:
        # A revision this process did not write and cannot describe; recording
        # that honestly is the point of provenance.
        provenance["install_kind"] = "unattributed"
        return provenance
    provenance["extension_count"] = len(source.extensions)
    provenance["program_digest"] = source.program_digest
    provenance["source_digest"] = source.source_digest
    provenance["implementation_digest"] = source.implementation_digest
    resource_path = resolved_catalog_resource()
    # The resource root names the file this process loaded its own catalog from,
    # so only this process's own catalog may be attributed to it. A caller that
    # built a catalog in memory can hold one that hashes the same without the
    # packaged resource having anything to do with it, and recording that root
    # would name an install that never wrote the revision.
    if resource_path is None or source is not built_in:
        provenance["install_kind"] = "in-process" if resource_path else "unresolved"
        return provenance
    provenance["install_kind"] = _install_kind(resource_path)
    provenance["resource_root_digest"] = _resource_root_digest(resource_path)
    return provenance


__all__ = ["catalog_provenance", "version_ordinal"]
