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

import sys
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from .generated_command_catalog import GeneratedCommandCatalog

_KIND: Final = "catalog_provenance"


def _frozen() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))


def _attribution(resource_path: str) -> tuple[str, str | None]:
    """The install kind and resource root digest the runtime derives from the path.

    A runtime that cannot answer leaves the install unattributed rather than
    guessed, and the migration it describes is still recorded.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(_KIND, {"resource_path": resource_path, "frozen": _frozen()})
    except NativeRunnerAuthorityError:
        return "unavailable", None
    kind, digest = answer.get("install_kind"), answer.get("resource_root_digest")
    if not isinstance(kind, str) or not isinstance(digest, str):
        return "unavailable", None
    return kind, digest


def is_downgrade(writer_version: str, previous_version: str) -> bool:
    """Whether ``writer_version`` is an older release than ``previous_version``.

    The runtime compares the leading numeric components only, so an alpha of
    the same release is not a downgrade. One it cannot answer records none.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            _KIND, {"writer_version": writer_version, "previous_version": previous_version}
        )
    except NativeRunnerAuthorityError:
        return False
    return answer.get("downgrade") is True


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
    provenance["install_kind"], provenance["resource_root_digest"] = _attribution(resource_path)
    return provenance


__all__ = ["catalog_provenance", "is_downgrade"]
