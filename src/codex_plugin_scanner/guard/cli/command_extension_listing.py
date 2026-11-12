"""Command extension listings that cover everything Guard delivers.

The wheel packages only the core command catalog. Every other merged
extension reaches a device through the daemon's delivery stream, so a
listing that reads the packaged catalog alone reports a community
contribution as unknown long after it has shipped. These helpers read the
delivered catalog through the same daemon route ``command controls list``
and ``command controls show`` already use, and fall back to the packaged
catalog when no daemon is answering.

``command extensions`` stays an inspection: it never starts a daemon, never
writes the Guard home it reports on, and a device with no running daemon
still gets the packaged catalog instead of an error. Reaching a daemon that
is already running shares the endpoint discovery ``command controls`` uses,
and that discovery may refresh the runtime fingerprint cache under the
invoking user's own home while it decides whether the live daemon matches
this runtime. That cache is Guard's private runtime bookkeeping, not state
for the inspected home, and the command adds nothing to it. This module is
CLI transport and presentation; the daemon's native read model owns the
catalog and nothing here re-derives an extension.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeVar

from ..native_daemon_client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTransportError,
    GuardSurfaceDaemonClient,
)
from ..runtime.command_extensions import COMMAND_EXTENSION_SCHEMA_VERSION
from ..runtime.command_inspection import command_extensions_payload
from .extension_catalog_reads import catalog_list, catalog_show

DELIVERED_SOURCE = "delivered"
# A ``ValueError`` is the daemon's own answer that it has no such extension.
# Carried through from the delivered catalog so a reader can pin the exact
# snapshot an entry came from, as ``command controls list`` reports it.
_PASSTHROUGH_KEYS = ("native_catalog_digest", "snapshot_id")
_UNKNOWN = "Unknown command safety extension: {extension_id}"
_UNREACHABLE = (
    "Unknown command safety extension: {extension_id}. Guard searched only the packaged core catalog because no "
    "running daemon could serve the delivered one; start Guard and try again."
)

_Result = TypeVar("_Result")


def _catalog_is_unavailable(error: Exception) -> bool:
    """Say whether nothing served the delivered catalog, rather than served it badly.

    Resolving an endpoint, verifying it against the native runtime and opening
    the socket each fail as an ``OSError`` or a ``RuntimeError`` subclass --
    ``NativeDaemonLifecycleError`` and the "not running" request error among
    them -- and none of those means an extension is absent, so the listing
    degrades to the packaged catalog. A daemon that did answer reports through
    a request error carrying its status or code, and a schema, server or
    traversal-integrity failure is a real fault: it propagates so the reader
    sees it instead of a quietly shortened catalog.
    """

    if isinstance(error, OSError | GuardDaemonTransportError):
        return True
    if isinstance(error, GuardDaemonRequestError):
        return error.status is None and error.code is None and not isinstance(error, GuardDaemonResponseSchemaError)
    return isinstance(error, RuntimeError)


def _read_delivered(guard_home: Path, read: Callable[[GuardSurfaceDaemonClient], _Result]) -> _Result:
    """Run one delivered-catalog read against an already running daemon."""

    from .extension_controls_commands import _client

    return read(_client(guard_home))


def _delivered_envelope(
    extensions: list[dict[str, object]],
    source_payload: dict[str, object],
    *,
    schema_version: object = COMMAND_EXTENSION_SCHEMA_VERSION,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "source": DELIVERED_SOURCE,
        "count": len(extensions),
        "extensions": extensions,
    }
    for key in _PASSTHROUGH_KEYS:
        value = source_payload.get(key)
        if value is not None:
            payload[key] = value
    return payload


def _delivered_extension(guard_home: Path, extension_id: str) -> dict[str, object]:
    """One delivered extension in the packaged shape, read through bounded detail."""

    try:
        extension = _read_delivered(guard_home, lambda client: catalog_show(client, extension_id))
    except ValueError as error:
        raise ValueError(_UNKNOWN.format(extension_id=extension_id)) from error
    except Exception as error:
        if not _catalog_is_unavailable(error):
            raise
        raise ValueError(_UNREACHABLE.format(extension_id=extension_id)) from error
    return _delivered_envelope([extension], {})


def _delivered_listing(guard_home: Path) -> dict[str, object]:
    """Every delivered extension as the daemon's index summary of it.

    A daemon serving the v2 index answers with what a roster shows -- identity,
    version, counts, trust class and purpose -- and leaves the rules and
    permissions to a detail read, while an older daemon answers with the full
    packaged shape. The envelope repeats whichever schema version the daemon
    declared, so a reader can tell the two apart. A reader that wants a
    packaged-shaped entry from either daemon asks for the extension by id.
    """

    listing = _read_delivered(guard_home, catalog_list)
    extensions = listing.get("extensions")
    if not isinstance(extensions, list):
        raise GuardDaemonResponseSchemaError("daemon returned an invalid catalog")
    return _delivered_envelope(
        [item for item in extensions if isinstance(item, dict)],
        listing,
        schema_version=listing.get("schema_version") or COMMAND_EXTENSION_SCHEMA_VERSION,
    )


def command_extensions_listing(guard_home: Path, extension_id: str | None = None) -> dict[str, object]:
    """Return command extension metadata, packaged core first then delivered.

    A single id resolves against the packaged catalog before the daemon, so
    the common core lookup stays offline and its payload is unchanged. A
    full listing prefers the delivered catalog, which is a superset of the
    packaged one.
    """

    if extension_id is not None:
        try:
            return command_extensions_payload(extension_id)
        except ValueError:
            return _delivered_extension(guard_home, extension_id)
    try:
        return _delivered_listing(guard_home)
    except Exception as error:
        if not _catalog_is_unavailable(error):
            raise
        return command_extensions_payload(None)


def command_extensions_title(payload: Mapping[str, object]) -> str:
    """Name the catalog a listing payload came from, packaged or delivered."""

    if str(payload.get("source") or "") == DELIVERED_SOURCE:
        return "Delivered command safety extensions"
    return "Built-in command safety extensions"
