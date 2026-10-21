"""Classify and record the failures behind ``pack_preparation_unavailable``.

Pack preparation reaches local storage, the activation authority and, for a
publication the installed bundle cannot authenticate, the release transport.
Both call sites used to collapse every ``ValueError``/``OSError`` from that
work into one bare code with nothing written to the daemon log, so an operator
who hit it saw a protocol token and had nothing to act on and no record to
read. Keep the public code stable, attach the classified cause and its
recovery action, and record the real failure in the daemon's own log.

Neither call site holds a daemon handle, so the record goes through the
module-level background sink the daemon installs. That sink takes one bounded,
path-free line, which is also why nothing here quotes an exception message
back to the caller.
"""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error
from collections.abc import Iterator

from .background_diagnostics import failure_detail, record_background_event
from .extension_control_errors import ExtensionControlApiError

_LOGGER = logging.getLogger(__name__)

PACK_PREPARATION_UNAVAILABLE = "pack_preparation_unavailable"

# The authority wording raised by preparation when no publication can be
# authenticated locally. Matched on the message because the runtime raises a
# plain ValueError for each of them. This is the pack-lifecycle publication
# authority, never the control authority both call sites have already found
# protected, so it must not be reported as one the operator can recover.
_PACK_AUTHORITY_MARKERS = (
    "authority is unavailable",
    "pack_lifecycle_pack_authority_unavailable",
    "requires an existing activation",
)

# Guard's storage layer raises a bare ``TimeoutError`` with this wording when a
# query passes its deadline. ``socket.timeout`` is ``TimeoutError`` on every
# supported Python, so the type alone cannot tell a slow database from an
# unreachable network.
_STORAGE_DEADLINE = "Guard storage operation deadline expired."

# The packaged compiler raises one exception type for a bundle it cannot verify
# and for a process that would not start or did not answer. Only the first is a
# broken install; the rest are transient and must not ask for a reinstall.
_COMPILER_EXECUTION_MARKERS = (
    "could not be started",
    "timed out",
)


def _causes(exc: BaseException) -> Iterator[BaseException]:
    """Walk the chained exceptions, because preparation rewraps what it caught.

    Follow the explicit cause first and the implicit context only where Python
    would show it. A context that ``raise ... from`` suppressed is a failure the
    code already handled, such as a retried network error.
    """

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__suppress_context__:
            current = None
        else:
            current = current.__context__


def _named_cause(exc: BaseException) -> str | None:
    from ..catalog_delivery.authority import ExpiredDistributionError
    from ..catalog_delivery.preparation import UnavailablePackError
    from ..catalog_delivery.revocations import RevokedPackError
    from ..catalog_delivery.transport import MissingReleaseError
    from ..extension_builder.native_source_compiler import NativeSourceCompilerError

    for error in _causes(exc):
        if isinstance(error, RevokedPackError):
            return "pack_revoked"
        if isinstance(error, (MissingReleaseError, ExpiredDistributionError, UnavailablePackError)):
            return "release_unavailable"
        if isinstance(error, NativeSourceCompilerError):
            if any(marker in str(error) for marker in _COMPILER_EXECUTION_MARKERS):
                return "installed_runtime_unresponsive"
            # An install whose packaged compiler or its manifest is missing or
            # fails verification cannot read its own bundle metadata. That is a
            # broken install, not a transient failure, so never tell the
            # operator to simply try again.
            return "installed_runtime_incomplete"
    return None


_UNREACHABLE = (urllib.error.URLError, socket.gaierror, ssl.SSLError, ConnectionError, TimeoutError)


def classify(exc: BaseException) -> str:
    """Name the step that failed without quoting any part of the message."""

    if any(type(error) is TimeoutError and _STORAGE_DEADLINE in str(error) for error in _causes(exc)):
        return "local_storage"
    # A typed failure outranks any network error left in its context: a
    # transport that retried past a dropped connection and then found the
    # release missing or revoked must not report the pack as offline.
    named = _named_cause(exc)
    if named is not None:
        return named
    for error in _causes(exc):
        if isinstance(error, urllib.error.HTTPError):
            return "release_unavailable"
        if isinstance(error, _UNREACHABLE):
            return "offline"
    if isinstance(exc, ValueError):
        if any(marker in str(exc) for marker in _PACK_AUTHORITY_MARKERS):
            return "pack_authority_unavailable"
        return "internal"
    if isinstance(exc, OSError):
        return "local_storage"
    return "internal"


def preparation_unavailable(exc: BaseException, *, stage: str) -> ExtensionControlApiError:
    """Record the real failure and return the classified 503 for the caller."""

    cause = classify(exc)
    detail = f"stage={stage} cause={cause} {failure_detail(exc)}"
    record_background_event("extension_control_preparation_failed", detail)
    # The daemon discards standard error, so this reaches a foreground process
    # and a test run; daemon.log is served by the record above.
    _LOGGER.error("Extension-control pack preparation failed: %s", detail, exc_info=exc)
    return ExtensionControlApiError(503, PACK_PREPARATION_UNAVAILABLE, cause=cause)
