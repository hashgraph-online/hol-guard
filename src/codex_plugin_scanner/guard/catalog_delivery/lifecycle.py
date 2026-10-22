"""Native lifecycle wire adapter. No policy fallback or authority by cache hash."""

from __future__ import annotations

import json
import os
import threading
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Any, cast

from ..extension_builder import native_executable_root
from ..extension_builder import native_source_compiler as transport


class NativePackLifecycleUnavailableError(ValueError):
    """The runtime could not answer: missing, unverifiable, timed out or crashed.

    This is the transport saying nothing, not the runtime refusing a record. A
    caller that resets state on a damaged record must let this one propagate, so
    an outage cannot be read as damage. It stays a `ValueError` because that is
    what every existing caller handles.
    """


class _Session:
    """Verifies and copies the executable on first use, then reuses that copy."""

    def __init__(self, stack: ExitStack):
        self._stack = stack
        self._lock = threading.Lock()
        self._executable: Path | None = None

    def executable(self) -> Path:
        with self._lock:
            if self._executable is None:
                self._executable = self._stack.enter_context(_verified_runtime())
            return self._executable


# What the last full verification admitted: the identities of the packaged
# files it read, and the size and SHA-256 of the runtime they hold.
_verified: tuple[tuple[tuple[int, ...], ...], int, str] | None = None


def _packaged_identity() -> tuple[tuple[int, ...], ...] | None:
    package = transport._NATIVE_PACKAGE
    files = (
        package / transport._MANIFEST_NAME,
        package / transport._COMPILER_NAME,
        package / "runtime-manifest.json",
        transport._PACKAGED_PROGRAM,
    )
    try:
        return tuple(
            (status.st_mode, status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)
            for status in (os.lstat(path) for path in files)
        )
    except OSError:
        return None


@contextmanager
def _verified_runtime():
    """Yield a private copy of the packaged runtime holding exactly verified bytes.

    A full verification reads, checks and hashes four packaged files, which
    takes about a second on a slow host. While none of them has been replaced
    or modified since the last one, the kept copy is hashed against the digest
    that verification admitted instead. Only verified bytes run either way: a
    changed file, or a copy that differs, falls back to a full verification.
    """
    global _verified
    identity = _packaged_identity()
    known = _verified
    if identity is not None and known is not None and known[0] == identity:
        with native_executable_root.reused_executable(known[1], known[2]) as kept:
            if kept is not None:
                yield kept
                return
    manifest = transport._verify_manifest(transport._NATIVE_PACKAGE / transport._MANIFEST_NAME)
    raw = transport._verify_compiler(transport._NATIVE_PACKAGE / transport._COMPILER_NAME, manifest)
    digest = manifest.get("compiler_sha256")
    if identity is not None and isinstance(digest, str) and identity == _packaged_identity():
        _verified = (identity, len(raw), digest)
    with transport._verified_executable(raw) as executable:
        yield executable


_SESSION: ContextVar[_Session | None] = ContextVar("verified_pack_lifecycle_session", default=None)


@contextmanager
def session():
    """Reuse one verified executable for an explicit bounded control operation.

    Verification is deferred to the first native request, so a session that
    needs no native answer costs nothing.
    """
    if _SESSION.get() is not None:
        yield
        return
    try:
        with ExitStack() as stack:
            token = _SESSION.set(_Session(stack))
            try:
                yield
            finally:
                _SESSION.reset(token)
    except transport.NativeSourceCompilerError as exc:
        raise NativePackLifecycleUnavailableError(f"native_pack_lifecycle_unavailable: {exc}") from exc


def one_runtime(function):
    """Verify and materialize the runtime once per operation, not once per record.

    A `record` call outside a session re-reads, hashes and copies the packaged
    executable before spawning it. An operation that authenticates several
    records -- a store read, a projection capture, a reservation inside an open
    write transaction -- pays that once with this.
    """

    @wraps(function)
    def operation(*args, **kwargs):
        with session():
            return function(*args, **kwargs)

    return operation


@contextmanager
def pinned_session(executable: Path):
    """Answer native requests with a runtime a build job compiled from this checkout.

    A source checkout carries no packaged runtime to verify, so the caller
    names the one it built. Nested sessions reuse it as they would a verified one.
    """
    with ExitStack() as stack:
        pinned = _Session(stack)
        pinned._executable = executable
        token = _SESSION.set(pinned)
        try:
            yield
        finally:
            _SESSION.reset(token)


def runtime_fingerprint() -> tuple[tuple[int, ...], ...]:
    """Cheap identity of the installed runtime files.

    It changes when either file is replaced or modified and raises when one is
    missing. It never vouches for the bytes: a native request still verifies them.
    """
    files = (transport._NATIVE_PACKAGE / transport._MANIFEST_NAME, transport._NATIVE_PACKAGE / transport._COMPILER_NAME)
    return tuple(
        (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)
        for status in (os.stat(path) for path in files)
    )


def invoke(kind, **fields) -> dict[str, Any]:
    return _invoke(kind, fields, 60)


def _invoke(kind, fields, deadline) -> dict[str, Any]:
    try:
        request = json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":")).encode()
        with session():
            executable = cast(_Session, _SESSION.get()).executable()
            # This subcommand is read by the runtime's own bounded stdin
            # reader, whose frame is smaller than the compiler front end's, so
            # the request is held to the smaller of the two here.
            code, stdout, stderr = transport._run_bounded(
                [str(executable), "pack-lifecycle", "--stdin"],
                request,
                timeout=deadline,
                limit=transport._MAX_NATIVE_REQUEST_BYTES,
            )
        # Rust validates each operation's record; this adapter transports heterogeneous JSON values.
        return cast(dict[str, Any], transport._decode_output(stdout, returncode=code, stderr=stderr))
    except transport.NativeSourceCompilerError as exc:
        raise NativePackLifecycleUnavailableError(f"native_pack_lifecycle_unavailable: {exc}") from exc


@contextmanager
def verified_preparation():
    """Pin verified bytes for all requests; never accept an executable from callers."""
    with session():

        def invoke_pinned(kind="preparation", **fields):
            return invoke(kind, **fields)

        yield invoke_pinned


def record(operation, purpose, *, key: bytes, **fields) -> dict[str, Any]:
    """Seal or verify one authenticated command-pack record in the runtime.

    A record that does not authenticate is reported as tampered; one that
    authenticates outside its schema is refused by name. Both arrive as answers:
    a tampered record raises `ExtensionControlAuthorityError`, a refused one
    raises `ValueError` with the reason, and only a runtime that could not
    answer raises `NativePackLifecycleUnavailableError`.
    """
    from ..runtime.extension_control_authority import ExtensionControlAuthorityError

    try:
        result = invoke("record", operation=operation, purpose=purpose, key=key.hex(), **fields)
    except (TypeError, OverflowError) as error:
        # A record the request cannot carry is refused by name here, the way the
        # runtime refuses one it can read but will not accept.
        raise ValueError("pack_lifecycle_record_payload_invalid") from error
    fault = result.get("fault")
    if fault == "tampered":
        raise ExtensionControlAuthorityError(str(result.get("reason")))
    if fault is not None:
        raise ValueError(str(result.get("reason")))
    return result


def transfer(**fields):
    # Rust bounds each copied file; the longer deadline covers a full catalog copy.
    return _invoke("offline", fields, 900)


def identity(prepared):
    return {
        "profile": prepared.authority_profile,
        "source": prepared.source_sha,
        "engine": prepared.engine,
        "root": prepared.root_digest,
        "version": prepared.release_version if prepared.authority_profile == "installed" else prepared.publication_id,
        "authority": prepared.authority_epoch,
        "revocation": prepared.revocation_epoch,
    }


def release_evidence(authority):
    from .preparation_authority import installed_bundle_type

    if type(authority) is not installed_bundle_type():
        raise ValueError("native lifecycle requires authenticated installed capability")
    # The existing installed factory authenticated both manifests against the
    # executable, source, engine and Root. This is fixed installed-package IO,
    # never a request-provided version or path.
    from ..extension_builder.io import read_bytes
    from .pack_store import decode

    return {
        "runtime_manifest": decode(read_bytes(transport._NATIVE_PACKAGE / "runtime-manifest.json", limit=65536)),
        "compiler_manifest": decode(read_bytes(transport._NATIVE_PACKAGE / transport._MANIFEST_NAME, limit=65536)),
        "release_data": authority.data.decode(),
    }


def installed_identity(authority):
    return invoke("installed", **release_evidence(authority))


def ancestry(floor, source):
    from .pack_store import decode
    from .transport import REPOSITORY, download

    if floor["source"] == source:
        return None
    url = f"https://api.github.com/repos/{REPOSITORY}/compare/{floor['source']}...{source}?per_page=1&page=2"
    return decode(download(url, 64 * 1024))
