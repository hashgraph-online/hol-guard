"""Native lifecycle wire adapter. No policy fallback or authority by cache hash."""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, cast

from ..extension_builder import native_source_compiler as transport

_EXECUTABLE: ContextVar[Path | None] = ContextVar("verified_pack_lifecycle_executable", default=None)


@contextmanager
def session():
    """Reuse one verified executable for an explicit bounded control operation."""
    if _EXECUTABLE.get() is not None:
        yield
        return
    try:
        manifest = transport._verify_manifest(transport._NATIVE_PACKAGE / transport._MANIFEST_NAME)
        raw = transport._verify_compiler(transport._NATIVE_PACKAGE / transport._COMPILER_NAME, manifest)
        with transport._verified_executable(raw) as executable:
            token = _EXECUTABLE.set(executable)
            try:
                yield
            finally:
                _EXECUTABLE.reset(token)
    except transport.NativeSourceCompilerError as exc:
        raise ValueError(f"native_pack_lifecycle_unavailable: {exc}") from exc


def invoke(kind, **fields) -> dict[str, Any]:
    return _invoke(kind, fields, 60)


def _invoke(kind, fields, deadline) -> dict[str, Any]:
    try:
        request = json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":")).encode()
        with session():
            executable = _EXECUTABLE.get()
            code, stdout, stderr = transport._run_bounded(
                [str(executable), "pack-lifecycle", "--stdin"], request, timeout=deadline
            )
        # Rust validates each operation's record; this adapter transports heterogeneous JSON values.
        return cast(dict[str, Any], transport._decode_output(stdout, returncode=code, stderr=stderr))
    except transport.NativeSourceCompilerError as exc:
        raise ValueError(f"native_pack_lifecycle_unavailable: {exc}") from exc


@contextmanager
def verified_preparation():
    """Pin verified bytes for all requests; never accept an executable from callers."""
    with session():

        def invoke_pinned(kind="preparation", **fields):
            return invoke(kind, **fields)

        yield invoke_pinned


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
