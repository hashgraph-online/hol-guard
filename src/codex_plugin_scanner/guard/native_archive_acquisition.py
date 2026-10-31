"""Mechanical transport for native archive acquisition and source identity.

Rust owns every request-time network and blob control. Python supplies the
existing managed trust service's roots and hydrates the bound native DTO.
Unavailable, malformed, late or unbound replies fail closed.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .runtime.restricted_archive_contract import (
    RestrictedArchiveDownload,
    RestrictedArchiveDownloadResult,
    RestrictedArchiveFailure,
)
from .strict_json_pairs import unique_json_object

_FEATURE = "archive-acquisition-v1"
_CONTENT_FEATURE = "managed-content-fetch-v1"
# The contained decoder's raw input ceiling; a larger body is never fetched.
MANAGED_CONTENT_MAX_RAW_BYTES = 3 * 1024 * 1024
_MAX_CONTENT_ENCODING_VALUES = 8
_REQUEST_SCHEMA = "hol-guard.archive-acquisition-request.v1"
_RESULT_SCHEMA = "hol-guard.archive-acquisition-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_TIMEOUT_MS = 8_000


def _request(
    query: dict[str, object],
    *,
    deadline: float,
    guard_home: Path | None = None,
    feature: str = _FEATURE,
) -> dict[str, Any] | None:
    try:
        deadline = min(deadline, time.monotonic() + _MAX_TIMEOUT_MS / 1000)
        home = _resolve_digest_home(guard_home)
        status = native_runtime_status(deadline_monotonic=deadline)
        if (
            not status.available
            or not status.compatible
            or status.identity is None
            or status.capabilities is None
            or _FEATURE not in status.capabilities.features
            or feature not in status.capabilities.features
            or "resident-protocol-v2" not in status.capabilities.features
        ):
            return None
        if not ensure_resident_prerequisite(home):
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        timeout_ms = max(1, int(remaining * 1000))
        if query["action"] in {"download", "content"}:
            timeout_ms = min(timeout_ms, cast(int, query["timeout_ms"]))
        query = {
            **query,
            "timeout_ms": timeout_ms,
            "expires_at_unix_ms": int((time.time() + remaining) * 1000),
        }
        request = {"schema": _REQUEST_SCHEMA, "request_id": uuid.uuid4().hex, "guard_home": str(home), "query": query}
        digest = "sha256:" + _canonical_request_sha256(request)
        encoded = json.dumps(
            {
                "operation": "archive_acquisition",
                "request": request,
                "deadline_budget_ms": max(1, int(remaining * 1000)),
            },
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            return None
        reply = native_resident_client_request(
            executable=status.identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=encoded,
            timeout_seconds=remaining,
            deadline_monotonic=deadline,
        )
        if reply is None or time.monotonic() >= deadline:
            return None
        result = json.loads(reply.decode("utf-8"), object_pairs_hook=unique_json_object)
        if (
            not isinstance(result, dict)
            or set(result) != {"schema", "request_id", "request_sha256", "status", "code", "payload"}
            or result["schema"] != _RESULT_SCHEMA
            or result["request_id"] != request["request_id"]
            or result["request_sha256"] != digest
            or result["status"] != "ok"
            or result["code"] != "ok"
            or not isinstance(result["payload"], dict)
        ):
            return None
        return result["payload"]
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeError):
        return None


def _query(source_url: str, action: str) -> dict[str, object]:
    return {
        "action": action,
        "source_url": source_url,
        "max_bytes": 6 * 1024 * 1024,
        "max_redirects": 4,
        "timeout_ms": 0,
        "expires_at_unix_ms": 0,
        "temp_dir": None,
        "trust_roots_der_hex": [],
        "allow_public_registries": True,
    }


def _destination(source_url: str) -> dict[str, Any] | None:
    payload = _request(_query(source_url, "destination"), deadline=time.monotonic() + 3.0)
    if (
        payload is None
        or set(payload) != {"kind", "canonical_url", "is_external"}
        or payload["kind"] != "destination"
        or not isinstance(payload["canonical_url"], (str, type(None)))
        or not isinstance(payload["is_external"], bool)
    ):
        return None
    return payload


def is_external_https_archive_source(source_url: str) -> bool:
    payload = _destination(source_url)
    # Unknown native identity must enter the guarded route, where unavailable
    # authority refuses acquisition. It cannot fall through to ordinary npm.
    return payload["is_external"] if payload is not None else True


def canonical_external_https_archive_source(source_url: str) -> str | None:
    payload = _destination(source_url)
    return payload["canonical_url"] if payload is not None else None


def _spooled_fetch(
    source_url: str,
    *,
    action: str,
    max_bytes: int,
    max_redirects: int,
    timeout_seconds: float,
    temp_dir: Path | None,
    feature: str,
) -> tuple[dict[str, Any] | None, tempfile.TemporaryDirectory[str]]:
    from .mdm.network_transport import managed_ssl_context, resolved_network_policy
    from .mdm.network_trust import export_managed_trust_roots

    # Invalid limits still reach native validation with a usable RPC budget.
    deadline = time.monotonic() + (timeout_seconds if timeout_seconds > 0 else 3.0)
    policy, _managed = resolved_network_policy(None)
    # Trust selection stays in the existing platform/managed service.
    # The native TLS implementation verifies the chain and hostname.
    roots = export_managed_trust_roots(managed_ssl_context(policy))
    # This is transport lifetime management, not a blob verdict. Removing
    # the parent on failure prevents a late resident from publishing a file.
    spool = tempfile.TemporaryDirectory(prefix="hol-guard-acquisition-", dir=temp_dir, ignore_cleanup_errors=True)
    try:
        query = {
            **_query(source_url, action),
            "max_bytes": max_bytes,
            "max_redirects": max_redirects,
            "timeout_ms": int(timeout_seconds * 1000),
            "temp_dir": str(Path(spool.name).resolve()),
            "trust_roots_der_hex": [root.hex() for root in roots],
            "allow_public_registries": policy.allow_public_registries,
        }
        return _request(query, deadline=deadline, feature=feature), spool
    except BaseException:
        with suppress(OSError):
            spool.cleanup()
        raise


def _native_failure(payload: dict[str, Any]) -> RestrictedArchiveFailure | None:
    if set(payload) != {"kind", "code", "message"} or not all(
        isinstance(payload[key], str) for key in ("code", "message")
    ):
        return None
    return RestrictedArchiveFailure(payload["code"], payload["message"])


def _valid_blob(
    payload: dict[str, Any], *, kind: str, extra: frozenset[str], source_url: str, max_bytes: int, spool: str
) -> bool:
    return (
        set(payload) == {"kind", "path", "sha256", "size", "source_url", "final_url"} | extra
        and payload["kind"] == kind
        and all(isinstance(payload[key], str) for key in ("path", "sha256", "source_url", "final_url"))
        and not isinstance(payload["size"], bool)
        and isinstance(payload["size"], int)
        and 0 <= payload["size"] <= max_bytes
        and Path(payload["path"]).is_absolute()
        and Path(payload["path"]).parent.samefile(spool)
        and payload["source_url"] == source_url
        and len(payload["sha256"]) == 64
        and all(character in "0123456789abcdef" for character in payload["sha256"])
    )


def download_restricted_archive(
    source_url: str,
    *,
    max_bytes: int = 6 * 1024 * 1024,
    max_redirects: int = 4,
    timeout_seconds: float = 3.0,
    temp_dir: Path | None = None,
) -> RestrictedArchiveDownloadResult:
    unavailable = RestrictedArchiveFailure(
        "native_archive_acquisition_unavailable", "Native archive acquisition is unavailable."
    )
    spool: tempfile.TemporaryDirectory[str] | None = None
    try:
        payload, spool = _spooled_fetch(
            source_url,
            action="download",
            max_bytes=max_bytes,
            max_redirects=max_redirects,
            timeout_seconds=timeout_seconds,
            temp_dir=temp_dir,
            feature=_FEATURE,
        )
        if payload is None:
            return unavailable
        if payload.get("kind") == "failure":
            return _native_failure(payload) or unavailable
        if not _valid_blob(
            payload, kind="download", extra=frozenset(), source_url=source_url, max_bytes=max_bytes, spool=spool.name
        ):
            return unavailable
        download = RestrictedArchiveDownload(
            path=Path(payload["path"]),
            sha256=payload["sha256"],
            size=payload["size"],
            source_url=payload["source_url"],
            final_url=payload["final_url"],
            _temporary_directory=spool,
        )
        spool = None
        return download
    except (OSError, RuntimeError, TypeError, ValueError):
        return unavailable
    finally:
        if spool is not None:
            with suppress(OSError):
                spool.cleanup()


@dataclass(frozen=True, slots=True)
class ManagedRawContent:
    """A raw response body exactly as the server sent it, still encoded.

    Every ``Content-Encoding`` value was vetted on every hop before the body
    was read; the body itself has not been decoded and is untrusted.
    """

    body: bytes
    content_encoding: tuple[str, ...]
    sha256: str
    source_url: str
    final_url: str


def fetch_managed_content_raw(
    source_url: str,
    *,
    max_bytes: int = MANAGED_CONTENT_MAX_RAW_BYTES,
    max_redirects: int = 4,
    timeout_seconds: float = 3.0,
) -> ManagedRawContent | RestrictedArchiveFailure:
    """Fetch one public HTTPS body without letting any HTTP stack decode it.

    The resident carries no credentials: only the managed trust roots and the
    URL. A coding the decoder would refuse stops the fetch on the hop that
    declared it, before that body is read.
    """

    unavailable = RestrictedArchiveFailure(
        "native_content_fetch_unavailable", "Native managed content fetch is unavailable."
    )
    spool: tempfile.TemporaryDirectory[str] | None = None
    try:
        payload, spool = _spooled_fetch(
            source_url,
            action="content",
            max_bytes=max_bytes,
            max_redirects=max_redirects,
            timeout_seconds=timeout_seconds,
            temp_dir=None,
            feature=_CONTENT_FEATURE,
        )
        if payload is None:
            return unavailable
        if payload.get("kind") == "failure":
            return _native_failure(payload) or unavailable
        codings = payload.get("content_encoding")
        if (
            not _valid_blob(
                payload,
                kind="content",
                extra=frozenset({"content_encoding"}),
                source_url=source_url,
                max_bytes=max_bytes,
                spool=spool.name,
            )
            or not isinstance(codings, list)
            or len(codings) > _MAX_CONTENT_ENCODING_VALUES
            or not all(isinstance(value, str) for value in codings)
        ):
            return unavailable
        with Path(payload["path"]).open("rb") as handle:
            body = handle.read(max_bytes + 1)
        if len(body) != payload["size"] or hashlib.sha256(body).hexdigest() != payload["sha256"]:
            return unavailable
        return ManagedRawContent(
            body=body,
            content_encoding=tuple(codings),
            sha256=payload["sha256"],
            source_url=payload["source_url"],
            final_url=payload["final_url"],
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return unavailable
    finally:
        if spool is not None:
            with suppress(OSError):
                spool.cleanup()
