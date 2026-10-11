"""Mechanical transport for native archive acquisition and source identity.

Rust owns every request-time network and blob control. Python supplies the
existing managed trust service's roots and hydrates the bound native DTO.
Unavailable, malformed, late or unbound replies fail closed.
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from contextlib import suppress
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
_REQUEST_SCHEMA = "hol-guard.archive-acquisition-request.v1"
_RESULT_SCHEMA = "hol-guard.archive-acquisition-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_TIMEOUT_MS = 8_000


def _request(query: dict[str, object], *, deadline: float, guard_home: Path | None = None) -> dict[str, Any] | None:
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
            or "resident-protocol-v2" not in status.capabilities.features
        ):
            return None
        if not ensure_resident_prerequisite(home):
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        timeout_ms = max(1, int(remaining * 1000))
        if query["action"] == "download":
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


def download_restricted_archive(
    source_url: str,
    *,
    max_bytes: int = 6 * 1024 * 1024,
    max_redirects: int = 4,
    timeout_seconds: float = 3.0,
    temp_dir: Path | None = None,
) -> RestrictedArchiveDownloadResult:
    from .mdm.network_transport import managed_ssl_context, resolved_network_policy
    from .mdm.network_trust import export_managed_trust_roots

    unavailable = RestrictedArchiveFailure(
        "native_archive_acquisition_unavailable", "Native archive acquisition is unavailable."
    )
    spool: tempfile.TemporaryDirectory[str] | None = None
    try:
        # Invalid limits still reach native validation with a usable RPC budget.
        deadline = time.monotonic() + (timeout_seconds if timeout_seconds > 0 else 3.0)
        policy, _managed = resolved_network_policy(None)
        # Trust selection stays in the existing platform/managed service.
        # The native TLS implementation verifies the chain and hostname.
        roots = export_managed_trust_roots(managed_ssl_context(policy))
        # This is transport lifetime management, not a blob verdict. Removing
        # the parent on failure prevents a late resident from publishing a file.
        spool = tempfile.TemporaryDirectory(prefix="hol-guard-acquisition-", dir=temp_dir, ignore_cleanup_errors=True)
        query = {
            **_query(source_url, "download"),
            "max_bytes": max_bytes,
            "max_redirects": max_redirects,
            "timeout_ms": int(timeout_seconds * 1000),
            "temp_dir": str(Path(spool.name).resolve()),
            "trust_roots_der_hex": [root.hex() for root in roots],
            "allow_public_registries": policy.allow_public_registries,
        }
        payload = _request(query, deadline=deadline)
        if payload is None:
            return unavailable
        if payload.get("kind") == "failure":
            if set(payload) != {"kind", "code", "message"} or not all(
                isinstance(payload[key], str) for key in ("code", "message")
            ):
                return unavailable
            return RestrictedArchiveFailure(payload["code"], payload["message"])
        if set(payload) != {"kind", "path", "sha256", "size", "source_url", "final_url"}:
            return unavailable
        if (
            payload["kind"] != "download"
            or not all(isinstance(payload[key], str) for key in ("path", "sha256", "source_url", "final_url"))
            or isinstance(payload["size"], bool)
            or not isinstance(payload["size"], int)
            or not 0 <= payload["size"] <= max_bytes
            or not Path(payload["path"]).is_absolute()
            or not Path(payload["path"]).parent.samefile(spool.name)
            or payload["source_url"] != source_url
            or len(payload["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in payload["sha256"])
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
