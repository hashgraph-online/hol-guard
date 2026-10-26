"""Request-bound portable policy DTOs through the existing persistent client."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time
from typing import Any
from uuid import uuid4

from .native_binary_identity import validate_native_binary
from .native_context import _canonical_request_sha256, _resolve_digest_home
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .policy_document_types import PolicyCompilationError
from .runtime.command_expression import CommandExpressionError
from .strict_json_pairs import unique_json_object


class NativePolicyDocumentError(ValueError, RuntimeError):
    """Unavailable or unbound native authority cannot compile a policy."""

    code = "native_policy_document_unavailable"


def bounds_claim(value: object) -> list[Any]:
    """Losslessly frame Python strings, floats and ordered containers as claims."""
    if isinstance(value, str):
        return ["text", base64.b64encode(value.encode("utf-32-le", "surrogatepass")).decode("ascii")]
    if isinstance(value, list):
        return ["list", [bounds_claim(item) for item in value]]
    if isinstance(value, dict):
        return ["mapping", [[bounds_claim(key), bounds_claim(item)] for key, item in value.items()]]
    if isinstance(value, float):
        return ["float", struct.pack(">d", value).hex()]
    return ["scalar", None]


def _wire_frame(result: Any, kind: str) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != {kind} or not isinstance(result[kind], dict):
        raise NativePolicyDocumentError("native_policy_document_transfer_unbound")
    frame = result[kind]
    keys = {"handle", "offset"} if kind == "wire_upload" else {"handle", "offset", "total", "sha256", "bytes"}
    if set(frame) != keys or not isinstance(frame["handle"], str) or type(frame["offset"]) is not int:
        raise NativePolicyDocumentError("native_policy_document_transfer_unbound")
    return frame


def _bound_query(
    query: str,
    body: dict[str, Any],
    *,
    deadline_monotonic: float | None = None,
    runtime_sha256: str | None = None,
) -> Any:
    deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 30.0
    if time.monotonic() >= deadline:
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or "request-context-v1" not in status.capabilities.features
        or "resident-protocol-v2" not in status.capabilities.features
    ):
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    identity = validate_native_binary(status.identity.path)
    if (
        identity is None
        or identity != status.identity
        or (runtime_sha256 is not None and identity.sha256 != runtime_sha256)
    ):
        raise NativePolicyDocumentError("native_policy_document_runtime_changed")
    home = _resolve_digest_home(None)
    request = {
        "schema": "guard-request-context-request.v1",
        "request_id": f"policy-document-{uuid4().hex}",
        "guard_home": str(home),
        "source": "direct_command",
        "owner_uid": None if sys.platform == "win32" else os.geteuid(),
        "budget_ms": max(1, int((deadline - time.monotonic()) * 1000)),
        "action": {"kind": "policy_document", "body": {"query": query, "input": body}},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
        wire = json.dumps(
            {"operation": "request_context_build", "request": request, "deadline_budget_ms": request["budget_ms"]},
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(wire) > 6 * 1024 * 1024 or time.monotonic() >= deadline:
            raise NativePolicyDocumentError("native_policy_document_request_invalid")
        raw = native_resident_client_request(
            executable=identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=wire,
            deadline_monotonic=deadline,
        )
        if raw is None or len(raw) > 2 * 1024 * 1024:
            raise NativePolicyDocumentError("native_policy_document_unavailable")
        response = json.loads(raw, object_pairs_hook=unique_json_object)
        if (
            not isinstance(response, dict)
            or set(response) != {"schema", "request_id", "request_sha256", "status", "code", "payload"}
            or response["schema"] != "guard-request-context-result.v1"
            or response["request_id"] != request["request_id"]
            or response["request_sha256"] != digest
            or response["status"] != "ok"
            or response["code"] != "ok"
        ):
            raise NativePolicyDocumentError("native_policy_document_unbound")
        payload = response["payload"]
        if (
            not isinstance(payload, dict)
            or set(payload) != {"kind", "query", "result"}
            or payload["kind"] != "policy_document"
            or payload["query"] != query
            or time.monotonic() >= deadline
        ):
            raise NativePolicyDocumentError("native_policy_document_unbound")
        result = payload["result"]
        if not isinstance(result, dict) or set(result) not in ({"ok"}, {"error"}, {"wire_upload"}, {"wire_download"}):
            raise NativePolicyDocumentError("native_policy_document_malformed")
        if "error" in result:
            error = result["error"]
            if (
                not isinstance(error, dict)
                or set(error) not in ({"type", "message"}, {"type", "message", "code", "rule_id"})
                or not all(isinstance(value, str) and len(value) <= 512 for value in error.values())
            ):
                raise NativePolicyDocumentError("native_policy_document_malformed")
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NativePolicyDocumentError("native_policy_document_unavailable") from exc
    if "error" in result:
        error = result["error"]
        if error["type"] == "PolicyCompilationError" and set(error) == {"type", "message", "code", "rule_id"}:
            raise PolicyCompilationError(error["code"], error["rule_id"])
        exceptions = {
            "CommandExpressionError": CommandExpressionError,
            "KeyError": KeyError,
            "TypeError": TypeError,
            "ValueError": ValueError,
        }
        if exception := exceptions.get(error["type"]):
            raise exception(error["message"].strip("'") if error["type"] == "KeyError" else error["message"])
        raise NativePolicyDocumentError("native_policy_document_malformed")
    return result


def policy_query(
    query: str, body: dict[str, Any], *, deadline_monotonic: float | None = None, runtime_sha256: str | None = None
) -> Any:
    deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 30.0
    if time.monotonic() >= deadline:
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    status = native_runtime_status(deadline_monotonic=deadline)
    if status.identity is None:
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    identity = runtime_sha256 or status.identity.sha256

    def call(operation: str, value: dict[str, Any]) -> Any:
        return _bound_query(operation, value, deadline_monotonic=deadline, runtime_sha256=identity)

    try:
        encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativePolicyDocumentError("native_policy_document_request_invalid") from exc
    if len(encoded) > 64 * 1024 * 1024:
        raise NativePolicyDocumentError("native_policy_document_request_too_large")
    if len(encoded) > 512 * 1024 or query in {"validate_bounds", "validate_yaml_tokens"}:
        start = _wire_frame(
            call("wire_start", {"query": query, "size": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}),
            "wire_upload",
        )
        if start["offset"] != 0:
            raise NativePolicyDocumentError("native_policy_document_upload_unbound")
        token = start["handle"]
        for offset in range(0, len(encoded), 512 * 1024):
            chunk = encoded[offset : offset + 512 * 1024]
            reply = call("wire_append", {"handle": token, "offset": offset, "bytes": base64.b64encode(chunk).decode()})
            if reply != {"wire_upload": {"handle": token, "offset": offset + len(chunk)}}:
                raise NativePolicyDocumentError("native_policy_document_upload_unbound")
        result = call("wire_finish", {"handle": token})
    else:
        result = call(query, body)
    if isinstance(result, dict) and set(result) == {"ok"}:
        return result["ok"]
    page = _wire_frame(result, "wire_download")
    token, total, digest = page["handle"], page["total"], page["sha256"]
    if type(total) is not int or not 0 < total <= 64 * 1024 * 1024:
        raise NativePolicyDocumentError("native_policy_document_result_too_large")
    chunks = bytearray()
    while True:
        if set(page) != {"handle", "offset", "total", "sha256", "bytes"} or (
            page["handle"],
            page["offset"],
            page["total"],
            page["sha256"],
        ) != (token, len(chunks), total, digest):
            raise NativePolicyDocumentError("native_policy_document_download_unbound")
        try:
            chunk = base64.b64decode(page["bytes"], validate=True)
        except (TypeError, ValueError) as exc:
            raise NativePolicyDocumentError("native_policy_document_download_unbound") from exc
        if len(chunk) != min(512 * 1024, total - len(chunks)):
            raise NativePolicyDocumentError("native_policy_document_download_unbound")
        chunks.extend(chunk)
        if len(chunks) == total:
            break
        page = _wire_frame(call("wire_read", {"handle": token, "offset": len(chunks)}), "wire_download")
    if hashlib.sha256(chunks).hexdigest() != digest or time.monotonic() >= deadline:
        raise NativePolicyDocumentError("native_policy_document_download_unbound")
    try:
        decoded = json.loads(chunks, object_pairs_hook=unique_json_object)
    except (TypeError, ValueError) as exc:
        raise NativePolicyDocumentError("native_policy_document_download_unbound") from exc
    if not isinstance(decoded, dict) or set(decoded) != {"ok"}:
        raise NativePolicyDocumentError("native_policy_document_malformed")
    return decoded["ok"]
