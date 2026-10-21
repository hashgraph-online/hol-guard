"""Request-bound transport for the native rich command parser."""

from __future__ import annotations

import base64
import gzip
import json
import time
from typing import Any
from uuid import uuid4

from . import native_context as _context
from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_ready, native_resident_client_request
from .native_runtime import NativeRuntimeStatus, _isolated_environment

FEATURE = "rich-command-model-v1"
SCHEMA = "guard-rich-command-model-request.v1"
RESULT_SCHEMA = "guard-rich-command-model-result.v1"
_MAX_BYTES = 2 * 1024 * 1024
_EXECUTABLE_CACHE: dict[tuple[str, str], str | None] = {}
_MISS = object()


def native_runtime_status(*, deadline_monotonic: float) -> NativeRuntimeStatus:
    """Reuse the shared status memo and bound every fresh capability probe."""
    if time.monotonic() >= deadline_monotonic:
        raise NativeCommandModelError("native_rich_command_model_deadline")
    probe = _context.native_runtime_status
    with _context._STATUS_MEMO_LOCK:
        memo = _context._status_memo
        if (
            memo is not None
            and memo[2] is probe
            and time.monotonic() - memo[0] < _context._STATUS_MEMO_TTL_SECONDS
            and _context._status_binary_unchanged(memo[1])
        ):
            return memo[1]
    status = probe(deadline_monotonic=deadline_monotonic)
    if status.identity is not None and time.monotonic() < deadline_monotonic:
        with _context._STATUS_MEMO_LOCK:
            _context._status_memo = (time.monotonic(), status, probe)
    return status


class NativeCommandModelError(RuntimeError, ValueError):
    """The native parser did not return an authoritative, bound result."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        from .native_local_cli_identity import record_local_cli_identity_failure

        record_local_cli_identity_failure(message)


def _shape(value: Any, spec: Any) -> bool:
    if isinstance(spec, tuple):
        return any(_shape(value, option) for option in spec)
    if isinstance(spec, dict):
        return (
            isinstance(value, dict)
            and set(value) == set(spec)
            and all(_shape(value[key], kind) for key, kind in spec.items())
            and (not {"start", "end"} <= set(spec) or value["start"] <= value["end"])
        )
    if isinstance(spec, list):
        if not isinstance(value, list):
            return False
        if len(spec) == 1:
            return all(_shape(item, spec[0]) for item in value)
        return len(value) == len(spec) and all(_shape(item, kind) for item, kind in zip(value, spec, strict=True))
    return type(value) is spec and (spec is not int or value >= 0)


def _valid_result(action: str, value: Any) -> bool:
    nullable = (str, type(None))
    span = {"source": str, "start": int, "end": int}
    redirect = {"operator": str, "target": str, "start": int, "end": int}
    specs = {
        "parse": {
            "raw_text": str,
            "normalized_text": str,
            "dialect": str,
            "transport": str,
            "extraction_provenance": str,
            "wrapper_chain": [str],
            "confidence": str,
            "uncertainty_reason": nullable,
            "security_identity": str,
            "path_overridden": bool,
            "segments": [
                {
                    "text": str,
                    "tokens": [str],
                    "executable": nullable,
                    "arguments": [str],
                    "environment_names": [str],
                    "wrapper_chain": [str],
                    "path_overridden": bool,
                    "execution_context": str,
                    "pipeline_index": int,
                    "span": span,
                }
            ],
            "redirects": [{"operator": str, "target": str, "span": span}],
            "embedded_commands": [{"kind": str, "text": str, "execution_context": str, "span": span}],
        },
        "tokens": [[str], bool],
        "windows_tokens": [[str], bool],
        "leading_environment": [[str], int, [str]],
        "executable": nullable,
        "sudo_options": int,
        "segment_tokens": [str],
        "redirects": [redirect],
        "identity": str,
        "env": {
            "complete": bool,
            "error": nullable,
            "original_tokens": [str],
            "expanded_tokens": [str],
            "option_effects": {
                "ignore_environment": bool,
                "unset_names": [str],
                "chdir": nullable,
                "search_path": nullable,
                "verbose": bool,
                "null_output": bool,
            },
            "environment_delta": {"clear": bool, "unset_names": [str], "assignments": [[str, str]]},
            "effective_environment": ([[str, str]], type(None)),
            "effective_cwd": nullable,
            "command_index": (int, type(None)),
            "executable_argv": [str],
            "split_expansions": [{"payload": str, "source_index": int, "tokens": [str]}],
        },
    }
    if action not in specs or not _shape(value, specs[action]):
        return False
    if action == "parse":
        identity = value["security_identity"].removeprefix("command-security-v2:")
        if not value["security_identity"].startswith("command-security-v2:") or len(identity) != 64:
            return False
        if any(character not in "0123456789abcdef" for character in identity):
            return False
        length = len(value["normalized_text"])
        for collection in ("segments", "redirects", "embedded_commands"):
            if any(
                item["span"]["source"] != "normalized" or item["span"]["end"] > length for item in value[collection]
            ):
                return False
    return True


def request(action: str, args: dict[str, Any], *, timeout_seconds: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout_seconds
    try:
        home = _resolve_digest_home(None)
        status = native_runtime_status(deadline_monotonic=deadline)
        if (
            not status.available
            or not status.compatible
            or status.identity is None
            or status.capabilities is None
            or FEATURE not in status.capabilities.features
            or "resident-protocol-v2" not in status.capabilities.features
        ):
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        if time.monotonic() >= deadline or not ensure_resident_prerequisite(home):
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        cache_key = None
        if action == "executable" and (value := args.get("value")) is not None and len(value) <= 1024:
            cache_key = (status.identity.sha256, value)
        if cache_key is not None and (cached := _EXECUTABLE_CACHE.get(cache_key, _MISS)) is not _MISS:
            return cached
        if action != "parse":
            budget = 1.0 if native_resident_client_ready(status.identity.path, home) else 4.0
            deadline = min(deadline, time.monotonic() + budget)
        wire_args = args
        if action == "parse" and len(args["command"].encode("utf-8")) > 32768:
            wire_args = {key: value for key, value in args.items() if key != "command"}
            source = args["command"].encode("utf-8")
            if len(source) > 8 * 1024 * 1024:
                raise NativeCommandModelError("native_rich_command_model_bounds")
            encoded = base64.b64encode(gzip.compress(source, mtime=0)).decode("ascii")
            wire_args["command_gzip_chunks"] = [
                encoded[index : index + 524288] for index in range(0, len(encoded), 524288)
            ]
        material = {
            "schema": SCHEMA,
            "request_id": uuid4().hex,
            "guard_home": str(home),
            "action": action,
            "args": wire_args,
        }
        digest = _canonical_request_sha256(material)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativeCommandModelError("native_rich_command_model_deadline")
        payload = json.dumps(
            {
                "operation": "rich_command_model",
                "request": material,
                "deadline_budget_ms": max(1, int(remaining * 1000)),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        if len(payload) > _MAX_BYTES:
            raise NativeCommandModelError("native_rich_command_model_bounds")
        response = native_resident_client_request(
            executable=status.identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=payload,
            deadline_monotonic=deadline,
        )
        if response is None or len(response) > _MAX_BYTES or time.monotonic() > deadline:
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        decoded = json.loads(response)
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {"schema", "request_id", "request_sha256", "status", "result", "error"}
            or decoded["schema"] != RESULT_SCHEMA
            or decoded["request_id"] != material["request_id"]
            or decoded["request_sha256"] != digest
        ):
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        if decoded["status"] == "invalid_input" and decoded["error"] == "Command text cannot be empty":
            raise ValueError(decoded["error"])
        if decoded["status"] != "ok" or decoded["error"] is not None:
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        result = decoded["result"]
        if action == "parse" and isinstance(result, dict) and "source_text_span" in result:
            span = result.pop("source_text_span")
            source = args["command"].encode("utf-8")
            if (
                not _shape(span, {"start": int, "end": int})
                or span["start"] >= span["end"]
                or span["end"] > len(source)
                or result.get("confidence") != "uncertain"
                or result.get("raw_text") != ""
                or result.get("normalized_text") != ""
            ):
                raise NativeCommandModelError("native_rich_command_model_invalid_result")
            result["raw_text"] = result["normalized_text"] = source[span["start"] : span["end"]].decode("utf-8")
        if not _valid_result(action, result):
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        if cache_key is not None:
            if len(_EXECUTABLE_CACHE) >= 256:
                _EXECUTABLE_CACHE.clear()
            _EXECUTABLE_CACHE[cache_key] = decoded["result"]
        return result
    except UnicodeEncodeError as error:
        raise NativeCommandModelError("native_rich_command_model_invalid_input") from error
    except (OSError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise NativeCommandModelError("native_rich_command_model_unavailable") from error


def string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise NativeCommandModelError("native_rich_command_model_invalid_result")
    return tuple(value)
